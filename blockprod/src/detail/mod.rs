// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod block_solver;
pub mod job_manager;
pub mod timestamp_searcher;
pub mod utils;

use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Mutex},
};

use tokio::sync::oneshot;

use chainstate::ChainstateHandle;
use common::{
    chain::{
        block::{
            block_body::BlockBody, timestamp::BlockTimestamp, BlockCreationError, BlockHeader,
            BlockReward, ConsensusData,
        },
        Block, ChainConfig, GenBlock, PoolId, SignedTransaction, Transaction,
    },
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use consensus::{GenerateBlockInputData, PoSGenerateBlockInputData};
use crypto::ephemeral_e2e::{self, EndToEndPrivateKey};
use mempool::{tx_accumulator::PackingStrategy, MempoolHandle};
use p2p::P2pHandle;
use randomness::{make_true_rng, Rng};
use serialization::{Decode, Encode};

use ::utils::{atomics::RelaxedAtomicBool, once_destructor::OnceDestructor};

use crate::{
    config::BlockProdConfig,
    detail::{
        job_manager::{JobKey, JobManagerHandle, JobManagerImpl},
        utils::collect_transactions,
    },
    BlockProductionError,
};

use self::{
    timestamp_searcher::TimestampSearchData,
    utils::{calculate_median_time_past, get_best_block_index},
};

pub const JOBKEY_DEFAULT_LEN: usize = 32;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CustomId {
    data: Vec<u8>,
}

impl CustomId {
    pub fn new_from_entropy() -> Self {
        Self::new_from_rng(&mut make_true_rng())
    }

    pub fn new_from_rng(rng: &mut impl Rng) -> Self {
        Self {
            data: rng.gen::<[u8; JOBKEY_DEFAULT_LEN]>().into(),
        }
    }

    pub fn new_from_input_data(input_data: &GenerateBlockInputData) -> Self {
        match input_data {
            GenerateBlockInputData::PoS(pos_input_data) => Self {
                data: pos_input_data.stake_public_key().encode(),
            },
            GenerateBlockInputData::None | GenerateBlockInputData::PoW(_) => {
                Self::new_from_entropy()
            }
        }
    }

    pub fn new_from_value(value: Vec<u8>) -> Self {
        Self { data: value }
    }
}

#[allow(dead_code)]
pub struct BlockProduction {
    chain_config: Arc<ChainConfig>,
    blockprod_config: Arc<BlockProdConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    job_manager_handle: JobManagerHandle,
    mining_thread_pool: Arc<slave_pool::ThreadPool>,
    p2p_handle: P2pHandle,
    e2e_encryption_key: ephemeral_e2e::EndToEndPrivateKey,
    last_used_block_timespamps_for_pos: Mutex<BTreeMap<PoolId, BlockTimestamp>>,
}

impl BlockProduction {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        blockprod_config: Arc<BlockProdConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        p2p_handle: P2pHandle,
        time_getter: TimeGetter,
        mining_thread_pool: Arc<slave_pool::ThreadPool>,
    ) -> Result<Self, BlockProductionError> {
        let job_manager_handle = Box::new(JobManagerImpl::new(Some(chainstate_handle.clone())));

        let mut rng = make_true_rng();

        let block_production = Self {
            chain_config,
            blockprod_config,
            chainstate_handle,
            mempool_handle,
            p2p_handle,
            time_getter,
            job_manager_handle,
            mining_thread_pool,
            e2e_encryption_key: EndToEndPrivateKey::new_from_rng(&mut rng),
            last_used_block_timespamps_for_pos: Mutex::new(BTreeMap::new()),
        };

        Ok(block_production)
    }

    #[cfg(test)]
    fn set_job_manager(&mut self, job_manager_handle: JobManagerHandle) {
        self.job_manager_handle = job_manager_handle
    }

    pub async fn stop_all_jobs(&mut self) -> Result<usize, BlockProductionError> {
        self.job_manager_handle
            .stop_all_jobs()
            .await
            .map_err(BlockProductionError::JobManagerError)
    }

    pub async fn stop_job(&mut self, job_key: JobKey) -> Result<bool, BlockProductionError> {
        Ok(self.job_manager_handle.stop_job(job_key).await? == 1)
    }

    fn get_last_used_block_timestamp_for_pos_data(
        &self,
        pos_data: &PoSGenerateBlockInputData,
    ) -> Option<BlockTimestamp> {
        let pool_id = pos_data.pool_id();
        self.last_used_block_timespamps_for_pos
            .lock()
            .expect("poisoned mutex")
            .get(&pool_id)
            .copied()
    }

    fn update_last_used_block_timestamp_for_pos(
        &self,
        input_data: &GenerateBlockInputData,
        last_used_block_timestamp: BlockTimestamp,
    ) {
        match input_data {
            GenerateBlockInputData::PoS(pos_data) => {
                let pool_id = pos_data.pool_id();
                let mut timespamps =
                    self.last_used_block_timespamps_for_pos.lock().expect("poisoned mutex");

                // TODO: need a way to clean the map from pools that no longer exist
                // (probably, it's better to just remove timestamps that are too old).
                timespamps.insert(pool_id, last_used_block_timestamp);
            }

            GenerateBlockInputData::PoW(_) | GenerateBlockInputData::None => {}
        }
    }

    /// The function that creates a new block.
    ///
    /// Returns the block and a oneshot receiver that will be notified when
    /// the internal job is finished. Generally this can be used to ensure
    /// that the block production process has ended and that there's no
    /// remnants in the job manager.
    ///
    /// Note: the function may exit early, e.g. in case of recoverable mempool error.
    /// TODO: recoverable mempool errors should not affect PoS.
    pub async fn produce_block(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.produce_block_with_custom_id(
            input_data,
            transactions,
            transaction_ids,
            packing_strategy,
            None,
        )
        .await
    }

    async fn ensure_can_produce_block(&self) -> Result<(), BlockProductionError> {
        if !self.blockprod_config.skip_ibd_check {
            let is_initial_block_download =
                self.chainstate_handle.call(|cs| cs.is_initial_block_download()).await?;

            if is_initial_block_download {
                return Err(BlockProductionError::ChainstateWaitForSync);
            }
        }

        let current_peer_count = self
            .p2p_handle
            .call_async_mut(move |p2p| p2p.get_peer_count())
            .await?
            .map_err(|err| BlockProductionError::PeerCountRetrievalError(err.to_string()))?;

        if current_peer_count < self.blockprod_config.min_peers_to_produce_blocks {
            return Err(BlockProductionError::PeerCountBelowRequiredThreshold(
                current_peer_count,
                self.blockprod_config.min_peers_to_produce_blocks,
            ));
        }

        Ok(())
    }

    /// Create the block header and body, filling it with the specified transactions.
    ///
    /// If `ignore_mempool_recoverable_error` is true and `collect_transactions` fails with
    /// a recoverable error (i.e. if `parent_id` doesn't match the current tip in mempool),
    /// the block will still be created without transactions; otherwise, the function will fail.
    //
    // TODO: `ignore_mempool_recoverable_error` should be removed; instead, we should be able
    // to perform in-memory reorg to the specified parent.
    async fn prepare_block(
        &self,
        parent_id: Id<GenBlock>,
        block_reward: BlockReward,
        block_timestamp: BlockTimestamp,
        consensus_data: ConsensusData,
        transactions: TxData,
        ignore_mempool_recoverable_error: bool,
    ) -> Result<(BlockHeader, BlockBody), BlockProductionError> {
        // Note: when validating a block, the lock-time constraints of its transactions
        // are validated against the "median time past" of the block's parent, rather than
        // the timestamp of the block itself.
        // So when constructing a new block we must make sure that transactions with locks
        // after this point are not included, otherwise the block will be incorrect.
        let median_time_past = self
            .chainstate_handle
            .call(move |cs| -> Result<_, BlockProductionError> {
                calculate_median_time_past(cs, &parent_id)
            })
            .await??;

        let collected_transactions = collect_transactions(
            &self.mempool_handle,
            &self.chain_config,
            parent_id,
            median_time_past,
            transactions.transactions,
            transactions.transaction_ids,
            transactions.packing_strategy,
        )
        .await?;
        let collected_transactions = if let Some(collected_transactions) = collected_transactions {
            collected_transactions
        } else if ignore_mempool_recoverable_error {
            Vec::new()
        } else {
            return Err(BlockProductionError::RecoverableMempoolError);
        };

        let block_body = BlockBody::new(block_reward, collected_transactions);

        let merkle_proxy =
            block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

        let block_header = BlockHeader::new(
            parent_id,
            merkle_proxy.merkle_tree().root(),
            merkle_proxy.witness_merkle_tree().root(),
            block_timestamp,
            consensus_data,
        );

        Ok((block_header, block_body))
    }

    async fn produce_block_with_custom_id(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
        custom_id_maybe: Option<Vec<u8>>,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.ensure_can_produce_block().await?;

        let best_block_index = self
            .chainstate_handle
            .call(move |cs| -> Result<_, BlockProductionError> { get_best_block_index(cs) })
            .await??;

        let (solver_input_data, last_used_block_timestamp_for_pos_receiver) = self
            .pull_block_solver_input_data(
                best_block_index.clone(),
                input_data.clone(),
                TxData {
                    transactions,
                    transaction_ids,
                    packing_strategy,
                },
            )
            .await?;

        let stop_flag = Arc::new(RelaxedAtomicBool::new(false));
        let custom_id = custom_id_maybe.map_or_else(
            || CustomId::new_from_input_data(&input_data),
            CustomId::new_from_value,
        );

        let is_pos = solver_input_data.is_pos();

        let (job_key, mut cancel_receiver) = self
            .job_manager_handle
            .add_job(
                custom_id.clone(),
                // Don't cancel the job on tip change if we're staking.
                (!is_pos).then_some(best_block_index.block_id()),
            )
            .await?;

        // This destructor ensures that the job manager cleans up its
        // housekeeping for the job when this current function returns
        let (job_stopper_function, job_finished_receiver) =
            self.job_manager_handle.make_job_stopper_function();
        let _job_stopper_destructor = {
            let job_key = job_key.clone();
            OnceDestructor::new(move || job_stopper_function(job_key))
        };

        // A synchronous channel that sends only when the mining/staking is done
        let (ended_sender, ended_receiver) = mpsc::channel::<()>();

        // Return the result of mining
        let (result_sender, mut result_receiver) = oneshot::channel();

        self.spawn_block_solver(
            solver_input_data,
            Arc::clone(&stop_flag),
            ended_sender,
            result_sender,
        )?;

        let solver_result = tokio::select! {
            _ = cancel_receiver.recv() => {
                stop_flag.store(true);

                // This can fail if the mining thread has already finished
                let _ended = ended_receiver.recv();

                return Err(BlockProductionError::Cancelled);
            }
            solver_result = &mut result_receiver => {
                solver_result.map_err(|_| BlockProductionError::TaskExitedPrematurely)?
            }
        };

        if let Some(last_used_block_timestamp_for_pos_receiver) =
            last_used_block_timestamp_for_pos_receiver
        {
            let last_used_block_timestamp_for_pos =
                *last_used_block_timestamp_for_pos_receiver.borrow();

            self.update_last_used_block_timestamp_for_pos(
                &input_data,
                last_used_block_timestamp_for_pos,
            );
        }

        let block = self.finalize_block(solver_result?).await?;

        Ok((block, job_finished_receiver))
    }

    pub fn e2e_private_key(&self) -> &ephemeral_e2e::EndToEndPrivateKey {
        &self.e2e_encryption_key
    }

    pub async fn collect_timestamp_search_data_impl(
        &self,
        pool_id: &PoolId,
        min_height: BlockHeight,
        max_height: Option<BlockHeight>,
        seconds_to_check_for_height: u64,
        check_all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, BlockProductionError> {
        timestamp_searcher::collect_timestamp_search_data(
            &self.chainstate_handle,
            pool_id,
            min_height,
            max_height,
            seconds_to_check_for_height,
            check_all_timestamps_between_blocks,
        )
        .await
    }
}

/// Tx data that is passed into produce_block.
#[derive(Debug, Clone)]
pub struct TxData {
    pub transactions: Vec<SignedTransaction>,
    pub transaction_ids: Vec<Id<Transaction>>,
    pub packing_strategy: PackingStrategy,
}

#[cfg(test)]
mod tests;
