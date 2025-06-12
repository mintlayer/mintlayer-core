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

pub mod job_manager;
pub mod timestamp_searcher;
pub mod utils;

use std::{
    cmp,
    sync::{mpsc, Arc},
};

use tokio::sync::oneshot;

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateHandle};
use chainstate_types::{pos_randomness::PoSRandomness, GenBlockIndex};
use common::{
    chain::{
        block::{
            block_body::BlockBody, signed_block_header::SignedBlockHeader,
            timestamp::BlockTimestamp, BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, PoolId, RequiredConsensus, SignedTransaction, Transaction,
    },
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use consensus::{
    generate_consensus_data_and_reward_ignore_consensus, generate_pos_consensus_data_and_reward,
    generate_pow_consensus_data_and_reward, ConsensusCreationError, ConsensusPoSError,
    ConsensusPoWError, FinalizeBlockInputData, GenerateBlockInputData, PoSFinalizeBlockInputData,
    PoSGenerateBlockInputData,
};
use crypto::ephemeral_e2e::{self, EndToEndPrivateKey};
use mempool::{tx_accumulator::PackingStrategy, MempoolHandle};
use p2p::P2pHandle;
use randomness::{make_true_rng, Rng};
use serialization::{Decode, Encode};

use ::utils::{
    atomics::{AcqRelAtomicU64, RelaxedAtomicBool},
    once_destructor::OnceDestructor,
};

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
    utils::{
        calculate_median_time_past, get_best_block_index, get_pool_staker_balance,
        get_pool_total_balance, get_sealed_epoch_randomness, make_ancestor_getter,
        timestamp_add_secs,
    },
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
        };

        Ok(block_production)
    }

    pub fn time_getter(&self) -> &TimeGetter {
        &self.time_getter
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

    pub async fn update_last_used_block_timestamp(
        &self,
        custom_id: CustomId,
        last_used_block_timestamp: BlockTimestamp,
    ) -> Result<(), BlockProductionError> {
        self.job_manager_handle
            .update_last_used_block_timestamp(custom_id, last_used_block_timestamp)
            .await?;

        Ok(())
    }

    async fn pull_consensus_data(
        &self,
        input_data: GenerateBlockInputData,
        time_getter: TimeGetter,
    ) -> Result<
        (
            ConsensusData,
            BlockReward,
            /*best_block_index:*/ GenBlockIndex,
            /*current_tip_median_time_past:*/ BlockTimestamp,
            FinalizeBlockInputData,
        ),
        BlockProductionError,
    > {
        let consensus_data = self
            .chainstate_handle
            .call({
                let chain_config = Arc::clone(&self.chain_config);

                move |cs| -> Result<_, BlockProductionError> {
                    let best_block_index = get_best_block_index(cs)?;

                    let best_block_id = best_block_index.block_id();
                    let current_tip_median_time_past =
                        calculate_median_time_past(cs, &best_block_id)?;

                    let block_height = best_block_index.block_height().next_height();
                    let sealed_epoch_randomness =
                        get_sealed_epoch_randomness(&chain_config, cs, block_height)?;
                    let required_consensus =
                        chain_config.consensus_upgrades().consensus_status(block_height);
                    let block_timestamp = BlockTimestamp::from_time(time_getter.get_time());

                    let (consensus_data, block_reward, finalize_block_data) =
                        match (required_consensus, input_data) {
                            (
                                RequiredConsensus::PoS(pos_status),
                                GenerateBlockInputData::PoS(pos_input_data),
                            ) => {
                                let (consensus_data, block_reward) =
                                    generate_pos_consensus_data_and_reward(
                                        &chain_config,
                                        &best_block_index,
                                        &pos_input_data,
                                        &pos_status,
                                        sealed_epoch_randomness,
                                        // TODO: this block_timestamp and the vrf_data inside PoSData make no sense here,
                                        // because they'll be overwritten during staking.
                                        block_timestamp,
                                        block_height,
                                        make_ancestor_getter(cs),
                                        &mut randomness::make_true_rng(),
                                    )?;
                                let consensus_data = ConsensusData::PoS(Box::new(consensus_data));

                                let finalize_block_data =
                                    FinalizeBlockInputData::PoS(generate_finalize_block_data_pos(
                                        &chain_config,
                                        cs,
                                        block_height,
                                        sealed_epoch_randomness,
                                        &pos_input_data,
                                    )?);

                                (consensus_data, block_reward, finalize_block_data)
                            }
                            (
                                RequiredConsensus::PoW(pow_status),
                                GenerateBlockInputData::PoW(pow_input_data),
                            ) => {
                                let (consensus_data, block_reward) =
                                    generate_pow_consensus_data_and_reward(
                                        &chain_config,
                                        &best_block_index,
                                        block_timestamp,
                                        &pow_status,
                                        make_ancestor_getter(cs),
                                        *pow_input_data,
                                        block_height,
                                    )
                                    .map_err(ConsensusCreationError::MiningError)?;
                                let consensus_data = ConsensusData::PoW(Box::new(consensus_data));

                                let finalize_block_data = FinalizeBlockInputData::PoW;

                                (consensus_data, block_reward, finalize_block_data)
                            }
                            (RequiredConsensus::IgnoreConsensus, GenerateBlockInputData::None) => {
                                let (consensus_data, block_reward) =
                                    generate_consensus_data_and_reward_ignore_consensus(
                                        &chain_config,
                                        block_height,
                                    )?;
                                let finalize_block_data = FinalizeBlockInputData::None;

                                (consensus_data, block_reward, finalize_block_data)
                            }
                            (RequiredConsensus::PoS(_), GenerateBlockInputData::PoW(_)) => {
                                Err(ConsensusCreationError::StakingError(
                                    ConsensusPoSError::PoWInputDataProvided,
                                ))?
                            }
                            (RequiredConsensus::PoS(_), GenerateBlockInputData::None) => {
                                Err(ConsensusCreationError::StakingError(
                                    ConsensusPoSError::NoInputDataProvided,
                                ))?
                            }
                            (RequiredConsensus::PoW(_), GenerateBlockInputData::PoS(_)) => {
                                Err(ConsensusCreationError::MiningError(
                                    ConsensusPoWError::PoSInputDataProvided,
                                ))?
                            }
                            (RequiredConsensus::PoW(_), GenerateBlockInputData::None) => {
                                Err(ConsensusCreationError::MiningError(
                                    ConsensusPoWError::NoInputDataProvided,
                                ))?
                            }
                            (
                                RequiredConsensus::IgnoreConsensus,
                                GenerateBlockInputData::PoS(_),
                            ) => Err(
                                BlockProductionError::PoSInputDataProvidedWhenIgnoringConsensus,
                            )?,
                            (
                                RequiredConsensus::IgnoreConsensus,
                                GenerateBlockInputData::PoW(_),
                            ) => Err(
                                BlockProductionError::PoWInputDataProvidedWhenIgnoringConsensus,
                            )?,
                        };

                    Ok((
                        consensus_data,
                        block_reward,
                        best_block_index,
                        current_tip_median_time_past,
                        finalize_block_data,
                    ))
                }
            })
            .await??;

        Ok(consensus_data)
    }

    async fn pull_best_block_index(&self) -> Result<GenBlockIndex, BlockProductionError> {
        // Clippy insists that this closure is redundant, however the compiler doesn't
        // like the simple "chainstate_handle.call(get_best_block_index)", complaining about
        // lifetime issues.
        #[allow(clippy::redundant_closure)]
        let best_block_index = self.chainstate_handle.call(|cs| get_best_block_index(cs)).await??;

        Ok(best_block_index)
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

    async fn produce_block_with_custom_id(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
        custom_id_maybe: Option<Vec<u8>>,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.ensure_can_produce_block().await?;

        let stop_flag = Arc::new(RelaxedAtomicBool::new(false));
        let tip_at_start = self.pull_best_block_index().await?;
        let custom_id = custom_id_maybe.map_or_else(
            || CustomId::new_from_input_data(&input_data),
            CustomId::new_from_value,
        );

        let (job_key, previous_last_used_block_timestamp, mut cancel_receiver) = self
            .job_manager_handle
            .add_job(custom_id.clone(), Some(tip_at_start.block_id()))
            .await?;

        // This destructor ensures that the job manager cleans up its
        // housekeeping for the job when this current function returns
        let (job_stopper_function, job_finished_receiver) =
            self.job_manager_handle.make_job_stopper_function();
        let _job_stopper_destructor = {
            let job_key = job_key.clone();
            OnceDestructor::new(move || job_stopper_function(job_key))
        };

        // Unlike Proof of Work, which can vary any header field when
        // searching for a valid block, Proof of Stake can only vary
        // the header timestamp. Its search space starts at the
        // previous block's timestamp + 1 second, and ends at the
        // current timestamp + some distance in time defined by the
        // blockchain.
        //
        // This variable keeps track of the last timestamp that was
        // attempted, and during Proof of Stake, will prevent
        // searching over the same search space, across multiple
        // calls, given the same tip
        let last_timestamp_seconds_used = {
            let prev_timestamp = cmp::max(
                previous_last_used_block_timestamp.unwrap_or(BlockTimestamp::from_int_seconds(0)),
                tip_at_start.block_timestamp(),
            );

            let mut prev_plus_one = timestamp_add_secs(prev_timestamp, 1)?;

            if self.blockprod_config.use_current_time_if_non_pos {
                let is_pos = match &input_data {
                    GenerateBlockInputData::None | GenerateBlockInputData::PoW(_) => false,
                    GenerateBlockInputData::PoS(_) => true,
                };

                if !is_pos {
                    prev_plus_one = cmp::max(
                        prev_plus_one,
                        BlockTimestamp::from_time(self.time_getter.get_time()),
                    );
                }
            }

            Arc::new(AcqRelAtomicU64::new(prev_plus_one.as_int_seconds()))
        };

        let (
            consensus_data,
            block_reward,
            current_tip_index,
            // The so-called "median time past" timestamp calculated from the current tip.
            // Note: when validating a block, the lock-time constraints of its transactions
            // are validated against the "median time past" of the block's parent, rather than
            // the timestamp of the block itself.
            // So when constructing a new block we must make sure that transactions with locks
            // after this point are not included, otherwise the block will be incorrect.
            current_tip_median_time_past,
            finalize_block_data,
        ) = self.pull_consensus_data(input_data.clone(), self.time_getter.clone()).await?;

        let collected_transactions = collect_transactions(
            &self.mempool_handle,
            &self.chain_config,
            current_tip_index.block_id(),
            current_tip_median_time_past,
            transactions.clone(),
            transaction_ids.clone(),
            packing_strategy,
        )
        .await?
        .ok_or(BlockProductionError::RecoverableMempoolError)?;

        let block_body = BlockBody::new(block_reward, collected_transactions);

        // A synchronous channel that sends only when the mining/staking is done
        let (ended_sender, ended_receiver) = mpsc::channel::<()>();

        // Return the result of mining
        let (result_sender, mut result_receiver) = oneshot::channel();

        self.spawn_block_solver(
            &current_tip_index,
            Arc::clone(&stop_flag),
            &block_body,
            Arc::clone(&last_timestamp_seconds_used),
            finalize_block_data,
            consensus_data,
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

        let last_used_block_timestamp =
            BlockTimestamp::from_int_seconds(last_timestamp_seconds_used.load());

        self.update_last_used_block_timestamp(custom_id.clone(), last_used_block_timestamp)
            .await?;

        let signed_block_header = solver_result?;
        let block = Block::new_from_header(signed_block_header, block_body.clone())?;
        Ok((block, job_finished_receiver))
    }

    // TODO: get rid of the "block_timestamp_seconds" atomic.
    #[allow(clippy::too_many_arguments)]
    fn spawn_block_solver(
        &self,
        current_tip_index: &GenBlockIndex,
        stop_flag: Arc<RelaxedAtomicBool>,
        block_body: &BlockBody,
        block_timestamp_seconds: Arc<AcqRelAtomicU64>,
        finalize_block_data: FinalizeBlockInputData,
        consensus_data: ConsensusData,
        ended_sender: mpsc::Sender<()>,
        result_sender: oneshot::Sender<Result<SignedBlockHeader, BlockProductionError>>,
    ) -> Result<(), BlockProductionError> {
        let max_block_timestamp_for_pos = {
            let current_timestamp = BlockTimestamp::from_time(self.time_getter().get_time());
            let current_block_height = current_tip_index.block_height().next_height();
            let max_offset =
                self.chain_config.max_future_block_time_offset(current_block_height).as_secs();
            timestamp_add_secs(current_timestamp, max_offset)?
        };

        let min_block_timestamp = BlockTimestamp::from_int_seconds(block_timestamp_seconds.load());

        // TODO: this should be PoS only.
        if min_block_timestamp > max_block_timestamp_for_pos {
            return Err(BlockProductionError::TryAgainLater);
        }

        self.mining_thread_pool.spawn({
            let chain_config = Arc::clone(&self.chain_config);
            let current_tip_height = current_tip_index.block_height();
            let stop_flag = Arc::clone(&stop_flag);

            let merkle_proxy =
                block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

            let mut block_header = BlockHeader::new(
                current_tip_index.block_id(),
                merkle_proxy.merkle_tree().root(),
                merkle_proxy.witness_merkle_tree().root(),
                min_block_timestamp,
                consensus_data,
            );

            move || {
                let mut block_timestamp_for_pos =
                    BlockTimestamp::from_int_seconds(block_timestamp_seconds.load());

                let finalize_consensus_result = consensus::finalize_consensus_data(
                    &chain_config,
                    &mut block_header,
                    current_tip_height,
                    &mut block_timestamp_for_pos,
                    max_block_timestamp_for_pos,
                    stop_flag,
                    finalize_block_data,
                    &mut randomness::make_true_rng(),
                )
                .map_err(BlockProductionError::FailedConsensusInitialization);

                block_timestamp_seconds.store(block_timestamp_for_pos.as_int_seconds());

                let _ended_sender = OnceDestructor::new(move || {
                    // This can fail if the function exited before the mining thread finished
                    let _send_whether_ended = ended_sender.send(());
                });

                result_sender
                    .send(finalize_consensus_result)
                    .expect("Failed to send block header back to main thread");
            }
        });

        Ok(())
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

fn generate_finalize_block_data_pos(
    chain_config: &ChainConfig,
    chainstate: &dyn ChainstateInterface,
    new_block_height: BlockHeight,
    sealed_epoch_randomness: PoSRandomness,
    pos_input_data: &PoSGenerateBlockInputData,
) -> Result<PoSFinalizeBlockInputData, BlockProductionError> {
    let pool_id = pos_input_data.pool_id();
    let total_balance = get_pool_total_balance(chainstate, &pool_id)?;
    let staker_balance = get_pool_staker_balance(chainstate, &pool_id)?;

    #[cfg(debug_assertions)]
    {
        let pool_balances = utils::get_pool_balances_at_height(
            chainstate,
            new_block_height.prev_height().expect("new block height can't be zero"),
            &pool_id,
        )?;

        assert_eq!(total_balance, pool_balances.total_balance());
        assert_eq!(staker_balance, pool_balances.staker_balance());
    }

    let epoch_index = chain_config.epoch_index_from_height(&new_block_height);

    Ok(PoSFinalizeBlockInputData::new(
        pos_input_data.stake_private_key().clone(),
        pos_input_data.vrf_private_key().clone(),
        epoch_index,
        sealed_epoch_randomness,
        staker_balance,
        total_balance,
    ))
}

#[cfg(test)]
mod tests;
