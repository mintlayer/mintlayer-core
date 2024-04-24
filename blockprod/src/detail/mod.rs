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

use std::{
    cmp,
    sync::{mpsc, Arc},
};

use chainstate::{chainstate_interface::ChainstateInterface, ChainstateHandle, PropertyQueryError};
use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, GenBlockIndex, GetAncestorError,
};
use common::{
    chain::{
        block::{
            block_body::BlockBody, signed_block_header::SignedBlockHeader,
            timestamp::BlockTimestamp, BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, GenBlock, SignedTransaction, Transaction,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use consensus::{
    generate_consensus_data_and_reward, ConsensusCreationError, ConsensusPoSError,
    FinalizeBlockInputData, GenerateBlockInputData, PoSFinalizeBlockInputData,
};
use crypto::ephemeral_e2e::{self, EndToEndPrivateKey};
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, PackingStrategy, TransactionAccumulator},
    MempoolHandle,
};
use p2p::P2pHandle;
use randomness::{make_true_rng, Rng};
use serialization::{Decode, Encode};
use tokio::sync::oneshot;
use utils::atomics::{AcqRelAtomicU64, RelaxedAtomicBool};
use utils::once_destructor::OnceDestructor;

use crate::{
    config::BlockProdConfig,
    detail::job_manager::{JobKey, JobManagerHandle, JobManagerImpl},
    BlockProductionError,
};

#[derive(Debug, Clone)]
pub enum TransactionsSource {
    Mempool,
    Provided(Vec<SignedTransaction>),
}

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
        let mut rng = make_true_rng();

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

    /// Collect transactions from the mempool
    /// Returns the accumulator that is filled with transactions from the mempool
    /// Ok(None) means that a recoverable error happened (such as that the mempool tip moved).
    pub async fn collect_transactions(
        &self,
        current_tip: Id<GenBlock>,
        current_tip_median_time_past: BlockTimestamp,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockProductionError> {
        let mut accumulator = Box::new(DefaultTxAccumulator::new(
            self.chain_config.max_block_size_from_std_scripts(),
            current_tip,
            current_tip_median_time_past,
        ));

        for transaction in transactions.into_iter() {
            let transaction_id = transaction.transaction().get_id();

            accumulator
                .add_tx(transaction, Amount::ZERO.into())
                .map_err(|err| BlockProductionError::FailedToAddTransaction(transaction_id, err))?
        }

        let returned_accumulator = self
            .mempool_handle
            .call(move |mempool| {
                mempool.collect_txs(accumulator, transaction_ids, packing_strategy)
            })
            .await??;

        Ok(returned_accumulator)
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

                let current_timestamp = BlockTimestamp::from_time(self.time_getter().get_time());

                move |this| {
                    let best_block_index = this
                        .get_best_block_index()
                        .map_err(|_| ConsensusCreationError::BestBlockIndexNotFound)?;

                    let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
                        this.get_ancestor(
                            &block_index.clone().into_gen_block_index(),
                            ancestor_height,
                        )
                        .map_err(|_| {
                            PropertyQueryError::GetAncestorError(
                                GetAncestorError::InvalidAncestorHeight {
                                    block_height: block_index.block_height(),
                                    ancestor_height,
                                },
                            )
                        })
                    };

                    let best_block_id = best_block_index.block_id();
                    let current_tip_median_time_past =
                        this.calculate_median_time_past(&best_block_id).map_err(|err| {
                            ConsensusPoSError::ChainstateError(
                                consensus::ChainstateError::FailedToCalculateMedianTimePast(
                                    best_block_id,
                                    err.to_string(),
                                ),
                            )
                        })?;
                    let block_height = best_block_index.block_height().next_height();
                    let sealed_epoch_index = chain_config.sealed_epoch_index(&block_height);

                    let sealed_epoch_randomness = sealed_epoch_index
                        .map(|index| this.get_epoch_data(index))
                        .transpose()
                        .map_err(|err| {
                            ConsensusPoSError::ChainstateError(
                                consensus::ChainstateError::FailedToObtainEpochData(
                                    block_height,
                                    err.to_string(),
                                ),
                            )
                        })?
                        .flatten()
                        .map_or(PoSRandomness::at_genesis(&chain_config), |epoch_data| {
                            *epoch_data.randomness()
                        });

                    let (consensus_data, block_reward) = generate_consensus_data_and_reward(
                        &chain_config,
                        &best_block_index,
                        sealed_epoch_randomness,
                        input_data.clone(),
                        BlockTimestamp::from_time(time_getter.get_time()),
                        block_height,
                        get_ancestor,
                        randomness::make_true_rng(),
                    )?;

                    let finalize_block_data = generate_finalize_block_data(
                        &chain_config,
                        this,
                        block_height,
                        current_timestamp,
                        sealed_epoch_randomness,
                        input_data,
                    )?;

                    Ok((
                        consensus_data,
                        block_reward,
                        best_block_index,
                        current_tip_median_time_past,
                        finalize_block_data,
                    ))
                }
            })
            .await?
            .map_err(BlockProductionError::FailedConsensusInitialization)?;

        Ok(consensus_data)
    }

    async fn pull_best_block_index(&self) -> Result<GenBlockIndex, BlockProductionError> {
        let best_block_index = self
            .chainstate_handle
            .call(move |this| {
                let best_block_index = this
                    .get_best_block_index()
                    .map_err(|_| BlockCreationError::CurrentTipRetrievalError)?;

                Ok(best_block_index)
            })
            .await?
            .map_err(BlockProductionError::FailedToConstructBlock)?;

        Ok(best_block_index)
    }

    /// The function the creates a new block.
    ///
    /// Returns the block and a oneshot receiver that will be notified when
    /// the internal job is finished. Generally this can be used to ensure
    /// that the block production process has ended and that there's no
    /// remnants in the job manager.
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

    async fn produce_block_with_custom_id(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
        custom_id_maybe: Option<Vec<u8>>,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        if !self.blockprod_config.skip_ibd_check {
            let is_initial_block_download = self
                .chainstate_handle
                .call(|this| this.is_initial_block_download())
                .await
                .map_err(|_| BlockProductionError::ChainstateInfoRetrievalError)?;

            if is_initial_block_download {
                return Err(BlockProductionError::ChainstateWaitForSync);
            }
        }

        let current_peer_count = self
            .p2p_handle
            .call_async_mut(move |this| this.get_peer_count())
            .await?
            .map_err(|_| BlockProductionError::PeerCountRetrievalError)?;

        if current_peer_count < self.blockprod_config.min_peers_to_produce_blocks {
            return Err(BlockProductionError::PeerCountBelowRequiredThreshold(
                current_peer_count,
                self.blockprod_config.min_peers_to_produce_blocks,
            ));
        }

        let stop_flag = Arc::new(RelaxedAtomicBool::new(false));
        let tip_at_start = self.pull_best_block_index().await?;
        let custom_id = custom_id_maybe.map_or_else(
            || CustomId::new_from_input_data(&input_data),
            CustomId::new_from_value,
        );

        let (job_key, previous_last_used_block_timestamp, mut cancel_receiver) = self
            .job_manager_handle
            .add_job(custom_id.clone(), tip_at_start.block_id())
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
            let tip_timestamp = cmp::max(
                previous_last_used_block_timestamp.unwrap_or(BlockTimestamp::from_int_seconds(0)),
                tip_at_start.block_timestamp(),
            );

            let tip_plus_one = tip_timestamp
                .add_int_seconds(1)
                .ok_or(ConsensusCreationError::TimestampOverflow(tip_timestamp, 1))?;

            Arc::new(AcqRelAtomicU64::new(tip_plus_one.as_int_seconds()))
        };

        // Range of timestamps for the block we attempt to construct.
        let min_constructed_block_timestamp =
            BlockTimestamp::from_time(self.time_getter().get_time());
        let max_constructed_block_timestamp = min_constructed_block_timestamp
            .add_int_seconds(self.chain_config.max_future_block_time_offset().as_secs())
            .ok_or(ConsensusCreationError::TimestampOverflow(
                min_constructed_block_timestamp,
                self.chain_config.max_future_block_time_offset().as_secs(),
            ))?;

        loop {
            {
                // If the last timestamp we tried on a block is larger than the max range allowed, no point in continuing
                let last_used_block_timestamp =
                    BlockTimestamp::from_int_seconds(last_timestamp_seconds_used.load());

                if last_used_block_timestamp >= max_constructed_block_timestamp {
                    stop_flag.store(true);
                    return Err(BlockProductionError::TryAgainLater);
                }

                self.update_last_used_block_timestamp(custom_id.clone(), last_used_block_timestamp)
                    .await?;
            }

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

            if current_tip_index.block_id() != tip_at_start.block_id() {
                log::info!(
                    "Current tip changed from {} with height {} to {} with height {} while mining, cancelling",
                    tip_at_start.block_id(),
                    tip_at_start.block_height(),
                    current_tip_index.block_id(),
                    current_tip_index.block_height(),
                );
                return Err(BlockProductionError::TipChanged(
                    tip_at_start.block_id(),
                    tip_at_start.block_height(),
                    current_tip_index.block_id(),
                    current_tip_index.block_height(),
                ));
            }

            let accumulator = self
                .collect_transactions(
                    current_tip_index.block_id(),
                    current_tip_median_time_past,
                    transactions.clone(),
                    transaction_ids.clone(),
                    packing_strategy,
                )
                .await?;

            let collected_transactions = match accumulator {
                Some(acc) => acc.transactions().to_vec(),
                None => continue,
            };

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

            tokio::select! {
                _ = cancel_receiver.recv() => {
                    stop_flag.store(true);

                    // This can fail if the mining thread has already finished
                    let _ended = ended_receiver.recv();

                    return Err(BlockProductionError::Cancelled);
                }
                solve_receive_result = &mut result_receiver => {
                    let mining_result = match solve_receive_result {
                        Ok(mining_result) => mining_result,
                        Err(_) => continue,
                    };

                    let signed_block_header = match mining_result {
                        Ok(header) => header,
                        Err(_) => continue,
                    };

                    let block = Block::new_from_header(signed_block_header, block_body.clone())?;
                    return Ok((block, job_finished_receiver));
                }
            }
        }
    }

    // TODO: here, `block_timestamp_seconds` is a scary thing because, by being AcqRel, it might
    // imply that we perform thread synchronization through it. Which would be a bad thing
    // to do, because thread synchronization via atomics is too low-level and non-trivial
    // to implement correctly. Normally, it should be properly encapsulated, but here we
    // share the variable across packages, passing it to `consensus::finalize_consensus_data`.
    // So it's better to get rid of it ASAP.
    // (Note that we don't really do any thread synchronization through it currently; we made
    // it "AcqRel" just in case, for extra peace of mind.)
    // One way of removing it would be to pass the initial value via a non-atomic parameter and
    // return the updated value back; in `finalize_consensus_data` and its callees it can
    // be done simply via the functions' return values. And here in `spawn_block_solver` we
    // already have a one-shot `result_sender`, which may be used for that purpose.
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
        self.mining_thread_pool.spawn({
            let chain_config = Arc::clone(&self.chain_config);
            let current_tip_height = current_tip_index.block_height();
            let stop_flag = Arc::clone(&stop_flag);

            let merkle_proxy =
                block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

            let block_timestamp = BlockTimestamp::from_int_seconds(block_timestamp_seconds.load());

            let mut block_header = BlockHeader::new(
                current_tip_index.block_id(),
                merkle_proxy.merkle_tree().root(),
                merkle_proxy.witness_merkle_tree().root(),
                block_timestamp,
                consensus_data,
            );

            move || {
                let signed_block_header = consensus::finalize_consensus_data(
                    &chain_config,
                    &mut block_header,
                    current_tip_height,
                    block_timestamp_seconds,
                    stop_flag,
                    finalize_block_data,
                )
                .map_err(BlockProductionError::FailedConsensusInitialization);

                let _ended_sender = OnceDestructor::new(move || {
                    // This can fail if the function exited before the mining thread finished
                    let _send_whether_ended = ended_sender.send(());
                });

                result_sender
                    .send(signed_block_header)
                    .expect("Failed to send block header back to main thread");
            }
        });

        Ok(())
    }

    pub fn e2e_private_key(&self) -> &ephemeral_e2e::EndToEndPrivateKey {
        &self.e2e_encryption_key
    }
}

fn generate_finalize_block_data(
    chain_config: &ChainConfig,
    chainstate_handle: &dyn ChainstateInterface,
    block_height: BlockHeight,
    current_timestamp: BlockTimestamp,
    sealed_epoch_randomness: PoSRandomness,
    input_data: GenerateBlockInputData,
) -> Result<FinalizeBlockInputData, ConsensusPoSError> {
    match input_data {
        GenerateBlockInputData::PoS(pos_input_data) => {
            let max_block_timestamp = current_timestamp
                .add_int_seconds(chain_config.max_future_block_time_offset().as_secs())
                .ok_or(ConsensusPoSError::TimestampOverflow)?;

            let pledge_amount = chainstate_handle
                .get_stake_pool_data(pos_input_data.pool_id())
                .map_err(|err| {
                    ConsensusPoSError::ChainstateError(
                        consensus::ChainstateError::StakePoolDataReadError(
                            pos_input_data.pool_id(),
                            err.to_string(),
                        ),
                    )
                })?
                .ok_or(ConsensusPoSError::PropertyQueryError(
                    PropertyQueryError::StakePoolDataNotFound(pos_input_data.pool_id()),
                ))?
                .staker_balance()
                .map_err(|_| {
                    ConsensusPoSError::PropertyQueryError(
                        PropertyQueryError::StakerBalanceOverflow(pos_input_data.pool_id()),
                    )
                })?;

            let pool_balance = chainstate_handle
                .get_stake_pool_balance(pos_input_data.pool_id())
                .map_err(|err| {
                    ConsensusPoSError::ChainstateError(
                        consensus::ChainstateError::PoolBalanceReadError(
                            pos_input_data.pool_id(),
                            err.to_string(),
                        ),
                    )
                })?
                .ok_or(ConsensusPoSError::PropertyQueryError(
                    PropertyQueryError::PoolBalanceNotFound(pos_input_data.pool_id()),
                ))?;

            let epoch_index = chain_config.epoch_index_from_height(&block_height);

            Ok(FinalizeBlockInputData::PoS(PoSFinalizeBlockInputData::new(
                pos_input_data.stake_private_key().clone(),
                pos_input_data.vrf_private_key().clone(),
                epoch_index,
                sealed_epoch_randomness,
                max_block_timestamp,
                pledge_amount,
                pool_balance,
            )))
        }
        GenerateBlockInputData::PoW(_) => Ok(FinalizeBlockInputData::PoW),
        GenerateBlockInputData::None => Ok(FinalizeBlockInputData::None),
    }
}

#[cfg(test)]
mod tests;
