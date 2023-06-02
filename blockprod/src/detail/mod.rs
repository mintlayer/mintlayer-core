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

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
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
        Block, ChainConfig, SignedTransaction,
    },
    primitives::BlockHeight,
    time_getter::TimeGetter,
};
use consensus::{
    generate_consensus_data_and_reward, ConsensusCreationError, ConsensusPoSError,
    FinalizeBlockInputData, GenerateBlockInputData, PoSFinalizeBlockInputData,
};
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};
use tokio::sync::oneshot;
use utils::once_destructor::OnceDestructor;

use crate::{
    detail::job_manager::{JobKey, JobManager},
    BlockProductionError,
};

#[derive(Debug, Clone)]
pub enum TransactionsSource {
    Mempool,
    Provided(Vec<SignedTransaction>),
}

#[allow(dead_code)]
pub struct BlockProduction {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    job_manager: JobManager,
    mining_thread_pool: Arc<slave_pool::ThreadPool>,
}

impl BlockProduction {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        mining_thread_pool: Arc<slave_pool::ThreadPool>,
    ) -> Result<Self, BlockProductionError> {
        let job_manager = JobManager::new(chainstate_handle.clone());

        let block_production = Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            job_manager,
            mining_thread_pool,
        };

        Ok(block_production)
    }

    pub fn time_getter(&self) -> &TimeGetter {
        &self.time_getter
    }

    pub async fn stop_all_jobs(&mut self) -> Result<usize, BlockProductionError> {
        self.job_manager
            .stop_all_jobs()
            .await
            .map_err(BlockProductionError::JobManagerError)
    }

    pub async fn stop_job(&mut self, job_key: JobKey) -> Result<bool, BlockProductionError> {
        Ok(self.job_manager.stop_job(job_key).await? == 1)
    }

    pub async fn collect_transactions(
        &self,
    ) -> Result<Box<dyn TransactionAccumulator>, BlockProductionError> {
        let max_block_size = self.chain_config.max_block_size_from_txs();
        let returned_accumulator = self
            .mempool_handle
            .call(move |mempool| {
                mempool.collect_txs(Box::new(DefaultTxAccumulator::new(max_block_size)))
            })
            .await?
            .map_err(|_| BlockProductionError::MempoolChannelClosed)?;
        Ok(returned_accumulator)
    }

    async fn pull_consensus_data(
        &self,
        input_data: GenerateBlockInputData,
        block_timestamp_seconds: Arc<AtomicU64>,
    ) -> Result<
        (
            ConsensusData,
            BlockReward,
            GenBlockIndex,
            FinalizeBlockInputData,
        ),
        BlockProductionError,
    > {
        let consensus_data = self
            .chainstate_handle
            .call({
                let chain_config = Arc::clone(&self.chain_config);

                let block_timestamp = BlockTimestamp::from_int_seconds(
                    block_timestamp_seconds.load(Ordering::SeqCst),
                );

                let current_timestamp =
                    BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

                move |this| {
                    let best_block_index = this
                        .get_best_block_index()
                        .expect("Best block index retrieval failed in block production");

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

                    let block_height = best_block_index.block_height().next_height();
                    let sealed_epoch_index = chain_config.sealed_epoch_index(&block_height);

                    let sealed_epoch_randomness = sealed_epoch_index
                        .map(|index| this.get_epoch_data(index))
                        .transpose()
                        .map_err(|_| {
                            ConsensusPoSError::PropertyQueryError(
                                PropertyQueryError::EpochDataNotFound(block_height),
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
                        block_timestamp,
                        block_height,
                        get_ancestor,
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
        transactions_source: TransactionsSource,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.produce_block_with_custom_id(input_data, transactions_source, None).await
    }

    async fn produce_block_with_custom_id(
        &self,
        input_data: GenerateBlockInputData,
        transactions_source: TransactionsSource,
        custom_id: Option<Vec<u8>>,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let tip_at_start = self.pull_best_block_index().await?;

        let (job_key, mut cancel_receiver) =
            self.job_manager.add_job(custom_id, tip_at_start.block_id()).await?;

        // This destructor ensures that the job manager cleans up its
        // housekeeping for the job when this current function returns
        let (job_stopper_function, job_finished_receiver) =
            self.job_manager.make_job_stopper_function();
        let _job_stopper_destructor = OnceDestructor::new(move || job_stopper_function(job_key));

        // Unlike Proof of Work, which can vary any header field when
        // searching for a valid block, Proof of Stake can only vary
        // the header timestamp. Its search space starts at the
        // previous block's timestamp + 1 second, and ends at the
        // current timestamp + some distance in time defined by the
        // blockchain.
        //
        // This variable keeps track of the last timestamp that was
        // attempted, and during Proof of Stake, will prevent
        // searching over the same search space.
        let last_timestamp_seconds_used = {
            let tip_timestamp = tip_at_start.block_timestamp();

            let tip_plus_one = tip_timestamp
                .add_int_seconds(1)
                .ok_or(ConsensusCreationError::TimestampOverflow(tip_timestamp, 1))?;

            Arc::new(AtomicU64::new(tip_plus_one.as_int_seconds()))
        };

        let max_block_timestamp = {
            let current_timestamp =
                BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

            current_timestamp
                .add_int_seconds(self.chain_config.max_future_block_time_offset().as_secs())
                .ok_or(ConsensusCreationError::TimestampOverflow(
                    current_timestamp,
                    self.chain_config.max_future_block_time_offset().as_secs(),
                ))?
        };

        loop {
            {
                // If the last timestamp we tried on a block is larger than the max range allowed, no point in continuing
                let last_used_block_timestamp = BlockTimestamp::from_int_seconds(
                    last_timestamp_seconds_used.load(Ordering::SeqCst),
                );

                if last_used_block_timestamp >= max_block_timestamp {
                    stop_flag.store(true, Ordering::Relaxed);
                    return Err(BlockProductionError::TryAgainLater);
                }
            }

            let (consensus_data, block_reward, current_tip_index, finalize_block_data) = self
                .pull_consensus_data(input_data.clone(), Arc::clone(&last_timestamp_seconds_used))
                .await?;

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

            // TODO: see if we can simplify this
            let transactions = match transactions_source.clone() {
                TransactionsSource::Mempool => {
                    self.collect_transactions().await?.transactions().clone()
                }
                TransactionsSource::Provided(txs) => txs,
            };

            let block_body = BlockBody::new(block_reward, transactions);

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
                    stop_flag.store(true, Ordering::Relaxed);

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

    #[allow(clippy::too_many_arguments)]
    fn spawn_block_solver(
        &self,
        current_tip_index: &GenBlockIndex,
        stop_flag: Arc<AtomicBool>,
        block_body: &BlockBody,
        block_timestamp_seconds: Arc<AtomicU64>,
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

            let block_timestamp =
                BlockTimestamp::from_int_seconds(block_timestamp_seconds.load(Ordering::SeqCst));

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

            let pool_balance = chainstate_handle
                .get_stake_pool_balance(pos_input_data.pool_id())
                .map_err(|_| {
                    ConsensusPoSError::PropertyQueryError(PropertyQueryError::PoolBalanceReadError(
                        pos_input_data.pool_id(),
                    ))
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
                pool_balance,
            )))
        }
        GenerateBlockInputData::PoW(_) => Ok(FinalizeBlockInputData::PoW),
        GenerateBlockInputData::None => Ok(FinalizeBlockInputData::None),
    }
}

#[cfg(test)]
mod tests;
