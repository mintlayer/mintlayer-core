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
    atomic::{AtomicBool, Ordering},
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
        Block, ChainConfig, RequiredConsensus, SignedTransaction,
    },
    primitives::BlockHeight,
    time_getter::TimeGetter,
};
use consensus::{
    generate_consensus_data_and_reward, ConsensusPoSError, FinalizeBlockInputData,
    GenerateBlockInputData, PoSFinalizeBlockInputData,
};
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};
use tokio::{
    sync::oneshot,
    time::{sleep, Duration},
};
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
        block_timestamp: BlockTimestamp,
    ) -> Result<
        (
            ConsensusData,
            BlockReward,
            GenBlockIndex,
            Option<FinalizeBlockInputData>,
        ),
        BlockProductionError,
    > {
        let consensus_data = self
            .chainstate_handle
            .call({
                let chain_config = Arc::clone(&self.chain_config);

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
                    let sealed_epoch_index =
                        chain_config.sealed_epoch_index(&block_height).unwrap_or(0);

                    let sealed_epoch_randomness = this
                        .get_epoch_data(sealed_epoch_index)
                        .map_err(|_| {
                            ConsensusPoSError::PropertyQueryError(
                                PropertyQueryError::EpochDataNotFound(block_height),
                            )
                        })?
                        .map(|epoch_data| *epoch_data.randomness())
                        .expect("There should always be epoch data avaiable");

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
                        &best_block_index,
                        sealed_epoch_index,
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
        let stop_flag = Arc::new(false.into());
        let tip_at_start = self.pull_best_block_index().await?;

        let (job_key, mut cancel_receiver) =
            self.job_manager.add_job(custom_id, tip_at_start.block_id()).await?;

        // This destructor ensures that the job manager cleans up its
        // housekeeping for the job when this current function returns
        let (job_stopper_function, job_finished_receiver) =
            self.job_manager.make_job_stopper_function();
        let _job_stopper_destructor = OnceDestructor::new(move || job_stopper_function(job_key));

        let mut previous_attempt = timestamp_at_start;
        let mut previous_consensus_status =
            self.chain_config.net_upgrade().consensus_status(tip_at_start.block_height());

        loop {
            let timestamp =
                BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

            match previous_consensus_status {
                RequiredConsensus::IgnoreConsensus | RequiredConsensus::PoW(_) => {}
                RequiredConsensus::PoS(_) => {
                    if previous_attempt == timestamp && timestamp != timestamp_at_start {
                        sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }

            let (consensus_data, block_reward, current_tip_index, finalize_block_data) =
                self.pull_consensus_data(input_data.clone(), timestamp).await?;

            previous_attempt = timestamp;
            previous_consensus_status = self
                .chain_config
                .net_upgrade()
                .consensus_status(current_tip_index.block_height());

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
                timestamp,
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
                        Err(_) => {
                            log::error!(
                                "Mining thread pool channel lost on tip {} on best height {}",
                                current_tip_index.block_id(),
                                current_tip_index.block_height()
                            );

                            continue;
                        }
                    };

                    let signed_block_header = match mining_result {
                        Ok(header) => header,
                        Err(e) => {
                            log::error!(
                                "Solving block in thread-pool returned an error on tip {} on best height {}: {e}",
                                current_tip_index.block_id(),
                                current_tip_index.block_height()
                            );

                            continue;
                        }
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
        timestamp: BlockTimestamp,
        finalize_block_data: Option<FinalizeBlockInputData>,
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

            let mut block_header = BlockHeader::new(
                current_tip_index.block_id(),
                merkle_proxy.merkle_tree().root(),
                merkle_proxy.witness_merkle_tree().root(),
                timestamp,
                consensus_data,
            );

            move || {
                let signed_block_header = consensus::finalize_consensus_data(
                    &chain_config,
                    &mut block_header,
                    current_tip_height,
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
    chainstate_handle: &(dyn ChainstateInterface),
    best_block_index: &GenBlockIndex,
    sealed_epoch_index: EpochIndex,
    sealed_epoch_randomness: PoSRandomness,
    input_data: GenerateBlockInputData,
) -> Result<Option<FinalizeBlockInputData>, ConsensusPoSError> {
    match input_data {
        GenerateBlockInputData::PoS(pos_input_data) => {
            let previous_block_timestamp = match best_block_index.prev_block_id() {
                None => chain_config.genesis_block().timestamp(),
                Some(prev_gen_block_id) => match prev_gen_block_id.classify(chain_config) {
                    GenBlockId::Genesis(_) => chain_config.genesis_block().timestamp(),
                    GenBlockId::Block(block_id) => chainstate_handle
                        .get_block(block_id)
                        .map_err(|_| ConsensusPoSError::FailedReadingBlock(block_id))?
                        .ok_or({
                            ConsensusPoSError::PropertyQueryError(
                                PropertyQueryError::BlockNotFound(block_id),
                            )
                        })?
                        .timestamp(),
                },
            };

            let max_block_timestamp = previous_block_timestamp
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

            Ok(Some(FinalizeBlockInputData::PoS(
                PoSFinalizeBlockInputData::new(
                    pos_input_data.stake_private_key().clone(),
                    pos_input_data.vrf_private_key().clone(),
                    sealed_epoch_index,
                    sealed_epoch_randomness,
                    previous_block_timestamp,
                    max_block_timestamp,
                    pool_balance,
                ),
            )))
        }
        GenerateBlockInputData::PoW(_) => Ok(Some(FinalizeBlockInputData::PoW)),
        GenerateBlockInputData::None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use common::chain::GenBlock;
    use common::primitives::{Id, H256};
    use crypto::random::Rng;
    use mempool::{MempoolInterface, MempoolSubsystemInterface};
    use mocks::MempoolInterfaceMock;
    use rstest::rstest;
    use std::sync::atomic::Ordering;
    use subsystem::CallRequest;
    use test_utils::random::{make_seedable_rng, Seed};

    use crate::{prepare_thread_pool, tests::setup_blockprod_test};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn collect_transactions_subsystem_error() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test();

        let mock_mempool = MempoolInterfaceMock::new();

        let mock_mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call: CallRequest<dyn MempoolInterface>, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

        mock_mempool_subsystem.call({
            let shutdown = manager.make_shutdown_trigger();
            move |_| shutdown.initiate()
        });

        // shutdown straight after startup, *then* call collect_transactions()
        manager.main().await;

        // spawn rather than adding a subsystem as manager is moved into main() above
        tokio::spawn(async move {
            let block_production = BlockProduction::new(
                chain_config,
                chainstate,
                mock_mempool_subsystem,
                Default::default(),
                prepare_thread_pool(1),
            )
            .expect("Error initializing blockprod");

            let accumulator = block_production.collect_transactions().await;

            let collected_transactions = mock_mempool.collect_txs_called.load(Ordering::Relaxed);
            assert!(
                !collected_transactions,
                "Expected collect_tx() to not be called"
            );

            assert!(
                matches!(
                    accumulator,
                    Err(BlockProductionError::SubsystemCallError(_))
                ),
                "Expected a subsystem error"
            );
        })
        .await
        .expect("Subsystem error thread failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn collect_transactions_collect_txs_failed() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test();

        let mock_mempool = MempoolInterfaceMock::new();
        mock_mempool.collect_txs_should_error.store(true, Ordering::Relaxed);

        let mock_mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

        manager.add_subsystem_with_custom_eventloop(
            "test-call",
            move |_: CallRequest<()>, _| async move {
                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate,
                    mock_mempool_subsystem,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let accumulator = block_production.collect_transactions().await;

                let collected_transactions =
                    mock_mempool.collect_txs_called.load(Ordering::Relaxed);
                assert!(collected_transactions, "Expected collect_tx() to be called");

                assert!(
                    matches!(accumulator, Err(BlockProductionError::MempoolChannelClosed)),
                    "Expected collect_tx() to fail"
                );
            },
        );

        manager.main().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn collect_transactions_succeeded() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test();

        let mock_mempool = MempoolInterfaceMock::new();

        let mock_mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

        let block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mock_mempool_subsystem,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let accumulator = block_production.collect_transactions().await;

                let collected_transactions =
                    mock_mempool.collect_txs_called.load(Ordering::Relaxed);
                assert!(collected_transactions, "Expected collect_tx() to be called");

                assert!(
                    accumulator.is_ok(),
                    "Expected collect_transactions() to succeed"
                );
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_job_non_existent_job(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let (_other_job_key, _other_job_cancel_receiver) = block_production
            .job_manager
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let stop_job_key = JobKey::new(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>);

        let job_stopped = block_production.stop_job(stop_job_key).await.unwrap();
        assert!(!job_stopped, "Stopped a non-existent job");

        let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 1, "Jobs count is incorrect");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_job_existing_job(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let (_other_job_key, _other_job_cancel_receiver) = block_production
            .job_manager
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let (stop_job_key, _stop_job_cancel_receiver) = block_production
            .job_manager
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let job_stopped = block_production.stop_job(stop_job_key).await.unwrap();
        assert!(job_stopped, "Failed to stop job");

        let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 1, "Jobs count is incorrect");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_job_multiple_jobs(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut job_keys = Vec::new();
        let jobs_to_create = rng.gen::<usize>() % 20 + 1;

        for _ in 1..=jobs_to_create {
            let (job_key, _stop_job_cancel_receiver) = block_production
                .job_manager
                .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
                .await
                .unwrap();

            job_keys.push(job_key)
        }

        assert_eq!(
            job_keys.len(),
            jobs_to_create,
            "Failed to create {jobs_to_create} jobs"
        );

        while !job_keys.is_empty() {
            let current_jobs_count = block_production.job_manager.get_job_count().await.unwrap();
            assert_eq!(
                current_jobs_count,
                job_keys.len(),
                "Jobs count is incorrect"
            );

            let job_key = job_keys.pop().unwrap();

            let job_stopped = block_production.stop_job(job_key).await.unwrap();
            assert!(job_stopped, "Failed to stop job");
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn produce_block_multiple_jobs(#[case] seed: Seed) {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let mut rng = make_seedable_rng(seed);

        let jobs_to_create = rng.gen::<usize>() % 20 + 1;

        let block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let produce_blocks_futures_iter = (0..jobs_to_create).map(|_| {
                    let id: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();

                    block_production.produce_block_with_custom_id(
                        GenerateBlockInputData::None,
                        TransactionsSource::Provided(vec![]),
                        Some(id),
                    )
                });

                let produce_results = futures::future::join_all(produce_blocks_futures_iter).await;

                let jobs_finished_iter = produce_results.into_iter().map(|r| r.unwrap());

                for (_block, job) in jobs_finished_iter {
                    job.await.unwrap();
                }

                let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
                assert_eq!(jobs_count, 0, "Job count was incorrect {jobs_count}");
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_all_jobs(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let (_other_job_key, _other_job_cancel_receiver) = block_production
            .job_manager
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let (_stop_job_key, _stop_job_cancel_receiver) = block_production
            .job_manager
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let jobs_stopped = block_production.stop_all_jobs().await.unwrap();
        assert_eq!(jobs_stopped, 2, "Incorrect number of jobs stopped");

        let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 0, "Jobs count is incorrect");
    }
}
