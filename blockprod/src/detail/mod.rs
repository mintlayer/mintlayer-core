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

use crate::{
    detail::job_manager::{JobKey, JobManager},
    BlockProductionError,
};

use std::sync::{atomic::AtomicBool, mpsc, Arc};

use chainstate::{ChainstateHandle, PropertyQueryError};

use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, EpochData, GenBlockIndex, GetAncestorError,
};
use common::{
    chain::{
        block::{
            block_body::BlockBody, consensus_data::GenerateBlockInputData,
            timestamp::BlockTimestamp, BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, Destination, SignedTransaction,
    },
    primitives::BlockHeight,
    time_getter::TimeGetter,
};
use consensus::ConsensusPoSError;
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};

use tokio::sync::oneshot;
use utils::once_destructor::OnceDestructor;

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
        input_data: Option<GenerateBlockInputData>,
        block_timestamp: BlockTimestamp,
    ) -> Result<(ConsensusData, GenBlockIndex), BlockProductionError> {
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

                    let sealed_epoch_randomness = chain_config
                        .sealed_epoch_index(&block_height)
                        .map(|index| this.get_epoch_data(index))
                        .transpose()
                        .map_err(|_| {
                            ConsensusPoSError::PropertyQueryError(
                                PropertyQueryError::EpochDataNotFound,
                            )
                        })?
                        .flatten()
                        .or_else(|| Some(EpochData::new(PoSRandomness::at_genesis(&chain_config))));

                    let consensus_data = consensus::generate_consensus_data(
                        &chain_config,
                        &best_block_index,
                        sealed_epoch_randomness,
                        input_data,
                        block_timestamp,
                        block_height,
                        get_ancestor,
                    );

                    consensus_data.map(|cons_data| (cons_data, best_block_index))
                }
            })
            .await?
            .map_err(BlockProductionError::FailedConsensusInitialization)?;

        Ok(consensus_data)
    }

    fn solve_block(
        chain_config: Arc<ChainConfig>,
        mut block_header: BlockHeader,
        current_tip_height: BlockHeight,
        stop_flag: Arc<AtomicBool>,
    ) -> Result<BlockHeader, BlockProductionError> {
        consensus::finalize_consensus_data(
            &chain_config,
            &mut block_header,
            current_tip_height,
            stop_flag,
        )?;

        Ok(block_header)
    }

    /// The function the creates a new block.
    /// Returns the block and a oneshot receiver that will be notified when
    /// the internal job is finished. Generally this can be used to ensure
    /// that the block production process has ended and that there's no
    /// remnants in the job manager.
    pub async fn produce_block(
        &self,
        input_data: Option<GenerateBlockInputData>,
        reward_destination: Destination,
        transactions_source: TransactionsSource,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        self.produce_block_with_custom_id(input_data, reward_destination, transactions_source, None)
            .await
    }

    async fn produce_block_with_custom_id(
        &self,
        input_data: Option<GenerateBlockInputData>,
        _reward_destination: Destination,
        transactions_source: TransactionsSource,
        custom_id: Option<Vec<u8>>,
    ) -> Result<(Block, oneshot::Receiver<usize>), BlockProductionError> {
        let stop_flag = Arc::new(false.into());

        let timestamp = BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

        let (_, tip_at_start) = self.pull_consensus_data(input_data.clone(), timestamp).await?;

        let (job_key, mut cancel_receiver) =
            self.job_manager.add_job(custom_id, tip_at_start.block_id()).await?;

        // At the end of this function, the job has to be removed
        let (job_remover_func, end_confirm_receiver) = self.job_manager.make_job_stopper_function();
        let _job_remover = OnceDestructor::new(move || job_remover_func(job_key));

        loop {
            let timestamp =
                BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

            let (consensus_data, current_tip_index) =
                self.pull_consensus_data(input_data.clone(), timestamp).await?;

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

            // TODO: instead of the following static value, look at
            // self.chain_config for the current block reward, then send
            // it to self.reward_destination
            let block_reward = BlockReward::new(vec![]);

            // TODO: see if we can simplify this
            let transactions = match transactions_source.clone() {
                TransactionsSource::Mempool => {
                    self.collect_transactions().await?.transactions().clone()
                }
                TransactionsSource::Provided(txs) => txs,
            };

            let block_body = BlockBody::new(block_reward, transactions);

            let merkle_proxy =
                block_body.merkle_tree_proxy().map_err(BlockCreationError::MerkleTreeError)?;

            let tx_merkle_root = merkle_proxy.merkle_tree().root();
            let witness_merkle_root = merkle_proxy.witness_merkle_tree().root();

            let block_header = BlockHeader::new(
                current_tip_index.block_id(),
                tx_merkle_root,
                witness_merkle_root,
                timestamp,
                consensus_data,
            );

            // A synchronous channel that sends only when the mining/staking is done
            let (ended_sender, ended_receiver) = mpsc::channel::<()>();

            // Return the result of mining
            let (result_sender, mut result_receiver) = oneshot::channel();

            {
                let chain_config = Arc::clone(&self.chain_config);
                let current_tip_height = current_tip_index.block_height();
                let stop_flag = Arc::clone(&stop_flag);

                self.mining_thread_pool.spawn(move || {
                    let block_header = Self::solve_block(
                        chain_config,
                        block_header,
                        current_tip_height,
                        stop_flag,
                    );

                    let _ended_sender = OnceDestructor::new(move || {
                        // This can fail if the function exited before the mining thread finished
                        let _send_whether_ended = ended_sender.send(());
                    });

                    result_sender
                        .send(block_header)
                        .expect("Failed to send block header back to main thread");
                });
            }

            tokio::select! {
                _ = cancel_receiver.recv() => {
                    stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);

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

                    let block_header = match mining_result {
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

                    let block = Block::new_from_header(block_header.with_no_signature(), block_body.clone())?;
                    return Ok((block, end_confirm_receiver));
                }
            }
        }
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
    async fn generate_block_multiple_jobs(#[case] seed: Seed) {
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
                        None,
                        Destination::AnyoneCanSpend,
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

    // TODO: add generate_block() tests with actual transactions

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
