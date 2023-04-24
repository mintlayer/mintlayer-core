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

use chainstate_types::{BlockIndex, GenBlockIndex, GetAncestorError};
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, timestamp::BlockTimestamp,
            BlockBody, BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, Destination, SignedTransaction,
    },
    primitives::BlockHeight,
    time_getter::TimeGetter,
};
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

    async fn stop_job_in_scope(&mut self, job_key: JobKey, job_key_destroyed: &AtomicBool) {
        // TODO: this function has to go.
        // I couldn't find a way to use RAII to call an async function that takes a mut reference to self.
        // Once this solution is found, this has to go
        {
            assert!(
                !job_key_destroyed.load(std::sync::atomic::Ordering::SeqCst),
                "Must be true as it was done already"
            );
            let result_receiver = self.job_manager.stop_job(job_key.clone());
            let _stop_result = result_receiver.await;
        }
        // We consume the value so that it doesn't happen again
        job_key_destroyed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    async fn pull_consensus_data(
        &self,
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

                    let consensus_data = consensus::generate_consensus_data(
                        &chain_config,
                        &best_block_index,
                        block_timestamp,
                        best_block_index.block_height().next_height(),
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

    pub async fn generate_block(
        &mut self,
        _reward_destination: Destination,
        transactions_source: TransactionsSource,
    ) -> Result<Block, BlockProductionError> {
        let stop_flag = Arc::new(false.into());

        let timestamp = BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

        let (_, tip_at_start) = self.pull_consensus_data(timestamp).await?;

        let (job_key, mut cancel_receiver) =
            self.job_manager.add_job(tip_at_start.block_id()).await?;

        // At the end of this function, the job has to be removed
        // Once the job key is used, we swap it with None... this is all temporary.
        // The docs in the function self.stop_job_in_scope()
        let job_key_destroyed = AtomicBool::new(false);
        let _job_remove_checker = OnceDestructor::new(|| {
            assert!(job_key_destroyed.load(std::sync::atomic::Ordering::SeqCst));
        });

        loop {
            let timestamp =
                BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

            let (consensus_data, current_tip_index) = self.pull_consensus_data(timestamp).await?;

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

            let tx_merkle_root = calculate_tx_merkle_root(&block_body)
                .map_err(BlockCreationError::MerkleTreeError)?;
            let witness_merkle_root = calculate_witness_merkle_root(&block_body)
                .map_err(BlockCreationError::MerkleTreeError)?;

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

                    // This can fail if the function exited before the mining thread finished
                    let _send_whether_ended = ended_sender.send(());

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

                    // TODO: use RAII for this
                    self.stop_job_in_scope(job_key, &job_key_destroyed).await;

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

                    // TODO: use RAII for this
                    self.stop_job_in_scope(job_key, &job_key_destroyed).await;

                    let block = Block::new_from_header(block_header, block_body.clone())?;
                    return Ok(block);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use common::chain::GenBlock;
    use common::primitives::{Id, H256};
    use crypto::random::make_pseudo_rng;
    use mempool::{MempoolInterface, MempoolSubsystemInterface};
    use mocks::MempoolInterfaceMock;
    use std::sync::atomic::Ordering::Relaxed;
    use subsystem::CallRequest;

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

            let collected_transactions = mock_mempool.collect_txs_called.load(Relaxed);
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
        mock_mempool.collect_txs_should_error.store(true, Relaxed);

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

                let collected_transactions = mock_mempool.collect_txs_called.load(Relaxed);
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

                let collected_transactions = mock_mempool.collect_txs_called.load(Relaxed);
                assert!(collected_transactions, "Expected collect_tx() to be called");

                assert!(
                    accumulator.is_ok(),
                    "Expected collect_transactions() to succeed"
                );
            },
        );

        manager.main().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_job_non_existent_job() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

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
            .add_job(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>)
            .await
            .unwrap();

        let stop_job_key =
            JobKey::new(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>);

        let job_stopped = block_production.stop_job(stop_job_key).await.unwrap();
        assert!(!job_stopped, "Stopped a non-existent job");

        let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 1, "Jobs count is incorrect");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_job_existing_job() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

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
            .add_job(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>)
            .await
            .unwrap();

        let (stop_job_key, _stop_job_cancel_receiver) = block_production
            .job_manager
            .add_job(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>)
            .await
            .unwrap();

        let job_stopped = block_production.stop_job(stop_job_key).await.unwrap();
        assert!(job_stopped, "Failed to stop job");

        let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 1, "Jobs count is incorrect");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_job_multiple_jobs() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut job_keys = Vec::new();
        let jobs_to_create = 5;

        for _ in 1..=jobs_to_create {
            let (job_key, _stop_job_cancel_receiver) = block_production
                .job_manager
                .add_job(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>)
                .await
                .unwrap();

            job_keys.push(job_key)
        }

        assert_eq!(job_keys.len(), jobs_to_create, "Failed to create {jobs_to_create} jobs");

        while !job_keys.is_empty() {
            let current_jobs_count = block_production.job_manager.get_job_count().await.unwrap();
            assert_eq!(current_jobs_count, job_keys.len(), "Jobs count is incorrect");

            let job_key = job_keys.pop().unwrap();

            let job_stopped = block_production.stop_job(job_key).await.unwrap();
            assert!(job_stopped, "Failed to stop job");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn generate_block_multiple_jobs() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let jobs_to_create = 5;

        let mut block_production = BlockProduction::new(
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
                for _ in 1..=jobs_to_create {
                    _ = block_production
                        .generate_block(
                            Destination::AnyoneCanSpend,
                            TransactionsSource::Provided(vec![]),
                        )
                        .await;
                }

                shutdown_trigger.initiate();

                let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
                assert_eq!(jobs_count, 0, "Job count was incorrect {jobs_count}");
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_all_jobs() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

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
            .add_job(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>)
            .await
            .unwrap();

        let (_stop_job_key, _stop_job_cancel_receiver) = block_production
            .job_manager
            .add_job(Id::new(H256::random_using(&mut make_pseudo_rng())) as Id<GenBlock>)
            .await
            .unwrap();

        let jobs_stopped = block_production.stop_all_jobs().await.unwrap();
        assert_eq!(jobs_stopped, 2, "Incorrect number of jobs stopped");

        let jobs_count = block_production.job_manager.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 0, "Jobs count is incorrect");
    }
}
