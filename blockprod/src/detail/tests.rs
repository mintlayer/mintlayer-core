// Copyright (c) 2023 RBB S.r.l
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

use std::{sync::atomic::Ordering, time::Duration};

use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{Builder, ChainType},
        transaction::TxInput,
        Destination, GenBlock, Genesis, OutPointSourceId, PoolId,
    },
    primitives::{time, Id, H256},
    time_getter::TimeGetter,
};
use consensus::{ConsensusCreationError, PoSGenerateBlockInputData, PoWGenerateBlockInputData};
use crypto::random::Rng;
use mempool::{MempoolInterface, MempoolSubsystemInterface};
use mocks::MempoolInterfaceMock;
use rstest::rstest;
use subsystem::CallRequest;
use test_utils::random::{make_seedable_rng, Seed};
use utils::once_destructor::OnceDestructor;

use crate::{
    detail::{
        job_manager::{tests::MockJobManager, JobManagerError},
        GenerateBlockInputData, TransactionsSource,
    },
    prepare_thread_pool,
    tests::{process_block, setup_blockprod_test, setup_pos},
    BlockProduction, BlockProductionError, JobKey,
};

mod collect_transactions {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn collect_txs_failed() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test(None);

        let mock_mempool = MempoolInterfaceMock::new();
        mock_mempool.collect_txs_should_error.store(true);

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

                match accumulator {
                    Err(BlockProductionError::MempoolChannelClosed) => {}
                    _ => panic!("Expected collect_tx() to fail"),
                };
            },
        );

        manager.main().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subsystem_error() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test(None);

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

            let collected_transactions = mock_mempool.collect_txs_called.load();
            assert!(collected_transactions, "Expected collect_tx() to be called");

            match accumulator {
                Err(BlockProductionError::SubsystemCallError(_)) => {}
                _ => panic!("Expected a subsystem error"),
            };
        })
        .await
        .expect("Subsystem error thread failed");
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn succeeded() {
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test(None);

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

                let collected_transactions = mock_mempool.collect_txs_called.load();
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
}

mod produce_block {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn input_none() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        TransactionsSource::Provided(vec![]),
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_eq!(
                    block_production
                        .job_manager_handle
                        .get_job_count()
                        .await
                        .expect("Error getting job count"),
                    0,
                    "Job manager should have zero jobs running"
                );

                process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn input_pos(#[case] seed: Seed) {
        let (
            pos_chain_config,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = setup_pos(seed);

        let (manager, chain_config, chainstate, mempool) =
            setup_blockprod_test(Some(pos_chain_config));

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let input_data = Box::new(PoSGenerateBlockInputData::new(
                    genesis_stake_private_key,
                    genesis_vrf_private_key,
                    PoolId::new(H256::zero()),
                    vec![TxInput::from_utxo(
                        OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                        0,
                    )],
                    vec![create_genesis_pool_txoutput],
                ));

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        GenerateBlockInputData::PoS(input_data),
                        TransactionsSource::Provided(vec![]),
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_eq!(
                    block_production
                        .job_manager_handle
                        .get_job_count()
                        .await
                        .expect("Error getting job count"),
                    0,
                    "Job manager should have zero jobs running"
                );

                process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn input_pow() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
                            Destination::AnyoneCanSpend,
                        ))),
                        TransactionsSource::Provided(vec![]),
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_eq!(
                    block_production
                        .job_manager_handle
                        .get_job_count()
                        .await
                        .expect("Error getting job count"),
                    0,
                    "Job manager should have zero jobs running"
                );

                process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_jobs_with_wait(#[case] seed: Seed) {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate,
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let mut rng = make_seedable_rng(seed);
                let jobs_to_create = rng.gen::<usize>() % 20 + 1;

                for _ in 0..jobs_to_create {
                    let (_block, job) = block_production
                        .produce_block(
                            GenerateBlockInputData::None,
                            TransactionsSource::Provided(vec![]),
                        )
                        .await
                        .unwrap();

                    job.await.unwrap();
                }

                let jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();
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
    async fn multiple_jobs_without_wait(#[case] seed: Seed) {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate,
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let mut rng = make_seedable_rng(seed);
                let jobs_to_create = rng.gen::<usize>() % 20 + 1;

                // The following is a race between the successive
                // calls to produce_block() and the job manager
                // cleaning up, so we try a number of times before
                // giving up

                for _ in 0..jobs_to_create {
                    let result = block_production
                        .produce_block(
                            GenerateBlockInputData::None,
                            TransactionsSource::Provided(vec![]),
                        )
                        .await;

                    match result {
                        Err(BlockProductionError::JobManagerError(
                            JobManagerError::JobAlreadyExists,
                        )) => break,
                        Err(_) => panic!("Duplicate job key should fail"),
                        Ok(_) => continue,
                    }
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overflow_tip_plus_one() {
        let (manager, chain_config, chainstate, mempool) = {
            let genesis_block = Genesis::new(
                "blockprod-testing".into(),
                BlockTimestamp::from_int_seconds(u64::MAX),
                vec![],
            );

            let override_chain_config =
                Builder::new(ChainType::Regtest).genesis_custom(genesis_block).build();

            setup_blockprod_test(Some(override_chain_config))
        };

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        TransactionsSource::Provided(vec![]),
                    )
                    .await;

                match result {
                    Err(BlockProductionError::FailedConsensusInitialization(
                        ConsensusCreationError::TimestampOverflow(_, 1),
                    )) => {}
                    _ => panic!("Expected timestamp overflow"),
                };
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overflow_max_blocktimestamp() {
        let override_chain_config = Builder::new(ChainType::Regtest)
            .max_future_block_time_offset(Duration::MAX)
            .build();

        let (manager, chain_config, chainstate, mempool) =
            setup_blockprod_test(Some(override_chain_config));

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        TransactionsSource::Provided(vec![]),
                    )
                    .await;

                match result {
                    Err(BlockProductionError::FailedConsensusInitialization(
                        ConsensusCreationError::TimestampOverflow(_, _),
                    )) => {}
                    _ => panic!("Expected timestamp overflow"),
                };
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_again_later() {
        // Ensure we reset the global mock time
        let _reset_time_destructor = OnceDestructor::new(time::reset);

        let (manager, chain_config, chainstate, mempool) = {
            let last_used_block_timestamp = TimeGetter::get_time(&TimeGetter::default());

            let genesis_block = Genesis::new(
                "blockprod-testing".into(),
                BlockTimestamp::from_duration_since_epoch(last_used_block_timestamp),
                vec![],
            );

            let override_chain_config =
                Builder::new(ChainType::Regtest).genesis_custom(genesis_block).build();

            _ = time::set(
                last_used_block_timestamp
                    .saturating_sub(*override_chain_config.max_future_block_time_offset()),
            );

            setup_blockprod_test(Some(override_chain_config))
        };

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        TransactionsSource::Provided(vec![]),
                    )
                    .await;

                match result {
                    Err(BlockProductionError::TryAgainLater) => {}
                    _ => panic!("Expected timestamp overflow"),
                };
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tip_changed() {
        // TODO: mock chainstate to return new tip
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_mempool() {
        // TODO: mock mempool to return transactions
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_provided() {
        // TODO: supply transactions
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_received() {
        // TODO: mock job manager
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solver_error() {
        // TODO
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solver_header_error() {
        // TODO
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_block_error() {
        // TODO
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_ignore_consensus() {
        // TODO
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_pow_consensus() {
        // TODO
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_pos_consensus() {
        // TODO
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lots_of_blocks_with_differing_consensus() {
        // TODO
    }
}

mod process_block_with_custom_id {
    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_jobs_with_wait(#[case] seed: Seed) {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

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

                let jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();
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
    async fn multiple_jobs_without_wait_same_jobkey(#[case] seed: Seed) {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let mut rng = make_seedable_rng(seed);

        let jobs_to_create = 10 + rng.gen::<usize>() % 20 + 1;

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

                let id: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();

                // The following is a race between the successive
                // calls to produce_block_with_custom_id() and the job
                // manager cleaning up, so we try a number of times
                // before giving up

                for _ in 0..jobs_to_create {
                    let result = block_production
                        .produce_block_with_custom_id(
                            GenerateBlockInputData::None,
                            TransactionsSource::Provided(vec![]),
                            Some(id.clone()),
                        )
                        .await;

                    match result {
                        Err(BlockProductionError::JobManagerError(
                            JobManagerError::JobAlreadyExists,
                        )) => break,
                        Err(_) => panic!("Duplicate job key should fail"),
                        Ok(_) => continue,
                    }
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }
}

mod stop_all_jobs {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn error() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate.clone(),
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut mock_job_manager = Box::<MockJobManager>::default();

        mock_job_manager
            .expect_stop_all_jobs()
            .times(1)
            .returning(|| Err(JobManagerError::FailedToStopJobs));

        block_production.set_job_manager(mock_job_manager);

        let result = block_production.stop_all_jobs().await;

        match result {
            Err(BlockProductionError::JobManagerError(_)) => {}
            _ => panic!("Unexpected return value"),
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ok(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

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
            .job_manager_handle
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let (_stop_job_key, _stop_job_cancel_receiver) = block_production
            .job_manager_handle
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let jobs_stopped = block_production.stop_all_jobs().await.unwrap();
        assert_eq!(jobs_stopped, 2, "Incorrect number of jobs stopped");

        let jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 0, "Jobs count is incorrect");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mocked_ok(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate.clone(),
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut mock_job_manager = Box::<MockJobManager>::default();
        let return_value = make_seedable_rng(seed).gen();
        let expected_value = return_value;

        mock_job_manager
            .expect_stop_all_jobs()
            .times(1)
            .returning(move || Ok(return_value));

        block_production.set_job_manager(mock_job_manager);

        let result = block_production.stop_all_jobs().await;

        assert_eq!(result, Ok(expected_value), "Unexpected return value");
    }
}

mod stop_job {
    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn error(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate.clone(),
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut mock_job_manager = Box::<MockJobManager>::default();

        mock_job_manager
            .expect_stop_job()
            .times(1)
            .returning(|_| Err(JobManagerError::FailedToStopJobs));

        block_production.set_job_manager(mock_job_manager);

        let mut rng = make_seedable_rng(seed);
        let job_key = JobKey::new(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>);

        let result = block_production.stop_job(job_key).await;

        match result {
            Err(BlockProductionError::JobManagerError(_)) => {}
            _ => panic!("Unexpected return value"),
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn existing_job_ok(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

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
            .job_manager_handle
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let (stop_job_key, _stop_job_cancel_receiver) = block_production
            .job_manager_handle
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let job_stopped = block_production.stop_job(stop_job_key).await.unwrap();
        assert!(job_stopped, "Failed to stop job");

        let jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 1, "Jobs count is incorrect");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_jobs_ok(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

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
                .job_manager_handle
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
            let current_jobs_count =
                block_production.job_manager_handle.get_job_count().await.unwrap();
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
    async fn non_existent_job_ok(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

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
            .job_manager_handle
            .add_job(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>)
            .await
            .unwrap();

        let stop_job_key = JobKey::new(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>);

        let job_stopped = block_production.stop_job(stop_job_key).await.unwrap();
        assert!(!job_stopped, "Stopped a non-existent job");

        let jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();
        assert_eq!(jobs_count, 1, "Jobs count is incorrect");
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mocked_ok(#[case] seed: Seed) {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let mut block_production = BlockProduction::new(
            chain_config,
            chainstate.clone(),
            mempool,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut mock_job_manager = Box::<MockJobManager>::default();

        mock_job_manager.expect_stop_job().times(1).returning(|_| Ok(1));

        block_production.set_job_manager(mock_job_manager);

        let mut rng = make_seedable_rng(seed);
        let job_key = JobKey::new(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>);

        let result = block_production.stop_job(job_key).await;

        assert_eq!(result, Ok(true), "Unexpected return value");
    }
}
