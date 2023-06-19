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

use std::sync::atomic::Ordering;

use common::{
    chain::{transaction::TxInput, Destination, GenBlock, OutPointSourceId, PoolId},
    primitives::{Id, H256},
};
use consensus::{PoSGenerateBlockInputData, PoWGenerateBlockInputData};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collect_transactions_collect_txs_failed() {
    let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test(None);

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

            let collected_transactions = mock_mempool.collect_txs_called.load(Ordering::Relaxed);
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
async fn collect_transactions_subsystem_error() {
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

        let collected_transactions = mock_mempool.collect_txs_called.load(Ordering::Relaxed);
        assert!(
            !collected_transactions,
            "Expected collect_tx() to not be called"
        );

        match accumulator {
            Err(BlockProductionError::SubsystemCallError(_)) => {}
            _ => panic!("Expected a subsystem error"),
        };
    })
    .await
    .expect("Subsystem error thread failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collect_transactions_succeeded() {
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

            let collected_transactions = mock_mempool.collect_txs_called.load(Ordering::Relaxed);
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
    async fn multiple_jobs(#[case] seed: Seed) {
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
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_all_jobs(#[case] seed: Seed) {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_all_jobs_error() {
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
async fn stop_all_jobs_ok(#[case] seed: Seed) {
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_job_error(#[case] seed: Seed) {
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
async fn stop_job_existing_job(#[case] seed: Seed) {
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
async fn stop_job_multiple_jobs(#[case] seed: Seed) {
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
        let current_jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();
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
async fn stop_job_non_existent_job(#[case] seed: Seed) {
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
async fn stop_job_ok(#[case] seed: Seed) {
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
