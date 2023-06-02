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

            let collected_transactions = mock_mempool.collect_txs_called.load(Ordering::Relaxed);
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
