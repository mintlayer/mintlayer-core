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

use std::sync::Arc;

use rstest::rstest;

use common::time_getter::TimeGetter;
use randomness::RngExt as _;
use test_utils::random::{Seed, make_seedable_rng};

use crate::{
    BlockProduction, BlockProductionError, JobKey,
    detail::{
        CustomId,
        job_manager::{JobManagerError, tests::MockJobManager},
    },
    prepare_thread_pool, test_blockprod_config,
    tests::helpers::setup_blockprod_test,
};

mod stop_all_jobs {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn error() {
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool,
            p2p,
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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate,
            mempool,
            p2p,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let (_other_job_key, _other_last_used_block_timestamp, _other_job_cancel_receiver) =
            block_production
                .job_manager_handle
                .add_job(CustomId::new_from_rng(&mut rng), None)
                .await
                .unwrap();

        let (_stop_job_key, _stop_last_used_block_timestamp, _stop_job_cancel_receiver) =
            block_production
                .job_manager_handle
                .add_job(CustomId::new_from_rng(&mut rng), None)
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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool,
            p2p,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut mock_job_manager = Box::<MockJobManager>::default();
        let return_value = make_seedable_rng(seed).random_range(0..=usize::MAX);
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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool,
            p2p,
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
        let job_key = JobKey::new(CustomId::new_from_rng(&mut rng));

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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate,
            mempool,
            p2p,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let (_other_job_key, _other_last_used_block_timestamp, _other_job_cancel_receiver) =
            block_production
                .job_manager_handle
                .add_job(CustomId::new_from_rng(&mut rng), None)
                .await
                .unwrap();

        let (stop_job_key, _stop_last_used_block_timestamp, _stop_job_cancel_receiver) =
            block_production
                .job_manager_handle
                .add_job(CustomId::new_from_rng(&mut rng), None)
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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate,
            mempool,
            p2p,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut job_keys = Vec::new();
        let jobs_to_create = rng.random_range(1..=20);

        for _ in 1..=jobs_to_create {
            let (job_key, _stop_last_used_block_timestamp, _stop_job_cancel_receiver) =
                block_production
                    .job_manager_handle
                    .add_job(CustomId::new_from_rng(&mut rng), None)
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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut rng = make_seedable_rng(seed);

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate,
            mempool,
            p2p,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let (_other_job_key, _other_last_used_block_timestamp, _other_job_cancel_receiver) =
            block_production
                .job_manager_handle
                .add_job(CustomId::new_from_rng(&mut rng), None)
                .await
                .unwrap();

        let stop_job_key = JobKey::new(CustomId::new_from_rng(&mut rng));

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
        let (_manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool,
            p2p,
            Default::default(),
            prepare_thread_pool(1),
        )
        .expect("Error initializing blockprod");

        let mut mock_job_manager = Box::<MockJobManager>::default();

        mock_job_manager.expect_stop_job().times(1).returning(|_| Ok(1));

        block_production.set_job_manager(mock_job_manager);

        let mut rng = make_seedable_rng(seed);
        let job_key = JobKey::new(CustomId::new_from_rng(&mut rng));

        let result = block_production.stop_job(job_key).await;

        assert_eq!(result, Ok(true), "Unexpected return value");
    }
}
