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

use common::{chain::config::create_unit_test_config, time_getter::TimeGetter};
use mempool::tx_accumulator::PackingStrategy;
use randomness::RngExt as _;
use test_utils::random::{Seed, make_seedable_rng};
use utils::once_destructor::OnceDestructor;

use crate::{
    BlockProductionError,
    detail::{GenerateBlockInputData, job_manager::JobManagerError},
    tests::helpers::setup_blockprod_test,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_jobs_with_wait(#[case] seed: Seed) {
    let chain_config = Arc::new(create_unit_test_config());
    let (blockprod_setup, manager) =
        setup_blockprod_test(Arc::clone(&chain_config), TimeGetter::default());

    let mut rng = make_seedable_rng(seed);

    let jobs_to_create = rng.random_range(1..=20);

    let block_production = blockprod_setup.make_blockprod_builder().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let produce_blocks_futures_iter = (0..jobs_to_create).map(|_| {
                let id: Vec<u8> = (0..1024).map(|_| rng.random::<u8>()).collect();

                block_production.produce_block_with_custom_id(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
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
    let chain_config = Arc::new(create_unit_test_config());
    let (blockprod_setup, manager) =
        setup_blockprod_test(Arc::clone(&chain_config), TimeGetter::default());

    let mut rng = make_seedable_rng(seed);

    let jobs_to_create = 10 + rng.random_range(1..=20);

    let block_production = blockprod_setup.make_blockprod_builder().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let id: Vec<u8> = (0..1024).map(|_| rng.random::<u8>()).collect();

            // The following is a race between the successive
            // calls to produce_block_with_custom_id() and the job
            // manager cleaning up, so we try a number of times
            // before giving up

            for _ in 0..jobs_to_create {
                let result = block_production
                    .produce_block_with_custom_id(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
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
