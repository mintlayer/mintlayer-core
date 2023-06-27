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

use std::{sync::Arc, time::Duration};

use chainstate::{ChainstateError, ChainstateHandle, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockCreationError},
        config::{create_testnet, create_unit_test_config, Builder, ChainType},
        create_unittest_pos_config,
        stakelock::StakePoolData,
        transaction::TxInput,
        ConsensusUpgrade, Destination, GenBlock, Genesis, NetUpgrades, OutPointSourceId, PoolId,
        RequiredConsensus, TxOutput, UpgradeVersion,
    },
    primitives::{per_thousand::PerThousand, time, Amount, BlockHeight, Compact, Id, H256},
    time_getter::TimeGetter,
};
use consensus::{
    ConsensusCreationError, ConsensusPoSError, ConsensusPoWError, PoSGenerateBlockInputData,
    PoWGenerateBlockInputData,
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use mempool::{MempoolInterface, MempoolSubsystemInterface};
use mocks::{MempoolInterfaceMock, MockChainstateInterfaceMock};
use rstest::rstest;
use subsystem::CallRequest;
use test_utils::random::{make_seedable_rng, Seed};
use tokio::{
    sync::{mpsc::unbounded_channel, oneshot},
    time::sleep,
};
use utils::once_destructor::OnceDestructor;

use crate::{
    detail::{
        job_manager::{tests::MockJobManager, JobManagerError},
        GenerateBlockInputData, TransactionsSource,
    },
    prepare_thread_pool,
    tests::{assert_process_block, setup_blockprod_test, setup_pos},
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

                let collected_transactions = mock_mempool.collect_txs_called.load();
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
            assert!(
                !collected_transactions,
                "Expected collect_tx() not to be called"
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
    async fn pull_best_block_index_error() {
        let (mut manager, chain_config, _, mempool) = setup_blockprod_test(None);

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = Box::new(MockChainstateInterfaceMock::new());
            mock_chainstate.expect_subscribe_to_events().times(1).returning(|_| ());

            mock_chainstate.expect_get_best_block_index().times(1).returning(|| {
                Err(ChainstateError::FailedToReadProperty(
                    PropertyQueryError::BestBlockIndexNotFound,
                ))
            });

            manager.add_subsystem("mock-chainstate", mock_chainstate)
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
                    chainstate_subsystem,
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
                    Err(BlockProductionError::FailedToConstructBlock(
                        BlockCreationError::CurrentTipRetrievalError,
                    )) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn add_job_error() {
        let (manager, chain_config, chainstate, mempool) = setup_blockprod_test(None);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let mut block_production = BlockProduction::new(
                    chain_config,
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let mut mock_job_manager = Box::new(MockJobManager::new());

                mock_job_manager
                    .expect_add_job()
                    .times(1)
                    .returning(|_, _| Err(JobManagerError::FailedToSendNewJobEvent));

                block_production.set_job_manager(mock_job_manager);

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        TransactionsSource::Provided(vec![]),
                    )
                    .await;

                match result {
                    Err(BlockProductionError::JobManagerError(
                        JobManagerError::FailedToSendNewJobEvent,
                    )) => {}
                    _ => panic!("Unexpected return value"),
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

                assert_job_count(&block_production, 0).await;
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

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_again_later() {
        // Ensure we reset the global mock time on exit
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

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_consensus_data_error() {
        let (mut manager, chain_config, _, mempool) = setup_blockprod_test(None);

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = Box::new(MockChainstateInterfaceMock::new());
            mock_chainstate.expect_subscribe_to_events().times(1).returning(|_| ());

            let mut expected_return_values = vec![
                Ok(GenBlockIndex::Genesis(Arc::clone(
                    chain_config.genesis_block(),
                ))),
                Err(ChainstateError::FailedToReadProperty(
                    PropertyQueryError::BestBlockNotFound,
                )),
            ];

            mock_chainstate
                .expect_get_best_block_index()
                .times(expected_return_values.len())
                .returning(move || expected_return_values.remove(0));

            manager.add_subsystem("mock-chainstate", mock_chainstate)
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
                    chainstate_subsystem,
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
                        ConsensusCreationError::PropertyQueryError(
                            PropertyQueryError::BestBlockIndexNotFound,
                        ),
                    )) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tip_changed() {
        let (mut manager, chain_config, _, mempool) = setup_blockprod_test(None);

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = Box::new(MockChainstateInterfaceMock::new());
            mock_chainstate.expect_subscribe_to_events().times(1).returning(|_| ());

            let mut expected_return_values = vec![
                Ok(GenBlockIndex::Genesis(Arc::clone(
                    chain_config.genesis_block(),
                ))),
                Ok(GenBlockIndex::Genesis(Arc::clone(
                    create_testnet().genesis_block(),
                ))),
            ];

            mock_chainstate
                .expect_get_best_block_index()
                .times(expected_return_values.len())
                .returning(move || expected_return_values.remove(0));

            manager.add_subsystem("mock-chainstate", mock_chainstate)
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
                    chainstate_subsystem,
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
                    Err(BlockProductionError::TipChanged(_, _, _, _)) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_mempool_error() {
        // TODO: mock mempool to return transactions
        let (mut manager, chain_config, chainstate, _mempool) = setup_blockprod_test(None);

        let mock_mempool = MempoolInterfaceMock::new();
        mock_mempool.collect_txs_should_error.store(true);

        let mempool_subsystem = manager.add_subsystem_with_custom_eventloop("mock-mempool", {
            let mock_mempool = mock_mempool.clone();
            move |call, shutdn| async move {
                mock_mempool.run(call, shutdn).await;
            }
        });

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
                    mempool_subsystem,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(GenerateBlockInputData::None, TransactionsSource::Mempool)
                    .await;

                match result {
                    Err(BlockProductionError::MempoolChannelClosed) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_mempool() {
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
                        // TODO: Add transactions to the mempool
                        TransactionsSource::Mempool,
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_provided() {
        // TODO: supply transactions
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
                        // TODO: Add transactions to the parameters
                        TransactionsSource::Provided(vec![]),
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_received(#[case] seed: Seed) {
        let net_upgrades_chain_config = {
            let net_upgrades = NetUpgrades::initialize(vec![
                (
                    BlockHeight::new(0),
                    UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
                ),
                (
                    BlockHeight::new(1),
                    UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                        // Make difficulty impossible so the cancel from
                        // the mock job manager is always seen before
                        // solving the block
                        initial_difficulty: Compact::lowest_value(),
                    }),
                ),
            ])
            .expect("Net upgrade is valid");

            Builder::new(ChainType::Regtest).net_upgrades(net_upgrades).build()
        };

        let (manager, chain_config, chainstate, mempool) =
            setup_blockprod_test(Some(net_upgrades_chain_config));

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let mut block_production = BlockProduction::new(
                    chain_config,
                    chainstate,
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let mut mock_job_manager = Box::<MockJobManager>::default();

                mock_job_manager.expect_add_job().times(1).returning(move |_, _| {
                    let (_, cancel_receiver) = unbounded_channel::<()>();
                    let mut rng = make_seedable_rng(seed);
                    let job_key =
                        JobKey::new(None, Id::new(H256::random_using(&mut rng)) as Id<GenBlock>);
                    Ok((job_key, cancel_receiver))
                });

                mock_job_manager.expect_make_job_stopper_function().times(1).returning(|| {
                    let (_, result_receiver) = oneshot::channel::<usize>();
                    (Box::new(|_| {}), result_receiver)
                });

                block_production.set_job_manager(mock_job_manager);

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
                            Destination::AnyoneCanSpend,
                        ))),
                        TransactionsSource::Provided(vec![]),
                    )
                    .await;

                match result {
                    Err(BlockProductionError::Cancelled) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_ignore_consensus() {
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

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_pow_consensus() {
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

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_pos_consensus(#[case] seed: Seed) {
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

                let block_production = BlockProduction::new(
                    chain_config.clone(),
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

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

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        GenerateBlockInputData::PoS(input_data),
                        TransactionsSource::Provided(vec![]),
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solve_lots_of_blocks_with_differing_consensus(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let (genesis_stake_private_key, genesis_stake_public_key) =
            PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);

        let (genesis_vrf_private_key, genesis_vrf_public_key) =
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let mut kernel_input_utxo = {
            let min_stake_pool_pledge = {
                // throw away just to get value
                let chain_config = create_unit_test_config();
                chain_config.min_stake_pool_pledge()
            };

            TxOutput::CreateStakePool(
                H256::zero().into(),
                Box::new(StakePoolData::new(
                    min_stake_pool_pledge,
                    Destination::PublicKey(genesis_stake_public_key.clone()),
                    genesis_vrf_public_key,
                    Destination::PublicKey(genesis_stake_public_key.clone()),
                    PerThousand::new(1000).expect("Valid per thousand"),
                    Amount::ZERO,
                )),
            )
        };

        let blocks_to_generate = rng.gen_range(100..=1000);

        let net_upgrades_chain_config = {
            let genesis_block = Genesis::new(
                "blockprod-testing".into(),
                BlockTimestamp::from_int_seconds(
                    TimeGetter::default()
                        .get_time()
                        .checked_sub(Duration::new(
                            // Genesis must be in the past: now - (1 day..2 weeks)
                            rng.gen_range(60 * 60 * 24..60 * 60 * 24 * 14),
                            0,
                        ))
                        .expect("No time underflow")
                        .as_secs(),
                ),
                vec![kernel_input_utxo.clone()],
            );

            let consensus_types = vec![
                ConsensusUpgrade::IgnoreConsensus,
                ConsensusUpgrade::PoW {
                    initial_difficulty: Compact::highest_value(),
                },
                ConsensusUpgrade::PoS {
                    initial_difficulty: Compact::highest_value(),
                    config: create_unittest_pos_config(),
                },
            ];

            let mut randomized_net_upgrades = vec![(
                BlockHeight::new(0),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
            )];

            let mut next_height_consensus_change = 1;

            while next_height_consensus_change < blocks_to_generate {
                let next_consensus_type = rng.gen_range(0..consensus_types.len());

                randomized_net_upgrades.push((
                    BlockHeight::new(next_height_consensus_change),
                    UpgradeVersion::ConsensusUpgrade(consensus_types[next_consensus_type].clone()),
                ));

                next_height_consensus_change += rng.gen_range(1..50);
            }

            let net_upgrades =
                NetUpgrades::initialize(randomized_net_upgrades).expect("Net upgrades are valid");

            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis_block)
                .net_upgrades(net_upgrades)
                .build()
        };

        let (manager, chain_config, chainstate, mempool) =
            setup_blockprod_test(Some(net_upgrades_chain_config));

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config.clone(),
                    chainstate.clone(),
                    mempool,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let mut kernel_input = TxInput::from_utxo(
                    OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                    0,
                );

                for block_height in 1..=blocks_to_generate {
                    let input_data_pos =
                        GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                            genesis_stake_private_key.clone(),
                            genesis_vrf_private_key.clone(),
                            PoolId::new(H256::zero()),
                            vec![kernel_input.clone()],
                            vec![kernel_input_utxo.clone()],
                        )));

                    let input_data_pow = GenerateBlockInputData::PoW(Box::new(
                        PoWGenerateBlockInputData::new(Destination::AnyoneCanSpend),
                    ));

                    match chain_config
                        .net_upgrade()
                        .consensus_status(BlockHeight::new(block_height))
                    {
                        RequiredConsensus::IgnoreConsensus => {
                            let (new_block, job_finished_receiver) = block_production
                                .produce_block(
                                    GenerateBlockInputData::None,
                                    TransactionsSource::Provided(vec![]),
                                )
                                .await
                                .expect("Failed to produce a block: {:?}");

                            job_finished_receiver.await.expect("Job finished receiver closed");

                            assert_job_count(&block_production, 0).await;
                            assert_process_block(&chainstate, new_block.clone()).await;
                        }
                        RequiredConsensus::PoS(_) => {
                            // Try no input data for PoS consensus

                            let input_data_none_result = block_production
                                .produce_block(
                                    GenerateBlockInputData::None,
                                    TransactionsSource::Provided(vec![]),
                                )
                                .await;

                            match input_data_none_result {
                                Err(BlockProductionError::FailedConsensusInitialization(
                                    ConsensusCreationError::StakingError(
                                        ConsensusPoSError::NoInputDataProvided,
                                    ),
                                )) => {}
                                _ => panic!("Unexpected return value"),
                            }

                            // TODO: until duplicate job keys is fixed
                            // in produce_block(), manually wait until
                            // the job manager has cleaned up
                            assert_job_count(&block_production, 0).await;

                            // Try PoW input data for PoS consensus

                            let input_data_pow_result = block_production
                                .produce_block(input_data_pow, TransactionsSource::Provided(vec![]))
                                .await;

                            match input_data_pow_result {
                                Err(BlockProductionError::FailedConsensusInitialization(
                                    ConsensusCreationError::StakingError(
                                        ConsensusPoSError::PoWInputDataProvided,
                                    ),
                                )) => {}
                                _ => panic!("Unexpected return value"),
                            }

                            // TODO: until duplicate job keys is fixed
                            // in produce_block(), manually wait until
                            // the job manager has cleaned up
                            assert_job_count(&block_production, 0).await;

                            // Try PoS input data for PoS consensus

                            let (new_block, job_finished_receiver) = block_production
                                .produce_block(input_data_pos, TransactionsSource::Provided(vec![]))
                                .await
                                .expect("Failed to produce a job: {:?}");

                            job_finished_receiver.await.expect("Job finished receiver closed");

                            assert_job_count(&block_production, 0).await;
                            let result = assert_process_block(&chainstate, new_block).await;

                            // Update kernel input parameters for future PoS blocks

                            kernel_input = TxInput::from_utxo(
                                OutPointSourceId::BlockReward(
                                    result.into_gen_block_index().block_id(),
                                ),
                                0,
                            );

                            kernel_input_utxo = TxOutput::ProduceBlockFromStake(
                                Destination::PublicKey(genesis_stake_public_key.clone()),
                                H256::zero().into(),
                            );
                        }
                        RequiredConsensus::PoW(_) => {
                            // Try no input data for PoW consensus

                            let input_data_none_result = block_production
                                .produce_block(
                                    GenerateBlockInputData::None,
                                    TransactionsSource::Provided(vec![]),
                                )
                                .await;

                            match input_data_none_result {
                                Err(BlockProductionError::FailedConsensusInitialization(
                                    ConsensusCreationError::MiningError(
                                        ConsensusPoWError::NoInputDataProvided,
                                    ),
                                )) => {}
                                _ => panic!("Unexpected return value"),
                            }

                            // TODO: until duplicate job keys is fixed
                            // in produce_block(), manually wait until
                            // the job manager has cleaned up
                            assert_job_count(&block_production, 0).await;

                            // Try PoS input data for PoW consensus

                            let input_data_pos_result = block_production
                                .produce_block(input_data_pos, TransactionsSource::Provided(vec![]))
                                .await;

                            match input_data_pos_result {
                                Err(BlockProductionError::FailedConsensusInitialization(
                                    ConsensusCreationError::MiningError(
                                        ConsensusPoWError::PoSInputDataProvided,
                                    ),
                                )) => {}
                                _ => panic!("Unexpected return value"),
                            }

                            // TODO: until duplicate job keys is fixed
                            // in produce_block(), manually wait until
                            // the job manager has cleaned up
                            assert_job_count(&block_production, 0).await;

                            // Try PoW input data for PoW consensus

                            let (new_block, job_finished_receiver) = block_production
                                .produce_block(input_data_pow, TransactionsSource::Provided(vec![]))
                                .await
                                .expect("Failed to produce a block: {:?}");

                            job_finished_receiver.await.expect("Job finished receiver closed");

                            assert_job_count(&block_production, 0).await;
                            assert_process_block(&chainstate, new_block).await;
                        }
                    }
                }
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
                    assert_job_count(&block_production, 0).await;
                }
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

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
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

async fn assert_job_count(block_production: &BlockProduction, expected_jobs_count: usize) {
    // try for a sufficient amount of time before giving up with an error
    for _ in 1..100 {
        let jobs_count = block_production.job_manager_handle.get_job_count().await.unwrap();

        if jobs_count == expected_jobs_count {
            return;
        }

        sleep(tokio::time::Duration::from_millis(50)).await;
    }

    panic!("Job count was unexpected");
}
