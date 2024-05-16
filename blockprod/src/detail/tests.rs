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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use rstest::rstest;
use static_assertions::const_assert;
use tokio::{
    sync::{mpsc::unbounded_channel, oneshot},
    time::sleep,
};

use chainstate::{ChainstateError, ChainstateHandle, GenBlockIndex, PropertyQueryError};
use chainstate_test_framework::TransactionBuilder;
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{create_testnet, create_unit_test_config, Builder, ChainType},
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        transaction::TxInput,
        CoinUnit, ConsensusUpgrade, Destination, Genesis, NetUpgrades, OutPointSourceId, PoolId,
        RequiredConsensus, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, Id, Idable, H256},
    time_getter::TimeGetter,
    Uint256,
};
use consensus::{
    ConsensusCreationError, ConsensusPoSError, ConsensusPoWError, PoSGenerateBlockInputData,
    PoWGenerateBlockInputData,
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use mempool::{
    error::{BlockConstructionError, TxValidationError},
    tx_accumulator::{DefaultTxAccumulator, PackingStrategy},
    tx_origin::LocalTxOrigin,
    TxOptions,
};
use mocks::{MockChainstateInterface, MockMempoolInterface};
use randomness::Rng;
use subsystem::error::ResponseError;
use test_utils::{
    mock_time_getter::mocked_time_getter_seconds,
    random::{make_seedable_rng, Seed},
};
use utils::once_destructor::OnceDestructor;

use crate::{
    detail::{
        collect_transactions,
        job_manager::{tests::MockJobManager, JobManagerError, JobManagerImpl},
        CustomId, GenerateBlockInputData,
    },
    prepare_thread_pool, test_blockprod_config,
    tests::{
        assert_process_block, build_chain_config_for_pos, make_genesis_timestamp,
        setup_blockprod_test, setup_pos, setup_pos_with_genesis_timestamp,
    },
    BlockProduction, BlockProductionError, JobKey,
};

mod collect_transactions {
    use super::*;

    // A dummy timestamp for tests where the block timestamp is irrelevant
    const DUMMY_TIMESTAMP: BlockTimestamp = BlockTimestamp::from_int_seconds(0u64);

    // TODO: add tests for mempool rejecting transaction accumulator

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn collect_txs_failed() {
        let (mut manager, chain_config, _chainstate, _mempool, _p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut mock_mempool = MockMempoolInterface::default();
        mock_mempool.expect_collect_txs().return_once(|_, _, _| {
            Err(BlockConstructionError::Validity(
                TxValidationError::CallError(ResponseError::NoResponse.into()),
            ))
        });

        let mock_mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

        let current_tip = Id::new(H256::zero());

        let shutdown = manager.make_shutdown_trigger();
        let tester = tokio::spawn(async move {
            let accumulator = collect_transactions(
                &mock_mempool_subsystem,
                &chain_config,
                current_tip,
                DUMMY_TIMESTAMP,
                vec![],
                vec![],
                PackingStrategy::FillSpaceFromMempool,
            )
            .await;

            match accumulator {
                Err(BlockProductionError::MempoolBlockConstruction(
                    BlockConstructionError::Validity(TxValidationError::CallError(_)),
                )) => {}
                _ => panic!("Expected collect_tx() to fail"),
            };

            shutdown.initiate();
        });

        let _ = tokio::join!(manager.main(), tester);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn subsystem_error() {
        let (mut manager, chain_config, _chainstate, _mempool, _p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mock_mempool = MockMempoolInterface::default();
        let mock_mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

        mock_mempool_subsystem
            .as_submit_only()
            .submit({
                let shutdown = manager.make_shutdown_trigger();
                move |_| shutdown.initiate()
            })
            .unwrap();

        // shutdown straight after startup, *then* call collect_transactions()
        manager.main().await;

        let current_tip = Id::new(H256::zero());

        // spawn rather than adding a subsystem as manager is moved into main() above
        tokio::spawn(async move {
            let accumulator = collect_transactions(
                &mock_mempool_subsystem,
                &chain_config,
                current_tip,
                DUMMY_TIMESTAMP,
                vec![],
                vec![],
                PackingStrategy::LeaveEmptySpace,
            )
            .await;

            match accumulator {
                Ok(_) => panic!("Expected an error"),
                Err(BlockProductionError::SubsystemCallError(_)) => {}
                Err(err) => panic!("Expected a subsystem error, got {err:?}"),
            };
        })
        .await
        .expect("Subsystem error thread failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn succeeded() {
        let (mut manager, chain_config, _chainstate, _mempool, _p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut mock_mempool = MockMempoolInterface::default();

        mock_mempool
            .expect_collect_txs()
            .returning(|_, _, _| {
                Ok(Some(Box::new(DefaultTxAccumulator::new(
                    usize::default(),
                    Id::new(H256::zero()),
                    DUMMY_TIMESTAMP,
                ))))
            })
            .times(1);

        let mock_mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

        let current_tip = Id::new(H256::zero());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let accumulator = collect_transactions(
                    &mock_mempool_subsystem,
                    &chain_config,
                    current_tip,
                    DUMMY_TIMESTAMP,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await;

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
    use common::chain::{ChainConfig, PoSChainConfigBuilder};
    use test_utils::assert_matches;
    use utils::atomics::SeqCstAtomicU64;

    use super::*;
    use chainstate::chainstate_interface::ChainstateInterface;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_block_download() {
        let (mut manager, chain_config, _, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = MockChainstateInterface::new();
            mock_chainstate.expect_is_initial_block_download().returning(|| true);

            mock_chainstate
                .expect_subscribe_to_subsystem_events()
                .times(..=1)
                .returning(|_| ());

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
                    Arc::new(test_blockprod_config()),
                    chainstate_subsystem,
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await;

                match result {
                    Err(BlockProductionError::ChainstateWaitForSync) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn below_peer_count() {
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let mut blockprod_config = test_blockprod_config();
                blockprod_config.min_peers_to_produce_blocks = 100;

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(blockprod_config),
                    chainstate,
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await;

                match result {
                    Err(BlockProductionError::PeerCountBelowRequiredThreshold(0, 100)) => {}
                    _ => panic!("Unexpected return value"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_best_block_index_error() {
        let (mut manager, chain_config, _, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = Box::new(MockChainstateInterface::new());
            mock_chainstate
                .expect_subscribe_to_subsystem_events()
                .times(..=1)
                .returning(|_| ());
            mock_chainstate.expect_is_initial_block_download().returning(|| false);

            mock_chainstate.expect_get_best_block_index().times(1).returning(|| {
                Err(ChainstateError::FailedToReadProperty(
                    PropertyQueryError::BestBlockIndexNotFound,
                ))
            });

            let mock_chainstate: Box<dyn ChainstateInterface> = Box::new(mock_chainstate);
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
                    Arc::new(test_blockprod_config()),
                    chainstate_subsystem,
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await;

                match result {
                    Err(BlockProductionError::ChainstateError(
                        consensus::ChainstateError::FailedToObtainBestBlockIndex(_),
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
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

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

                let mut mock_job_manager = Box::new(MockJobManager::new());

                mock_job_manager
                    .expect_add_job()
                    .times(1)
                    .returning(|_, _| Err(JobManagerError::FailedToSendNewJobEvent));

                block_production.set_job_manager(mock_job_manager);

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
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
        let (manager, chain_config, chainstate, mempool, p2p) = {
            let genesis_block = Genesis::new(
                "blockprod-testing".into(),
                BlockTimestamp::from_int_seconds(u64::MAX),
                vec![],
            );

            let override_chain_config =
                Builder::new(ChainType::Regtest).genesis_custom(genesis_block).build();

            setup_blockprod_test(Some(override_chain_config), TimeGetter::default())
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
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await;

                assert_matches!(result, Err(BlockProductionError::TimestampOverflow(_, 1)));

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overflow_max_blocktimestamp(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let time_getter = TimeGetter::default();
        let (
            chain_config_builder,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = setup_pos(&time_getter, BlockHeight::new(1), &[], &mut rng);
        let chain_config = build_chain_config_for_pos(
            chain_config_builder.max_future_block_time_offset(Duration::MAX),
        );

        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(Some(chain_config), TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    Arc::clone(&chain_config),
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let input_data =
                    GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                        genesis_stake_private_key,
                        genesis_vrf_private_key,
                        PoolId::new(H256::zero()),
                        vec![TxInput::from_utxo(
                            OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                            0,
                        )],
                        vec![create_genesis_pool_txoutput],
                    )));

                let result = block_production
                    .produce_block(input_data, vec![], vec![], PackingStrategy::LeaveEmptySpace)
                    .await;

                assert_matches!(result, Err(BlockProductionError::TimestampOverflow(_, _)));

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn update_last_used_block_timestamp(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let time_getter = TimeGetter::default();
        let (
            chain_config_builder,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = setup_pos(&time_getter, BlockHeight::new(1), &[], &mut rng);

        let (manager, chain_config, chainstate, mempool, p2p) = setup_blockprod_test(
            Some(build_chain_config_for_pos(chain_config_builder)),
            time_getter,
        );

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config.clone(),
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let input_data =
                    GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                        genesis_stake_private_key,
                        genesis_vrf_private_key,
                        PoolId::new(H256::zero()),
                        vec![TxInput::from_utxo(
                            OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                            0,
                        )],
                        vec![create_genesis_pool_txoutput],
                    )));

                let _ = block_production
                    .job_manager_handle
                    .update_last_used_block_timestamp(
                        CustomId::new_from_input_data(&input_data),
                        BlockTimestamp::from_int_seconds(u64::MAX),
                    )
                    .await;

                let result = block_production
                    .produce_block(input_data, vec![], vec![], PackingStrategy::LeaveEmptySpace)
                    .await;

                assert_matches!(result, Err(BlockProductionError::TimestampOverflow(_, _)));

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_again_later(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let default_time_getter = TimeGetter::default();
        let genesis_time = default_time_getter.get_time();

        let (
            chain_config_builder,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = setup_pos_with_genesis_timestamp(
            BlockTimestamp::from_time(genesis_time),
            BlockHeight::new(1),
            &[],
            &mut rng,
        );

        let chain_config = build_chain_config_for_pos(chain_config_builder);
        let time_getter = {
            let cur_time_secs = genesis_time
                .saturating_duration_sub(*chain_config.max_future_block_time_offset())
                .as_secs_since_epoch();
            let time_value = Arc::new(SeqCstAtomicU64::new(cur_time_secs));
            mocked_time_getter_seconds(time_value)
        };

        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(Some(chain_config), time_getter.clone());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    Arc::clone(&chain_config),
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool,
                    p2p,
                    time_getter,
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let input_data =
                    GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                        genesis_stake_private_key,
                        genesis_vrf_private_key,
                        PoolId::new(H256::zero()),
                        vec![TxInput::from_utxo(
                            OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                            0,
                        )],
                        vec![create_genesis_pool_txoutput],
                    )));

                let result = block_production
                    .produce_block(input_data, vec![], vec![], PackingStrategy::LeaveEmptySpace)
                    .await;

                assert_matches!(result, Err(BlockProductionError::TryAgainLater));

                assert_job_count(&block_production, 0).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pull_consensus_data_error() {
        let (mut manager, chain_config, _, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = MockChainstateInterface::new();
            mock_chainstate
                .expect_subscribe_to_subsystem_events()
                .times(..=1)
                .returning(|_| ());
            mock_chainstate.expect_is_initial_block_download().returning(|| false);

            let mut expected_return_values = vec![
                Ok(GenBlockIndex::genesis(&chain_config)),
                Err(ChainstateError::FailedToReadProperty(
                    PropertyQueryError::BestBlockIndexNotFound,
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
                    Arc::new(test_blockprod_config()),
                    chainstate_subsystem,
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await;

                match result {
                    Err(BlockProductionError::ChainstateError(
                        consensus::ChainstateError::FailedToObtainBestBlockIndex(_),
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
        let (mut manager, chain_config, _, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let chainstate_subsystem: ChainstateHandle = {
            let mut mock_chainstate = MockChainstateInterface::new();
            mock_chainstate
                .expect_subscribe_to_subsystem_events()
                .times(..=1)
                .returning(|_| ());
            mock_chainstate.expect_is_initial_block_download().returning(|| false);

            let mut expected_return_values = vec![
                Ok(GenBlockIndex::genesis(&chain_config)),
                Ok(GenBlockIndex::genesis(&create_testnet())),
            ];

            mock_chainstate
                .expect_get_best_block_index()
                .times(expected_return_values.len())
                .returning(move || expected_return_values.remove(0));

            // Doesn't matter for this test.
            mock_chainstate
                .expect_calculate_median_time_past()
                .returning(|_| Ok(BlockTimestamp::from_int_seconds(0)));

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
                    Arc::new(test_blockprod_config()),
                    chainstate_subsystem,
                    mempool,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
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
        let (mut manager, chain_config, chainstate, _mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut mock_mempool = MockMempoolInterface::default();

        mock_mempool.expect_collect_txs().return_once(|_, _, _| {
            Err(BlockConstructionError::Validity(
                TxValidationError::CallError(ResponseError::NoResponse.into()),
            ))
        });

        let mempool_subsystem = manager.add_subsystem("mock-mempool", mock_mempool);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool_subsystem,
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await;

                match result {
                    Err(BlockProductionError::MempoolBlockConstruction(
                        BlockConstructionError::Validity(TxValidationError::CallError(_)),
                    )) => {}
                    _ => panic!("Unexpected return value: {result:?}"),
                }
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_mempool() {
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    // TODO: Add transactions to the mempool
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, &mempool, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_source_provided() {
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    // TODO: Add transactions to the parameters
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, &mempool, new_block).await;
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
        let override_chain_config = {
            let net_upgrades = NetUpgrades::initialize(vec![(
                BlockHeight::new(0),
                ConsensusUpgrade::PoW {
                    // Make difficulty impossible so the cancel from
                    // the mock job manager is always seen before
                    // solving the block
                    initial_difficulty: Uint256::ZERO.into(),
                },
            )])
            .expect("Net upgrade is valid");

            Builder::new(ChainType::Regtest).consensus_upgrades(net_upgrades).build()
        };

        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(Some(override_chain_config), TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

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

                let mut mock_job_manager = Box::<MockJobManager>::default();

                mock_job_manager.expect_add_job().times(1).returning(move |_, _| {
                    let (_, cancel_receiver) = unbounded_channel::<()>();
                    let mut rng = make_seedable_rng(seed);
                    let job_key = JobKey::new(CustomId::new_from_rng(&mut rng));
                    Ok((job_key, None, cancel_receiver))
                });

                mock_job_manager.expect_make_job_stopper_function().times(1).returning(|| {
                    let (_, result_receiver) = oneshot::channel::<usize>();
                    (Box::new(|_| {}), result_receiver)
                });

                mock_job_manager
                    .expect_update_last_used_block_timestamp()
                    .times(..=1)
                    .returning(|_, _| Ok(()));

                block_production.set_job_manager(mock_job_manager);

                let result = block_production
                    .produce_block(
                        GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
                            Destination::AnyoneCanSpend,
                        ))),
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
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
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        GenerateBlockInputData::None,
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, &mempool, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_pow_consensus() {
        let override_chain_config = {
            let net_upgrades = NetUpgrades::initialize(vec![(
                BlockHeight::new(0),
                ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::MAX.into(),
                },
            )])
            .expect("Net upgrade is valid");

            Builder::new(ChainType::Regtest).consensus_upgrades(net_upgrades).build()
        };

        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(Some(override_chain_config), TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
                            Destination::AnyoneCanSpend,
                        ))),
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, &mempool, new_block).await;
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
        let mut rng = make_seedable_rng(seed);
        let time_getter = TimeGetter::default();
        let (
            chain_config_builder,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = setup_pos(&time_getter, BlockHeight::new(1), &[], &mut rng);

        let (manager, chain_config, chainstate, mempool, p2p) = setup_blockprod_test(
            Some(build_chain_config_for_pos(chain_config_builder)),
            time_getter,
        );

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config.clone(),
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
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
                        vec![],
                        vec![],
                        PackingStrategy::LeaveEmptySpace,
                    )
                    .await
                    .expect("Failed to produce a block: {:?}");

                job_finished_receiver.await.expect("Job finished receiver closed");

                assert_job_count(&block_production, 0).await;
                assert_process_block(&chainstate, &mempool, new_block).await;
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    // The height at which the transaction_selection_xxx tests will create their test block.
    // Any value will do as long as it's bigger than the span used to calculate the median past time.
    const TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT: usize = 15;
    const_assert!(TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT > chainstate::MEDIAN_TIME_SPAN);

    // Common implementation for the transaction_selection_xxx tests below.
    // The passed chain config is assumed to switch to the consensus type required by the test
    // at the height TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT.
    // `genesis_premint_output_index` specifies the genesis tx that mints some coins that can
    // be spent by the test.
    // Steps:
    // 1) Create trivial blocks up to the height (TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT - 1).
    // Calculate the "median time past" using the current tip.
    // 2) Create the "main" tx that spends the genesis output by splitting it into multiple
    // utxos with different time locks. One of the locks is at the "median time past", the rest are
    // below and above that point.
    // Then create a bunch of "dependent" txs, each of which spends one of the utxos.
    // Add all the txs to the mempool.
    // 3) Produce a block using the provided input data.
    // Expected result:
    // a) The block is valid.
    // b) The block contains the main tx and all dependent txs up to and including the one at
    // the "median time past" time.
    async fn transaction_selection_test_impl(
        chain_config: ChainConfig,
        input_data: GenerateBlockInputData,
        time_getter: TimeGetter,
        genesis_premint_output_index: u32,
    ) {
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(Some(chain_config), time_getter.clone());

        let genesis_timestamp = chain_config.genesis_block().timestamp();
        let expected_median_time_past = genesis_timestamp.add_int_seconds(9).unwrap();

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config.clone(),
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .unwrap();

                for i in 1..TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT {
                    let (new_block, job_finished_receiver) = block_production
                        .produce_block(
                            GenerateBlockInputData::None,
                            vec![],
                            vec![],
                            PackingStrategy::LeaveEmptySpace,
                        )
                        .await
                        .unwrap();

                    job_finished_receiver.await.unwrap();

                    let expected_timestamp = genesis_timestamp.add_int_seconds(i as u64).unwrap();
                    assert_eq!(new_block.timestamp(), expected_timestamp);

                    assert_job_count(&block_production, 0).await;
                    assert_process_block(&chainstate, &mempool, new_block).await;
                }

                let median_time_past = chainstate
                    .call(|cs| cs.calculate_median_time_past(&cs.get_best_block_id().unwrap()))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(median_time_past, expected_median_time_past);

                let timestamp_offsets_count = 10i64;
                let tx_count = timestamp_offsets_count * 2 + 1;
                let main_tx = {
                    let mut builder = TransactionBuilder::new().add_input(
                        TxInput::from_utxo(
                            OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                            genesis_premint_output_index,
                        ),
                        InputWitness::NoSignature(None),
                    );

                    for timestamp_offset_secs in -timestamp_offsets_count..=timestamp_offsets_count
                    {
                        let lock_until_secs =
                            (median_time_past.as_int_seconds() as i64) + timestamp_offset_secs;
                        assert!(lock_until_secs > 0);
                        let lock_until = BlockTimestamp::from_int_seconds(lock_until_secs as u64);

                        let output = TxOutput::LockThenTransfer(
                            OutputValue::Coin(Amount::from_atoms(2 * CoinUnit::ATOMS_PER_COIN)),
                            Destination::AnyoneCanSpend,
                            OutputTimeLock::UntilTime(lock_until),
                        );
                        builder = builder.add_output(output);
                    }

                    builder.build()
                };
                let main_tx_id = main_tx.transaction().get_id();

                let dependent_txs = {
                    let mut txs = Vec::new();

                    for i in 0..tx_count {
                        let tx = TransactionBuilder::new()
                            .add_input(
                                TxInput::from_utxo(
                                    OutPointSourceId::Transaction(main_tx_id),
                                    i as u32,
                                ),
                                InputWitness::NoSignature(None),
                            )
                            .add_output(TxOutput::Transfer(
                                OutputValue::Coin(Amount::from_atoms(CoinUnit::ATOMS_PER_COIN)),
                                Destination::AnyoneCanSpend,
                            ))
                            .build();
                        txs.push(tx);
                    }

                    txs
                };

                mempool
                    .call_mut({
                        let dependent_txs = dependent_txs.clone();
                        |mp| {
                            let origin = LocalTxOrigin::Mempool;
                            let options = TxOptions::default_for(origin.into());

                            for tx in std::iter::once(main_tx).chain(dependent_txs.into_iter()) {
                                mp.add_transaction_local(tx, origin, options.clone()).unwrap();
                            }
                        }
                    })
                    .await
                    .unwrap();

                let (new_block, job_finished_receiver) = block_production
                    .produce_block(
                        input_data,
                        vec![],
                        vec![],
                        PackingStrategy::FillSpaceFromMempool,
                    )
                    .await
                    .unwrap();

                // We want the block to be slightly in the past, to ensure that blockprod doesn't
                // rely on the current time when collecting transactions.
                assert!(new_block.timestamp().into_time() < time_getter.get_time());

                let block_tx_ids = new_block
                    .transactions()
                    .iter()
                    .map(|tx| tx.transaction().get_id())
                    .collect::<BTreeSet<_>>();

                job_finished_receiver.await.unwrap();

                assert_job_count(&block_production, 0).await;
                // First ensure that the produced block is actually correct.
                assert_process_block(&chainstate, &mempool, new_block).await;

                // Now check the transaction ids.
                let expected_tx_ids = dependent_txs[..=timestamp_offsets_count as usize]
                    .iter()
                    .map(|tx| tx.transaction().get_id())
                    .chain(std::iter::once(main_tx_id))
                    .collect::<BTreeSet<_>>();
                assert_eq!(block_tx_ids, expected_tx_ids);
            }
        });

        manager.main().await;
        join_handle.await.unwrap();
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_selection_test_pos(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let initial_time_value_secs = TimeGetter::default().get_time().as_secs_since_epoch();
        let initial_time_value = Arc::new(SeqCstAtomicU64::new(initial_time_value_secs));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&initial_time_value));

        let extra_genesis_txs = [TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000 * CoinUnit::ATOMS_PER_COIN)),
            Destination::AnyoneCanSpend,
        )];

        let (
            chain_config_builder,
            genesis_stake_private_key,
            genesis_vrf_private_key,
            create_genesis_pool_txoutput,
        ) = setup_pos(
            &time_getter,
            BlockHeight::new(TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT as u64),
            &extra_genesis_txs,
            &mut rng,
        );
        let chain_config = build_chain_config_for_pos(chain_config_builder);

        let input_data = GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
            genesis_stake_private_key,
            genesis_vrf_private_key,
            PoolId::new(H256::zero()),
            vec![TxInput::from_utxo(
                OutPointSourceId::BlockReward(chain_config.genesis_block_id()),
                0,
            )],
            vec![create_genesis_pool_txoutput],
        )));

        transaction_selection_test_impl(chain_config, input_data, time_getter, 1).await;
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_selection_test_pow(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let initial_time_value_secs = TimeGetter::default().get_time().as_secs_since_epoch();
        let initial_time_value = Arc::new(SeqCstAtomicU64::new(initial_time_value_secs));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&initial_time_value));

        let extra_genesis_txs = vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000 * CoinUnit::ATOMS_PER_COIN)),
            Destination::AnyoneCanSpend,
        )];

        let genesis_timestamp = make_genesis_timestamp(&time_getter, &mut rng);
        let genesis = Genesis::new(
            "blockprod-testing".into(),
            genesis_timestamp,
            extra_genesis_txs,
        );

        let chain_config = {
            let net_upgrades = NetUpgrades::initialize(vec![
                (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
                (
                    BlockHeight::new(TRANSACTION_SELECTION_TESTS_BLOCK_HEIGHT as u64),
                    ConsensusUpgrade::PoW {
                        initial_difficulty: Uint256::MAX.into(),
                    },
                ),
            ])
            .unwrap();

            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis)
                .consensus_upgrades(net_upgrades)
                .build()
        };

        let input_data = GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
            Destination::AnyoneCanSpend,
        )));

        transaction_selection_test_impl(chain_config, input_data, time_getter, 0).await;
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transaction_selection_test_ignore_consensus(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let initial_time_value_secs = TimeGetter::default().get_time().as_secs_since_epoch();
        let initial_time_value = Arc::new(SeqCstAtomicU64::new(initial_time_value_secs));
        let time_getter = mocked_time_getter_seconds(Arc::clone(&initial_time_value));

        let extra_genesis_txs = vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1000 * CoinUnit::ATOMS_PER_COIN)),
            Destination::AnyoneCanSpend,
        )];

        let genesis_timestamp = make_genesis_timestamp(&time_getter, &mut rng);
        let genesis = Genesis::new(
            "blockprod-testing".into(),
            genesis_timestamp,
            extra_genesis_txs,
        );

        let chain_config = {
            let net_upgrades = NetUpgrades::initialize(vec![(
                BlockHeight::new(0),
                ConsensusUpgrade::IgnoreConsensus,
            )])
            .unwrap();

            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis)
                .consensus_upgrades(net_upgrades)
                .build()
        };

        transaction_selection_test_impl(chain_config, GenerateBlockInputData::None, time_getter, 0)
            .await;
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solve_lots_of_blocks_with_differing_consensus(#[case] seed: Seed) {
        use crate::tests::make_genesis_timestamp;

        let mut rng = make_seedable_rng(seed);

        let time_getter = TimeGetter::default();

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

        let override_chain_config = {
            let genesis_block = Genesis::new(
                "blockprod-testing".into(),
                make_genesis_timestamp(&time_getter, &mut rng),
                vec![kernel_input_utxo.clone()],
            );

            let easy_pos_config = PoSChainConfigBuilder::new_for_unit_test().build();

            let consensus_types = [
                ConsensusUpgrade::IgnoreConsensus,
                ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::MAX.into(),
                },
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(Uint256::MAX.into()),
                    config: easy_pos_config,
                },
            ];

            let mut randomized_net_upgrades =
                vec![(BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus)];

            let mut next_height_consensus_change = 1;

            while next_height_consensus_change < blocks_to_generate {
                let next_consensus_type = rng.gen_range(0..consensus_types.len());

                randomized_net_upgrades.push((
                    BlockHeight::new(next_height_consensus_change),
                    consensus_types[next_consensus_type].clone(),
                ));

                next_height_consensus_change += rng.gen_range(1..50);
            }

            let net_upgrades =
                NetUpgrades::initialize(randomized_net_upgrades).expect("Net upgrades are valid");

            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis_block)
                .consensus_upgrades(net_upgrades)
                .build()
        };

        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(Some(override_chain_config), time_getter);

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let mut block_production = BlockProduction::new(
                    chain_config.clone(),
                    Arc::new(test_blockprod_config()),
                    chainstate.clone(),
                    mempool.clone(),
                    p2p,
                    Default::default(),
                    prepare_thread_pool(1),
                )
                .expect("Error initializing blockprod");

                let no_chainstate_job_manager = Box::new(JobManagerImpl::new(None));
                block_production.set_job_manager(no_chainstate_job_manager);

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
                        .consensus_upgrades()
                        .consensus_status(BlockHeight::new(block_height))
                    {
                        RequiredConsensus::IgnoreConsensus => {
                            let (new_block, job_finished_receiver) = block_production
                                .produce_block(
                                    GenerateBlockInputData::None,
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
                                )
                                .await
                                .expect("Failed to produce a block: {:?}");

                            job_finished_receiver.await.expect("Job finished receiver closed");

                            assert_process_block(&chainstate, &mempool, new_block.clone()).await;
                        }
                        RequiredConsensus::PoS(_) => {
                            // Try no input data for PoS consensus

                            let input_data_none_result = block_production
                                .produce_block(
                                    GenerateBlockInputData::None,
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
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

                            // Try PoW input data for PoS consensus

                            let input_data_pow_result = block_production
                                .produce_block(
                                    input_data_pow,
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
                                )
                                .await;

                            match input_data_pow_result {
                                Err(BlockProductionError::FailedConsensusInitialization(
                                    ConsensusCreationError::StakingError(
                                        ConsensusPoSError::PoWInputDataProvided,
                                    ),
                                )) => {}
                                _ => panic!("Unexpected return value"),
                            }

                            // Try PoS input data for PoS consensus

                            let (new_block, job_finished_receiver) = block_production
                                .produce_block(
                                    input_data_pos,
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
                                )
                                .await
                                .expect("Failed to produce a job: {:?}");

                            job_finished_receiver.await.expect("Job finished receiver closed");

                            let result =
                                assert_process_block(&chainstate, &mempool, new_block).await;

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
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
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

                            // Try PoS input data for PoW consensus

                            let input_data_pos_result = block_production
                                .produce_block(
                                    input_data_pos,
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
                                )
                                .await;

                            match input_data_pos_result {
                                Err(BlockProductionError::FailedConsensusInitialization(
                                    ConsensusCreationError::MiningError(
                                        ConsensusPoWError::PoSInputDataProvided,
                                    ),
                                )) => {}
                                _ => panic!("Unexpected return value"),
                            }

                            // Try PoW input data for PoW consensus

                            let (new_block, job_finished_receiver) = block_production
                                .produce_block(
                                    input_data_pow,
                                    vec![],
                                    vec![],
                                    PackingStrategy::LeaveEmptySpace,
                                )
                                .await
                                .expect("Failed to produce a block: {:?}");

                            job_finished_receiver.await.expect("Job finished receiver closed");

                            assert_process_block(&chainstate, &mempool, new_block.clone()).await;
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
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let join_handle = tokio::spawn({
            let shutdown_trigger = manager.make_shutdown_trigger();
            async move {
                // Ensure a shutdown signal will be sent by the end of the scope
                let _shutdown_signal = OnceDestructor::new(move || {
                    shutdown_trigger.initiate();
                });

                let block_production = BlockProduction::new(
                    chain_config,
                    Arc::new(test_blockprod_config()),
                    chainstate,
                    mempool,
                    p2p,
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
                            vec![],
                            vec![],
                            PackingStrategy::LeaveEmptySpace,
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
}

mod process_block_with_custom_id {
    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_jobs_with_wait(#[case] seed: Seed) {
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut rng = make_seedable_rng(seed);

        let jobs_to_create = rng.gen::<usize>() % 20 + 1;

        let block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate,
            mempool,
            p2p,
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
        let (manager, chain_config, chainstate, mempool, p2p) =
            setup_blockprod_test(None, TimeGetter::default());

        let mut rng = make_seedable_rng(seed);

        let jobs_to_create = 10 + rng.gen::<usize>() % 20 + 1;

        let block_production = BlockProduction::new(
            chain_config,
            Arc::new(test_blockprod_config()),
            chainstate,
            mempool,
            p2p,
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
}

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
        let jobs_to_create = rng.gen::<usize>() % 20 + 1;

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
