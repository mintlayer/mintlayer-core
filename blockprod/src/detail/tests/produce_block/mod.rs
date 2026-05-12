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

mod tx_selection_mtp;

use std::{sync::Arc, time::Duration};

use rstest::rstest;
use tokio::{
    sync::{mpsc::unbounded_channel, oneshot},
    time::sleep,
};

use chainstate::{
    ChainstateError, GenBlockIndex, PropertyQueryError, chainstate_interface::ChainstateInterface,
};
use common::{
    Uint256,
    chain::{
        ConsensusUpgrade, Destination, Genesis, NetUpgrades, OutPointSourceId,
        PoSChainConfigBuilder, PoolId, RequiredConsensus, TxOutput,
        block::timestamp::BlockTimestamp,
        config::{Builder, ChainType, create_unit_test_config},
        stakelock::StakePoolData,
        transaction::TxInput,
    },
    primitives::{Amount, BlockHeight, H256, per_thousand::PerThousand},
    time_getter::TimeGetter,
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
    tx_accumulator::PackingStrategy,
};
use mocks::{MockChainstateInterface, MockMempoolInterface};
use randomness::RngExt as _;
use subsystem::error::ResponseError;
use test_utils::{
    assert_matches,
    mock_time_getter::mocked_time_getter_seconds,
    random::{Seed, make_seedable_rng},
};
use utils::{atomics::SeqCstAtomicU64, once_destructor::OnceDestructor};

use crate::{
    BlockProduction, BlockProductionError, JobKey,
    detail::{
        CustomId, GenerateBlockInputData,
        job_manager::{JobManagerError, JobManagerImpl, tests::MockJobManager},
    },
    test_blockprod_config,
    tests::helpers::{
        BlockprodTestSetupBuilder, make_chain_config_builder, make_genesis_timestamp, setup_pos,
        setup_pos_with_genesis_timestamp,
    },
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_block_download() {
    let (blockprod_setup, mut manager) = BlockprodTestSetupBuilder::new().build();

    let mock_chainstate = {
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

            let block_production = blockprod_setup
                .make_blockprod_builder()
                .with_chainstate(mock_chainstate)
                .build();

            let err = block_production
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await
                .unwrap_err();

            assert_eq!(err, BlockProductionError::ChainstateWaitForSync);
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn below_peer_count() {
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let mut blockprod_config = test_blockprod_config();
            blockprod_config.min_peers_to_produce_blocks = 100;

            let block_production = blockprod_setup
                .make_blockprod_builder()
                .with_blockprod_config(blockprod_config)
                .build();

            let err = block_production
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await
                .unwrap_err();

            assert_eq!(
                err,
                BlockProductionError::PeerCountBelowRequiredThreshold(0, 100)
            );
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_best_block_index_error() {
    let (blockprod_setup, mut manager) = BlockprodTestSetupBuilder::new().build();

    let mock_chainstate = {
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

            let block_production = blockprod_setup
                .make_blockprod_builder()
                .with_chainstate(mock_chainstate)
                .build();

            let result = block_production
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await;

            assert_matches!(
                result,
                Err(BlockProductionError::ChainstateError(
                    consensus::ChainstateError::FailedToObtainBestBlockIndex(_),
                ))
            );
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_job_error() {
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let mut block_production = blockprod_setup.make_blockprod_builder().build();

            let mut mock_job_manager = Box::new(MockJobManager::new());

            mock_job_manager
                .expect_add_job()
                .times(1)
                .returning(|_, _| Err(JobManagerError::FailedToSendNewJobEvent));

            block_production.set_job_manager(mock_job_manager);

            let err = block_production
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await
                .unwrap_err();

            assert_eq!(
                err,
                BlockProductionError::JobManagerError(JobManagerError::FailedToSendNewJobEvent,)
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
async fn overflow_tip_plus_one(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let pos_setup = setup_pos_with_genesis_timestamp(
        BlockTimestamp::from_int_seconds(u64::MAX),
        BlockHeight::new(1),
        &[],
        None,
        &mut rng,
    );

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&pos_setup.chain_config))
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope

            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let input_data = GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                pos_setup.genesis_stake_private_key,
                pos_setup.genesis_vrf_private_key,
                PoolId::new(H256::zero()),
                vec![TxInput::from_utxo(
                    OutPointSourceId::BlockReward(pos_setup.chain_config.genesis_block_id()),
                    0,
                )],
                vec![pos_setup.create_genesis_pool_utxo],
            )));

            let result = block_production
                .produce_block(input_data, vec![], vec![], PackingStrategy::LeaveEmptySpace)
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
    let pos_setup = setup_pos(
        &time_getter,
        BlockHeight::new(1),
        &[],
        Some(make_chain_config_builder().max_future_block_time_offset(Some(Duration::MAX))),
        &mut rng,
    );

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&pos_setup.chain_config))
        .with_time_getter(time_getter)
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let input_data = GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                pos_setup.genesis_stake_private_key,
                pos_setup.genesis_vrf_private_key,
                PoolId::new(H256::zero()),
                vec![TxInput::from_utxo(
                    OutPointSourceId::BlockReward(pos_setup.chain_config.genesis_block_id()),
                    0,
                )],
                vec![pos_setup.create_genesis_pool_utxo],
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
    let pos_setup = setup_pos(&time_getter, BlockHeight::new(1), &[], None, &mut rng);

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&pos_setup.chain_config))
        .with_time_getter(time_getter)
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let input_data = GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                pos_setup.genesis_stake_private_key,
                pos_setup.genesis_vrf_private_key,
                PoolId::new(H256::zero()),
                vec![TxInput::from_utxo(
                    OutPointSourceId::BlockReward(pos_setup.chain_config.genesis_block_id()),
                    0,
                )],
                vec![pos_setup.create_genesis_pool_utxo],
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

    let pos_setup = setup_pos_with_genesis_timestamp(
        BlockTimestamp::from_time(genesis_time),
        BlockHeight::new(1),
        &[],
        None,
        &mut rng,
    );

    let time_getter = {
        let cur_time_secs = genesis_time
            .saturating_duration_sub(
                pos_setup.chain_config.max_future_block_time_offset(BlockHeight::zero()),
            )
            .as_secs_since_epoch();
        let time_value = Arc::new(SeqCstAtomicU64::new(cur_time_secs));
        mocked_time_getter_seconds(time_value)
    };

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&pos_setup.chain_config))
        .with_time_getter(time_getter)
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let input_data = GenerateBlockInputData::PoS(Box::new(PoSGenerateBlockInputData::new(
                pos_setup.genesis_stake_private_key,
                pos_setup.genesis_vrf_private_key,
                PoolId::new(H256::zero()),
                vec![TxInput::from_utxo(
                    OutPointSourceId::BlockReward(pos_setup.chain_config.genesis_block_id()),
                    0,
                )],
                vec![pos_setup.create_genesis_pool_utxo],
            )));

            let err = block_production
                .produce_block(input_data, vec![], vec![], PackingStrategy::LeaveEmptySpace)
                .await
                .unwrap_err();

            assert_eq!(err, BlockProductionError::TryAgainLater);

            assert_job_count(&block_production, 0).await;
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pull_consensus_data_error() {
    let (blockprod_setup, mut manager) = BlockprodTestSetupBuilder::new().build();

    let mock_chainstate = {
        let mut mock_chainstate = MockChainstateInterface::new();
        mock_chainstate
            .expect_subscribe_to_subsystem_events()
            .times(..=1)
            .returning(|_| ());
        mock_chainstate.expect_is_initial_block_download().returning(|| false);

        let mut expected_return_values = vec![
            Ok(GenBlockIndex::genesis(&blockprod_setup.chain_config)),
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

            let block_production = blockprod_setup
                .make_blockprod_builder()
                .with_chainstate(mock_chainstate)
                .build();

            let result = block_production
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await;

            assert_matches!(
                result,
                Err(BlockProductionError::ChainstateError(
                    consensus::ChainstateError::FailedToObtainBestBlockIndex(_),
                ))
            );
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_source_mempool_error() {
    let (blockprod_setup, mut manager) = BlockprodTestSetupBuilder::new().build();

    let mock_mempool = {
        let mut mock_mempool = MockMempoolInterface::default();

        mock_mempool.expect_collect_txs().return_once(|_, _, _| {
            Err(BlockConstructionError::Validity(
                TxValidationError::SubsystemCallError(ResponseError::NoResponse.into()),
            ))
        });

        manager.add_subsystem("mock-mempool", mock_mempool)
    };

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production =
                blockprod_setup.make_blockprod_builder().with_mempool(mock_mempool).build();

            let result = block_production
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await;

            assert_matches!(
                result,
                Err(BlockProductionError::MempoolBlockConstruction(
                    BlockConstructionError::Validity(TxValidationError::SubsystemCallError(_)),
                ))
            );
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_source_mempool() {
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let (new_block, job_finished_receiver) = block_production
                // TODO: Add transactions to the mempool
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::FillSpaceFromMempool,
                )
                .await
                .unwrap();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_source_provided() {
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let (new_block, job_finished_receiver) = block_production
                // TODO: Add transactions to the parameters
                .produce_block(
                    GenerateBlockInputData::None,
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await
                .unwrap();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
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
    let chain_config = {
        let net_upgrades = NetUpgrades::initialize(vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoW {
                // Make difficulty impossible so the cancel from
                // the mock job manager is always seen before
                // solving the block
                initial_difficulty: Uint256::ZERO.into(),
            },
        )])
        .unwrap();

        Arc::new(Builder::new(ChainType::Regtest).consensus_upgrades(net_upgrades).build())
    };

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let mut block_production = blockprod_setup.make_blockprod_builder().build();

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

            let err = block_production
                .produce_block(
                    GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
                        Destination::AnyoneCanSpend,
                    ))),
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await
                .unwrap_err();

            assert_eq!(err, BlockProductionError::Cancelled);
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn solved_ignore_consensus() {
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

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

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
        }
    });

    manager.main().await;
    join_handle.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn solved_pow_consensus() {
    let chain_config = {
        let net_upgrades = NetUpgrades::initialize(vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoW {
                initial_difficulty: Uint256::MAX.into(),
            },
        )])
        .unwrap();

        Arc::new(Builder::new(ChainType::Regtest).consensus_upgrades(net_upgrades).build())
    };

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

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
                .unwrap();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
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
    let pos_setup = setup_pos(&time_getter, BlockHeight::new(1), &[], None, &mut rng);

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&pos_setup.chain_config))
        .with_time_getter(time_getter)
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let input_data = Box::new(PoSGenerateBlockInputData::new(
                pos_setup.genesis_stake_private_key,
                pos_setup.genesis_vrf_private_key,
                PoolId::new(H256::zero()),
                vec![TxInput::from_utxo(
                    OutPointSourceId::BlockReward(pos_setup.chain_config.genesis_block_id()),
                    0,
                )],
                vec![pos_setup.create_genesis_pool_utxo],
            ));

            let (new_block, job_finished_receiver) = block_production
                .produce_block(
                    GenerateBlockInputData::PoS(input_data),
                    vec![],
                    vec![],
                    PackingStrategy::LeaveEmptySpace,
                )
                .await
                .unwrap();

            job_finished_receiver.await.unwrap();

            assert_job_count(&block_production, 0).await;
            blockprod_setup.assert_process_block(new_block).await;
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
                PerThousand::new(1000).unwrap(),
                Amount::ZERO,
            )),
        )
    };

    let blocks_to_generate = rng.random_range(100..=1000);

    let chain_config = {
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
            let next_consensus_type = rng.random_range(0..consensus_types.len());

            randomized_net_upgrades.push((
                BlockHeight::new(next_height_consensus_change),
                consensus_types[next_consensus_type].clone(),
            ));

            next_height_consensus_change += rng.random_range(1..50);
        }

        let net_upgrades = NetUpgrades::initialize(randomized_net_upgrades).unwrap();

        Arc::new(
            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis_block)
                .consensus_upgrades(net_upgrades)
                .build(),
        )
    };

    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new()
        .with_chain_config(Arc::clone(&chain_config))
        .with_time_getter(time_getter)
        .build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let mut block_production = blockprod_setup.make_blockprod_builder().build();

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
                            .unwrap();

                        job_finished_receiver.await.unwrap();

                        blockprod_setup.assert_process_block(new_block.clone()).await;
                    }
                    RequiredConsensus::PoS(_) => {
                        // Try no input data for PoS consensus

                        let input_data_none_err = block_production
                            .produce_block(
                                GenerateBlockInputData::None,
                                vec![],
                                vec![],
                                PackingStrategy::LeaveEmptySpace,
                            )
                            .await
                            .unwrap_err();

                        assert_eq!(
                            input_data_none_err,
                            BlockProductionError::FailedConsensusInitialization(
                                ConsensusCreationError::StakingError(
                                    ConsensusPoSError::NoInputDataProvided,
                                ),
                            )
                        );

                        // Try PoW input data for PoS consensus

                        let input_data_pow_err = block_production
                            .produce_block(
                                input_data_pow,
                                vec![],
                                vec![],
                                PackingStrategy::LeaveEmptySpace,
                            )
                            .await
                            .unwrap_err();

                        assert_eq!(
                            input_data_pow_err,
                            BlockProductionError::FailedConsensusInitialization(
                                ConsensusCreationError::StakingError(
                                    ConsensusPoSError::PoWInputDataProvided,
                                ),
                            )
                        );

                        // Try PoS input data for PoS consensus

                        let (new_block, job_finished_receiver) = block_production
                            .produce_block(
                                input_data_pos,
                                vec![],
                                vec![],
                                PackingStrategy::LeaveEmptySpace,
                            )
                            .await
                            .unwrap();

                        job_finished_receiver.await.unwrap();

                        let result = blockprod_setup.assert_process_block(new_block).await;

                        // Update kernel input parameters for future PoS blocks

                        kernel_input = TxInput::from_utxo(
                            OutPointSourceId::BlockReward(result.into_gen_block_index().block_id()),
                            0,
                        );

                        kernel_input_utxo = TxOutput::ProduceBlockFromStake(
                            Destination::PublicKey(genesis_stake_public_key.clone()),
                            H256::zero().into(),
                        );
                    }
                    RequiredConsensus::PoW(_) => {
                        // Try no input data for PoW consensus

                        let input_data_none_err = block_production
                            .produce_block(
                                GenerateBlockInputData::None,
                                vec![],
                                vec![],
                                PackingStrategy::LeaveEmptySpace,
                            )
                            .await
                            .unwrap_err();

                        assert_eq!(
                            input_data_none_err,
                            BlockProductionError::FailedConsensusInitialization(
                                ConsensusCreationError::MiningError(
                                    ConsensusPoWError::NoInputDataProvided,
                                ),
                            )
                        );

                        // Try PoS input data for PoW consensus

                        let input_data_pos_err = block_production
                            .produce_block(
                                input_data_pos,
                                vec![],
                                vec![],
                                PackingStrategy::LeaveEmptySpace,
                            )
                            .await
                            .unwrap_err();

                        assert_eq!(
                            input_data_pos_err,
                            BlockProductionError::FailedConsensusInitialization(
                                ConsensusCreationError::MiningError(
                                    ConsensusPoWError::PoSInputDataProvided,
                                ),
                            )
                        );

                        // Try PoW input data for PoW consensus

                        let (new_block, job_finished_receiver) = block_production
                            .produce_block(
                                input_data_pow,
                                vec![],
                                vec![],
                                PackingStrategy::LeaveEmptySpace,
                            )
                            .await
                            .unwrap();

                        job_finished_receiver.await.unwrap();

                        blockprod_setup.assert_process_block(new_block.clone()).await;
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
    let (blockprod_setup, manager) = BlockprodTestSetupBuilder::new().build();

    let join_handle = tokio::spawn({
        let shutdown_trigger = manager.make_shutdown_trigger();
        async move {
            // Ensure a shutdown signal will be sent by the end of the scope
            let _shutdown_signal = OnceDestructor::new(move || {
                shutdown_trigger.initiate();
            });

            let block_production = blockprod_setup.make_blockprod_builder().build();

            let mut rng = make_seedable_rng(seed);
            let jobs_to_create = rng.random_range(1..=20);

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
