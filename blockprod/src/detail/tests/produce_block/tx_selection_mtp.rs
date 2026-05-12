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

use std::{collections::BTreeSet, sync::Arc};

use rstest::rstest;
use static_assertions::const_assert;

use chainstate_test_framework::TransactionBuilder;
use common::{
    Uint256,
    chain::{
        ChainConfig, CoinUnit, ConsensusUpgrade, Destination, Genesis, NetUpgrades,
        OutPointSourceId, PoolId, TxOutput,
        block::timestamp::BlockTimestamp,
        config::{Builder, ChainType},
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        transaction::TxInput,
    },
    primitives::{Amount, BlockHeight, H256, Idable},
    time_getter::TimeGetter,
};
use consensus::{PoSGenerateBlockInputData, PoWGenerateBlockInputData};
use mempool::{TxOptions, tx_accumulator::PackingStrategy, tx_origin::LocalTxOrigin};
use test_utils::{
    BasicTestTimeGetter,
    random::{Seed, make_seedable_rng},
};
use utils::once_destructor::OnceDestructor;

use crate::{
    BlockProduction,
    detail::{GenerateBlockInputData, tests::produce_block::assert_job_count},
    prepare_thread_pool, test_blockprod_config,
    tests::helpers::{
        assert_process_block, make_genesis_timestamp, setup_blockprod_test, setup_pos,
    },
};

// The height at which the transaction_selection_mtp_xxx tests will create their test block.
// Any value will do as long as it's bigger than the span used to calculate the median past time.
const TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT: usize = 15;
const_assert!(TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT > chainstate::MEDIAN_TIME_SPAN);

// Common implementation for the transaction_selection_mtp_xxx tests below.
// The passed chain config is assumed to switch to the consensus type required by the test
// at the height TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT.
// `genesis_premint_output_index` specifies the genesis tx that mints some coins that can
// be spent by the test.
// Steps:
// 1) Create trivial blocks up to the height (TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT - 1).
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
async fn transaction_selection_mtp_test_impl(
    chain_config: Arc<ChainConfig>,
    input_data: GenerateBlockInputData,
    time_getter: TimeGetter,
    genesis_premint_output_index: u32,
) {
    let (manager, chainstate, mempool, p2p) =
        setup_blockprod_test(Arc::clone(&chain_config), time_getter.clone());

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

            for i in 1..TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT {
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

                for timestamp_offset_secs in -timestamp_offsets_count..=timestamp_offsets_count {
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
                            TxInput::from_utxo(OutPointSourceId::Transaction(main_tx_id), i as u32),
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

                        for tx in std::iter::once(main_tx).chain(dependent_txs) {
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
async fn transaction_selection_mtp_test_pos(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

    let extra_genesis_txs = [TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(1000 * CoinUnit::ATOMS_PER_COIN)),
        Destination::AnyoneCanSpend,
    )];

    let (
        chain_config,
        genesis_stake_private_key,
        genesis_vrf_private_key,
        create_genesis_pool_txoutput,
    ) = setup_pos(
        &time_getter,
        BlockHeight::new(TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT as u64),
        &extra_genesis_txs,
        None,
        &mut rng,
    );

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

    transaction_selection_mtp_test_impl(chain_config, input_data, time_getter, 1).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_selection_mtp_test_pow(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

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
                BlockHeight::new(TRANSACTION_SELECTION_MTP_TESTS_BLOCK_HEIGHT as u64),
                ConsensusUpgrade::PoW {
                    initial_difficulty: Uint256::MAX.into(),
                },
            ),
        ])
        .unwrap();

        Arc::new(
            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis)
                .consensus_upgrades(net_upgrades)
                .build(),
        )
    };

    let input_data = GenerateBlockInputData::PoW(Box::new(PoWGenerateBlockInputData::new(
        Destination::AnyoneCanSpend,
    )));

    transaction_selection_mtp_test_impl(chain_config, input_data, time_getter, 0).await;
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_selection_mtp_test_ignore_consensus(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new().get_time_getter();

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

        Arc::new(
            Builder::new(ChainType::Regtest)
                .genesis_custom(genesis)
                .consensus_upgrades(net_upgrades)
                .build(),
        )
    };

    transaction_selection_mtp_test_impl(chain_config, GenerateBlockInputData::None, time_getter, 0)
        .await;
}
