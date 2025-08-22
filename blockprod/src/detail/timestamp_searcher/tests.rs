// Copyright (c) 2021-2024 RBB S.r.l
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

use rstest::rstest;

use test_utils::random::{make_seedable_rng, Seed};

use logging::{init_logging, log};
use randomness::{CryptoRng, Rng};

use crate::{detail::timestamp_searcher::SearchDataForHeight, TimestampSearchData};

mod collect_search_data {
    use std::num::NonZeroU64;

    use chainstate::{ChainstateConfig, NonZeroPoolBalances};
    use chainstate_test_framework::{
        create_custom_genesis_with_stake_pool, create_stake_pool_data_with_all_reward_to_staker,
        empty_witness, PoSBlockBuilder, TestFramework, TransactionBuilder, UtxoForSpending,
    };
    use chainstate_types::pos_randomness::PoSRandomness;
    use common::{
        chain::{
            self, config::ChainType, make_delegation_id, output_value::OutputValue, CoinUnit,
            ConsensusUpgrade, Destination, NetUpgrades, OutPointSourceId, PoSChainConfigBuilder,
            PoSConsensusVersion, PoolId, TxOutput, UtxoOutPoint,
        },
        primitives::{Amount, BlockCount, BlockHeight, Idable, H256},
    };
    use consensus::calculate_target_required_from_block_index;
    use crypto::{
        key::{KeyKind, PrivateKey},
        vrf::{VRFKeyKind, VRFPrivateKey},
    };

    use crate::detail::utils::make_ancestor_getter;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test(#[case] seed: Seed) {
        init_logging();

        let mut rng = make_seedable_rng(seed);

        let consensus_version = if rng.gen_bool(0.5) {
            PoSConsensusVersion::V0
        } else {
            PoSConsensusVersion::V1
        };
        let mut tf = make_test_framework(consensus_version, &mut rng);

        let mut utxo_for_spending = UtxoForSpending::new(
            UtxoOutPoint::new(
                OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                0,
            ),
            INITIAL_MINT_AMOUNT,
        );

        for _ in 0..3 {
            make_block_builder(&mut tf).build_and_process(&mut rng).unwrap();
        }

        let (pool_id, pool_pledge) = create_pool(&mut tf, &mut rng, &mut utxo_for_spending);
        let pool_creation_height = tf.best_block_index().block_height();

        for _ in 0..3 {
            make_block_builder(&mut tf).build_and_process(&mut rng).unwrap();
        }

        let delegated_amount = delegate(&mut tf, &mut rng, &pool_id, &mut utxo_for_spending);
        let delegation_height = tf.best_block_index().block_height();

        for _ in 0..3 {
            make_block_builder(&mut tf).build_and_process(&mut rng).unwrap();
        }

        log::debug!("pool_creation_height = {pool_creation_height}, delegation_height = {delegation_height}");

        let seconds_to_check = 1000;

        // Obtain the data for heights where the pool hasn't existed yet.
        {
            // check_all_timestamps_between_blocks = true
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                Some(pool_creation_height),
                seconds_to_check,
                true,
            )
            .unwrap();
            let expected_data = TimestampSearchData::new(
                BlockHeight::one(),
                vec![],
                tf.chain_config().final_supply().unwrap().to_amount_atoms(),
                true,
            );
            assert_eq!(search_data, expected_data);

            // check_all_timestamps_between_blocks = false
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                Some(pool_creation_height),
                seconds_to_check,
                false,
            )
            .unwrap();
            let expected_data = TimestampSearchData::new(
                BlockHeight::one(),
                vec![],
                tf.chain_config().final_supply().unwrap().to_amount_atoms(),
                false,
            );
            assert_eq!(search_data, expected_data);
        }

        // Obtain the data for heights where the delegation hasn't been created yet.
        {
            let make_expected_data =
                |tf: &TestFramework,
                 min_height: BlockHeight,
                 max_height: BlockHeight,
                 non_last_block_block_timestamp_diff: Option<u64>,
                 check_all_timestamps: bool| {
                    let mut data = Vec::new();
                    for height in min_height.iter_up_to_including(max_height) {
                        data.push(make_expected_data_for_height(
                            tf,
                            height,
                            NonZeroPoolBalances::new(pool_pledge, pool_pledge).unwrap(),
                            if height == max_height {
                                Some(seconds_to_check)
                            } else {
                                non_last_block_block_timestamp_diff
                            },
                            consensus_version,
                        ));
                    }
                    TimestampSearchData::new(
                        min_height,
                        data,
                        tf.chain_config().final_supply().unwrap().to_amount_atoms(),
                        check_all_timestamps,
                    )
                };

            // check_all_timestamps_between_blocks = true
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                Some(delegation_height),
                seconds_to_check,
                true,
            )
            .unwrap();
            let expected_data = make_expected_data(
                &tf,
                pool_creation_height.next_height(),
                delegation_height,
                None,
                true,
            );
            assert_eq!(search_data, expected_data);

            // check_all_timestamps_between_blocks = false
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                Some(delegation_height),
                seconds_to_check,
                false,
            )
            .unwrap();
            let expected_data = make_expected_data(
                &tf,
                pool_creation_height.next_height(),
                delegation_height,
                Some(seconds_to_check),
                false,
            );
            assert_eq!(search_data, expected_data);
        }

        // Obtain the data for all heights.
        {
            let make_expected_data =
                |tf: &TestFramework,
                 min_height: BlockHeight,
                 max_height: BlockHeight,
                 non_last_block_block_timestamp_diff: Option<u64>,
                 check_all_timestamps: bool| {
                    let mut data = Vec::new();
                    for height in min_height.iter_up_to_including(max_height) {
                        let balances = if height > delegation_height {
                            NonZeroPoolBalances::new(
                                (pool_pledge + delegated_amount).unwrap(),
                                pool_pledge,
                            )
                            .unwrap()
                        } else {
                            NonZeroPoolBalances::new(pool_pledge, pool_pledge).unwrap()
                        };

                        data.push(make_expected_data_for_height(
                            tf,
                            height,
                            balances,
                            if height == max_height {
                                Some(seconds_to_check)
                            } else {
                                non_last_block_block_timestamp_diff
                            },
                            consensus_version,
                        ));
                    }
                    TimestampSearchData::new(
                        min_height,
                        data,
                        tf.chain_config().final_supply().unwrap().to_amount_atoms(),
                        check_all_timestamps,
                    )
                };

            let max_height = tf.best_block_index().block_height().next_height();

            // check_all_timestamps_between_blocks = true
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                Some(max_height),
                seconds_to_check,
                true,
            )
            .unwrap();
            let expected_data = make_expected_data(
                &tf,
                pool_creation_height.next_height(),
                max_height,
                None,
                true,
            );
            assert_eq!(search_data, expected_data);

            // Do the same with None as max_height.
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                None,
                seconds_to_check,
                true,
            )
            .unwrap();
            assert_eq!(search_data, expected_data);

            // check_all_timestamps_between_blocks = false
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                Some(max_height),
                seconds_to_check,
                false,
            )
            .unwrap();
            let expected_data = make_expected_data(
                &tf,
                pool_creation_height.next_height(),
                max_height,
                Some(seconds_to_check),
                false,
            );
            assert_eq!(search_data, expected_data);

            // Do the same with None as max_height.
            let search_data = TimestampSearchData::obtain(
                &tf.chainstate,
                &pool_id,
                BlockHeight::one(),
                None,
                seconds_to_check,
                false,
            )
            .unwrap();
            assert_eq!(search_data, expected_data);
        }
    }

    const INITIAL_MINT_AMOUNT: Amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
    const MATURITY_BLOCK_COUNT: BlockCount = BlockCount::new(100);

    fn make_expected_data_for_height(
        tf: &TestFramework,
        block_height: BlockHeight,
        pool_balances: NonZeroPoolBalances,
        // The expected difference between the min and max timestamp;
        // if none, the max timestamp is the timestamp of the next block.
        timestamp_diff: Option<u64>,
        consensus_version: PoSConsensusVersion,
    ) -> SearchDataForHeight {
        let prev_block_index = tf.gen_block_index(&tf.block_id(block_height.into_int() - 1));

        let epoch_index = tf.chain_config().epoch_index_from_height(&block_height);
        let sealed_epoch_index = tf.chain_config().sealed_epoch_index(&block_height);

        let sealed_epoch_randomness = sealed_epoch_index
            .and_then(|epoch_index| tf.chainstate.get_epoch_data(epoch_index).unwrap())
            .map_or(PoSRandomness::at_genesis(tf.chain_config()), |epoch_data| {
                *epoch_data.randomness()
            });

        let pos_status = match tf.chain_config().consensus_upgrades().consensus_status(block_height)
        {
            chain::RequiredConsensus::PoS(pos_status) => pos_status,
            chain::RequiredConsensus::PoW(_) | chain::RequiredConsensus::IgnoreConsensus => {
                panic!("Consensus type is not PoS")
            }
        };

        let min_timestamp = prev_block_index.block_timestamp().add_int_seconds(1).unwrap();
        let max_timestamp = if let Some(min_max_height_diff) = timestamp_diff {
            min_timestamp.add_int_seconds(min_max_height_diff).unwrap()
        } else {
            let cur_block_index = tf.gen_block_index(&tf.block_id(block_height.into_int()));

            cur_block_index.block_timestamp()
        };

        let target_required = calculate_target_required_from_block_index(
            tf.chain_config(),
            &pos_status,
            &prev_block_index,
            make_ancestor_getter(&tf.chainstate),
        )
        .unwrap();

        SearchDataForHeight {
            sealed_epoch_randomness,
            epoch_index,
            target_required,
            min_timestamp,
            max_timestamp,
            pool_balances,
            consensus_version,
        }
    }

    fn make_test_framework(
        consensus_version: PoSConsensusVersion,
        rng: &mut (impl Rng + CryptoRng),
    ) -> TestFramework {
        let (staking_sk, staking_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);

        let upgrades = vec![
            (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
            (
                BlockHeight::new(1),
                ConsensusUpgrade::PoS {
                    initial_difficulty: None,
                    config: PoSChainConfigBuilder::new_for_unit_test()
                        .staking_pool_spend_maturity_block_count(MATURITY_BLOCK_COUNT)
                        .consensus_version(consensus_version)
                        .build(),
                },
            ),
        ];
        let net_upgrades = NetUpgrades::initialize(upgrades).unwrap();
        let genesis = create_custom_genesis_with_stake_pool(
            staking_pk,
            vrf_pk,
            INITIAL_MINT_AMOUNT,
            INITIAL_MINT_AMOUNT,
        );

        let chain_config = chain::config::Builder::new(ChainType::Regtest)
            .consensus_upgrades(net_upgrades)
            .genesis_custom(genesis)
            .epoch_length(NonZeroU64::new(2).unwrap())
            .sealed_epoch_distance_from_tip(1)
            .build();

        let target_block_time = chain_config.target_block_spacing();

        let mut tf = TestFramework::builder(rng)
            .with_chain_config(chain_config)
            .with_initial_time_since_genesis(target_block_time.as_secs())
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();

        tf.set_genesis_pool_keys(&H256::zero().into(), staking_sk, vrf_sk);

        tf
    }

    fn create_pool(
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        utxo_for_spending: &mut UtxoForSpending,
    ) -> (PoolId, Amount) {
        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let pledge =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));

        let (pool_data, _) = create_stake_pool_data_with_all_reward_to_staker(rng, pledge, vrf_pk);
        let pool_id = PoolId::from_utxo(utxo_for_spending.outpoint());

        let tx_builder = TransactionBuilder::new()
            .add_output(TxOutput::CreateStakePool(pool_id, Box::new(pool_data)));

        let tx = utxo_for_spending.add_input_and_build_tx(tx_builder, pledge, Amount::ZERO, rng);
        make_block_builder(tf).add_transaction(tx).build_and_process(rng).unwrap();

        (pool_id, pledge)
    }

    fn delegate(
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        utxo_for_spending: &mut UtxoForSpending,
    ) -> Amount {
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_delegate =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge / 2..min_stake_pool_pledge * 2));

        let tx1_builder = TransactionBuilder::new()
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                *pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
            ));
        let tx1 = utxo_for_spending.add_input_and_build_tx(
            tx1_builder,
            amount_to_delegate,
            Amount::ZERO,
            rng,
        );
        let delegation_id = make_delegation_id(tx1.inputs()).unwrap();
        let transfer_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(tx1.transaction().get_id()), 1);

        let tx2 = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        make_block_builder(tf)
            .add_transaction(tx1)
            .add_transaction(tx2)
            .build_and_process(rng)
            .unwrap();

        amount_to_delegate
    }

    fn make_block_builder(tf: &mut TestFramework) -> PoSBlockBuilder<'_> {
        tf.make_pos_block_builder().with_specific_staking_pool(&H256::zero().into())
    }
}

mod search {
    use common::{chain::block::timestamp::BlockTimestamp, primitives::BlockHeight};

    use super::*;

    // Ensure that the value of TimestampSearchData::assume_distinct_timestamps doesn't affect
    // the result of timestamp searching.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_assume_distinct_timestamps_has_no_visible_effect(#[case] seed: Seed) {
        use chainstate::NonZeroPoolBalances;
        use chainstate_types::pos_randomness::PoSRandomness;
        use common::{
            chain::PoSConsensusVersion,
            primitives::{Amount, H256},
            Uint256,
        };
        use consensus::PoSTimestampSearchInputData;
        use crypto::vrf::{VRFKeyKind, VRFPrivateKey};

        use crate::find_timestamps_for_staking;

        init_logging();

        let mut rng = make_seedable_rng(seed);

        let start_height = BlockHeight::new(rng.gen_range(0..10));
        let items_count = rng.gen_range(10..20);

        let mut data = Vec::with_capacity(items_count);
        for i in 0..items_count {
            let min_timestamp = rng.gen::<u32>() as u64;
            let max_timestamp = min_timestamp + rng.gen_range(1..10);
            let staker_balance = rng.gen_range(1..u32::MAX) as u128;
            let total_balance = staker_balance + rng.gen::<u32>() as u128;

            data.push(SearchDataForHeight {
                sealed_epoch_randomness: PoSRandomness::new(H256::random_using(&mut rng)),
                epoch_index: i as u64,
                target_required: Uint256::from_u64(rng.gen()).into(),
                min_timestamp: BlockTimestamp::from_int_seconds(min_timestamp),
                max_timestamp: BlockTimestamp::from_int_seconds(max_timestamp),
                pool_balances: NonZeroPoolBalances::new(
                    Amount::from_atoms(total_balance),
                    Amount::from_atoms(staker_balance),
                )
                .unwrap(),
                consensus_version: if rng.gen_bool(0.5) {
                    PoSConsensusVersion::V0
                } else {
                    PoSConsensusVersion::V1
                },
            });
        }

        let final_supply = Amount::from_atoms(rng.gen_range(u32::MAX as u64..u64::MAX) as u128);

        let search_data1 = TimestampSearchData {
            start_height,
            data: data.clone(),
            final_supply,
            assume_distinct_timestamps: true,
        };

        let search_data2 = TimestampSearchData {
            start_height,
            data,
            final_supply,
            assume_distinct_timestamps: false,
        };

        let (vrf_sk, _) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

        let secret_input_data =
            PoSTimestampSearchInputData::new(H256::random_using(&mut rng).into(), vrf_sk);

        let result1 = find_timestamps_for_staking(secret_input_data.clone(), search_data1)
            .await
            .unwrap();
        let result2 = find_timestamps_for_staking(secret_input_data, search_data2).await.unwrap();

        assert_eq!(result1, result2);
    }
}
