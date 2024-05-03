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

use std::collections::{BTreeMap, BTreeSet};

use rstest::rstest;

use chainstate::ChainstateConfig;
use chainstate_storage::TipStorageTag;
use chainstate_test_framework::{empty_witness, BlockBuilder, TestFramework, TransactionBuilder};
use common::{
    chain::{
        self, output_value::OutputValue, timelock::OutputTimeLock, AccountNonce, AccountOutPoint,
        AccountSpending, CoinUnit, DelegationId, Destination, OutPointSourceId, PoolId, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{amount::SignedAmount, Amount, BlockHeight, Idable},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use logging::log;
use pos_accounting::PoSAccountingStorageRead;
use randomness::{seq::IteratorRandom, CryptoRng, Rng};
use test_utils::random::{make_seedable_rng, Seed};

use crate::tests::helpers::{
    block_creation_helpers::make_block_reward,
    pos::create_stake_pool_data_with_all_reward_to_staker,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn basic_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                chain::config::create_unit_test_config_builder()
                    .min_stake_pool_pledge(Amount::from_atoms(CoinUnit::ATOMS_PER_COIN))
                    .build(),
            )
            .build();

        let mut test_data = TestData::new();

        let (pool1, pool1_pledge) = test_data.make_new_pool(&mut tf, &mut rng);

        let expected_balances_at_1 = [(pool1, pool1_pledge)];

        let check1 = |tf: &TestFramework| {
            let balances_at_0_0 = get_balances_at_heights(tf, &[pool1], Some(0), Some(0));
            assert_eq!(balances_at_0_0, BTreeMap::new());

            let balances_at_1_1 = get_balances_at_heights(tf, &[pool1], Some(1), Some(1));
            let expected_balances_at_1_1 = make_expected_balances(&[(1, &expected_balances_at_1)]);
            assert_eq!(balances_at_1_1, expected_balances_at_1_1);

            let balances_at_0_1 = get_balances_at_heights(tf, &[pool1], Some(0), Some(1));
            assert_eq!(balances_at_0_1, expected_balances_at_1_1);
        };

        check1(&tf);

        let (pool2, pool2_pledge) = test_data.make_new_pool(&mut tf, &mut rng);

        let expected_balances_at_2 = [(pool1, pool1_pledge), (pool2, pool2_pledge)];

        let check2 = |tf: &TestFramework| {
            check1(tf);

            let balances_at_2_2 = get_balances_at_heights(tf, &[pool1, pool2], Some(2), Some(2));
            let expected_balances_at_2_2 = make_expected_balances(&[(2, &expected_balances_at_2)]);
            assert_eq!(balances_at_2_2, expected_balances_at_2_2);

            let balances_at_1_2 = get_balances_at_heights(tf, &[pool1, pool2], Some(1), Some(2));
            let expected_balances_at_12 = make_expected_balances(&[
                (1, &expected_balances_at_1),
                (2, &expected_balances_at_2),
            ]);
            assert_eq!(balances_at_1_2, expected_balances_at_12);

            let balances_at_0_2 = get_balances_at_heights(tf, &[pool1, pool2], Some(0), Some(2));
            assert_eq!(balances_at_0_2, expected_balances_at_12);
        };

        check2(&tf);

        test_data.decommission_pool(&mut tf, &mut rng, &pool1);

        let expected_balances_at_3 = [(pool2, pool2_pledge)];

        let check3 = |tf: &TestFramework| {
            check2(tf);

            // Special case - asked only for the tip height and for the pool that doesn't
            // exist at that height.
            let balance_of_1_at_3_3 = get_balances_at_heights(tf, &[pool1], Some(3), Some(3));
            assert_eq!(balance_of_1_at_3_3, BTreeMap::new());

            let balances_at_3_3 = get_balances_at_heights(tf, &[pool1, pool2], Some(3), Some(3));
            let expected_balances_at_3_3 = make_expected_balances(&[(3, &expected_balances_at_3)]);
            assert_eq!(balances_at_3_3, expected_balances_at_3_3);

            let balances_at_2_3 = get_balances_at_heights(tf, &[pool1, pool2], Some(2), Some(3));
            let expected_balances_at_2_3 = make_expected_balances(&[
                (2, &expected_balances_at_2),
                (3, &expected_balances_at_3),
            ]);
            assert_eq!(balances_at_2_3, expected_balances_at_2_3);

            let balances_at_1_3 = get_balances_at_heights(tf, &[pool1, pool2], Some(1), Some(3));
            let expected_balances_at_1_3 = make_expected_balances(&[
                (1, &expected_balances_at_1),
                (2, &expected_balances_at_2),
                (3, &expected_balances_at_3),
            ]);
            assert_eq!(balances_at_1_3, expected_balances_at_1_3);

            let balances_at_0_3 = get_balances_at_heights(tf, &[pool1, pool2], Some(0), Some(3));
            assert_eq!(balances_at_0_3, expected_balances_at_1_3);
        };

        check3(&tf);

        let (delegation, delegated_anount) = test_data.create_delegation(&mut tf, &mut rng, &pool2);

        let pool2_balance = (pool2_pledge + delegated_anount).unwrap();
        let expected_balances_at_4 = [(pool2, pool2_balance)];

        let check4 = |tf: &TestFramework| {
            check3(tf);

            let balances_at_4_4 = get_balances_at_heights(tf, &[pool1, pool2], Some(4), Some(4));
            let expected_balances_at_4_4 = make_expected_balances(&[(4, &expected_balances_at_4)]);
            assert_eq!(balances_at_4_4, expected_balances_at_4_4);

            let balances_at_3_4 = get_balances_at_heights(tf, &[pool1, pool2], Some(3), Some(4));
            let expected_balances_at_3_4 = make_expected_balances(&[
                (3, &expected_balances_at_3),
                (4, &expected_balances_at_4),
            ]);
            assert_eq!(balances_at_3_4, expected_balances_at_3_4);

            let balances_at_2_4 = get_balances_at_heights(tf, &[pool1, pool2], Some(2), Some(4));
            let expected_balances_at_2_4 = make_expected_balances(&[
                (2, &expected_balances_at_2),
                (3, &expected_balances_at_3),
                (4, &expected_balances_at_4),
            ]);
            assert_eq!(balances_at_2_4, expected_balances_at_2_4);

            let balances_at_1_4 = get_balances_at_heights(tf, &[pool1, pool2], Some(1), Some(4));
            let expected_balances_at_1_4 = make_expected_balances(&[
                (1, &expected_balances_at_1),
                (2, &expected_balances_at_2),
                (3, &expected_balances_at_3),
                (4, &expected_balances_at_4),
            ]);
            assert_eq!(balances_at_1_4, expected_balances_at_1_4);

            let balances_at_0_4 = get_balances_at_heights(tf, &[pool1, pool2], Some(0), Some(4));
            assert_eq!(balances_at_0_4, expected_balances_at_1_4);
        };

        check4(&tf);

        let withdraw_amount =
            test_data.withdraw_from_delegation(&mut tf, &mut rng, &pool2, &delegation);

        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        let expected_balances_at_5 = [(pool2, pool2_balance)];

        let check5 = |tf: &TestFramework| {
            check4(tf);

            let balances_at_5_5 = get_balances_at_heights(tf, &[pool1, pool2], Some(5), Some(5));
            let expected_balances_at_5_5 = make_expected_balances(&[(5, &expected_balances_at_5)]);
            assert_eq!(balances_at_5_5, expected_balances_at_5_5);

            let balances_at_4_5 = get_balances_at_heights(tf, &[pool1, pool2], Some(4), Some(5));
            let expected_balances_at_4_5 = make_expected_balances(&[
                (4, &expected_balances_at_4),
                (5, &expected_balances_at_5),
            ]);
            assert_eq!(balances_at_4_5, expected_balances_at_4_5);

            let balances_at_3_5 = get_balances_at_heights(tf, &[pool1, pool2], Some(3), Some(5));
            let expected_balances_at_3_5 = make_expected_balances(&[
                (3, &expected_balances_at_3),
                (4, &expected_balances_at_4),
                (5, &expected_balances_at_5),
            ]);
            assert_eq!(balances_at_3_5, expected_balances_at_3_5);

            let balances_at_2_5 = get_balances_at_heights(tf, &[pool1, pool2], Some(2), Some(5));
            let expected_balances_at_2_4 = make_expected_balances(&[
                (2, &expected_balances_at_2),
                (3, &expected_balances_at_3),
                (4, &expected_balances_at_4),
                (5, &expected_balances_at_5),
            ]);
            assert_eq!(balances_at_2_5, expected_balances_at_2_4);

            let balances_at_1_5 = get_balances_at_heights(tf, &[pool1, pool2], Some(1), Some(5));
            let expected_balances_at_1_5 = make_expected_balances(&[
                (1, &expected_balances_at_1),
                (2, &expected_balances_at_2),
                (3, &expected_balances_at_3),
                (4, &expected_balances_at_4),
                (5, &expected_balances_at_5),
            ]);
            assert_eq!(balances_at_1_5, expected_balances_at_1_5);

            let balances_at_0_5 = get_balances_at_heights(tf, &[pool1, pool2], Some(0), Some(5));
            assert_eq!(balances_at_0_5, expected_balances_at_1_5);
        };

        check5(&tf);

        // Finally add to the delegation and create an empty block after that.
        // Perform simpler checks this time to reduce the noise.
        let added_amount = test_data.add_to_delegation(&mut tf, &mut rng, &pool2, &delegation);
        test_data.add_trivial_block(&mut tf, &mut rng);

        check5(&tf);

        let pool2_balance = (pool2_balance + added_amount).unwrap();
        let expected_balances_at_6 = [(pool2, pool2_balance)];

        let balances_at_0_7 = get_balances_at_heights(&tf, &[pool1, pool2], Some(0), Some(7));
        let expected_balances_at_0_7 = make_expected_balances(&[
            (1, &expected_balances_at_1),
            (2, &expected_balances_at_2),
            (3, &expected_balances_at_3),
            (4, &expected_balances_at_4),
            (5, &expected_balances_at_5),
            (6, &expected_balances_at_6),
            (7, &expected_balances_at_6),
        ]);
        assert_eq!(balances_at_0_7, expected_balances_at_0_7);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(
                chain::config::create_unit_test_config_builder()
                    .min_stake_pool_pledge(Amount::from_atoms(CoinUnit::ATOMS_PER_COIN))
                    .build(),
            )
            .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
            .build();

        let mut test_data = TestData::new();

        // Note: the assertions are performed inside make_new_pool etc, no need to check
        // anything explicitly.
        for _ in 0..100 {
            let mut did_something = false;
            match rng.gen_range(0..5) {
                0 => {
                    let _ = test_data.make_new_pool(&mut tf, &mut rng);
                    did_something = true;
                }
                1 => {
                    if rng.gen_bool(0.5) {
                        if let Some(pool_id) = test_data.random_pool_id(&mut rng) {
                            test_data.decommission_pool(&mut tf, &mut rng, &pool_id);
                            did_something = true;
                        }
                    }
                }
                2 => {
                    if rng.gen_bool(0.5) {
                        if let Some(pool_id) = test_data.random_pool_id(&mut rng) {
                            let _ = test_data.create_delegation(&mut tf, &mut rng, &pool_id);
                            did_something = true;
                        }
                    }
                }
                3 => {
                    if rng.gen_bool(0.5) {
                        if let Some((pool_id, delegation_id)) =
                            test_data.random_pool_and_delegation_id(&mut rng)
                        {
                            let _ = test_data.withdraw_from_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                &delegation_id,
                            );
                            did_something = true;
                        }
                    }
                }
                _ => {
                    if rng.gen_bool(0.5) {
                        if let Some((pool_id, delegation_id)) =
                            test_data.random_pool_and_delegation_id(&mut rng)
                        {
                            let _ = test_data.add_to_delegation(
                                &mut tf,
                                &mut rng,
                                &pool_id,
                                &delegation_id,
                            );
                            did_something = true;
                        }
                    }
                }
            }

            if !did_something {
                test_data.add_trivial_block(&mut tf, &mut rng);
            }
        }
    });
}

fn make_block_builder(tf: &mut TestFramework) -> BlockBuilder {
    tf.make_block_builder().with_reward(make_block_reward(Amount::from_atoms(
        100 * CoinUnit::ATOMS_PER_COIN,
    )))
}

fn get_balances_at_heights(
    tf: &TestFramework,
    pool_ids: &[PoolId],
    min_height: Option<u32>,
    max_height: Option<u32>,
) -> BTreeMap<BlockHeight, BTreeMap<PoolId, Amount>> {
    let min_height = BlockHeight::new(min_height.unwrap_or(0).into());
    let bb_height = tf.best_block_index().block_height();
    let max_height = max_height.map_or(bb_height, |h| BlockHeight::new(h.into()));

    let balances = tf
        .chainstate
        .get_stake_pool_balances_at_heights(pool_ids, min_height, max_height)
        .unwrap();

    // FIXME test the staker's balance
    balances
        .iter()
        .map(|(height, pool_to_balances_map)| {
            (
                *height,
                pool_to_balances_map
                    .iter()
                    .map(|(pool_id, balances)| (*pool_id, balances.total_balance()))
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect::<BTreeMap<_, _>>()
}

fn get_cur_balances(tf: &TestFramework, pool_ids: &[PoolId]) -> BTreeMap<PoolId, Amount> {
    let mut result = BTreeMap::new();

    for pool_id in pool_ids {
        if let Some(balance) = tf.chainstate.get_stake_pool_balance(*pool_id).unwrap() {
            result.insert(*pool_id, balance);
        }
    }

    result
}

fn make_expected_balances(
    balances: &[(u32, &[(PoolId, Amount)])],
) -> BTreeMap<BlockHeight, BTreeMap<PoolId, Amount>> {
    balances
        .iter()
        .map(|(height, pool_to_amount_map)| {
            let pool_to_amount_map = pool_to_amount_map.iter().copied().collect::<BTreeMap<_, _>>();
            (BlockHeight::new((*height).into()), pool_to_amount_map)
        })
        .collect::<BTreeMap<_, _>>()
}

struct TestPoolInfo {
    stake_outpoint: UtxoOutPoint,
    delegations: BTreeSet<DelegationId>,
}

struct TestData {
    pools: BTreeMap<PoolId, TestPoolInfo>,
    decommissioned_pools: BTreeSet<PoolId>,
    delegations: BTreeMap<DelegationId, /*next_nonce:*/ AccountNonce>,
    expected_balances: BTreeMap<BlockHeight, BTreeMap<PoolId, Amount>>,
}

impl TestData {
    fn new() -> Self {
        Self {
            pools: BTreeMap::new(),
            decommissioned_pools: BTreeSet::new(),
            delegations: BTreeMap::new(),
            expected_balances: BTreeMap::new(),
        }
    }

    fn make_new_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (PoolId, Amount) {
        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let pledge =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, _) =
            create_stake_pool_data_with_all_reward_to_staker(rng, pledge, vrf_pk);
        let outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(tf.best_block_id()), 0);
        let pool_id = pos_accounting::make_pool_id(&outpoint);

        let tx = TransactionBuilder::new()
            .add_input(outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();
        let stake_outpoint =
            UtxoOutPoint::new(OutPointSourceId::Transaction(tx.transaction().get_id()), 0);
        make_block_builder(tf).add_transaction(tx).build_and_process(rng).unwrap();

        log::debug!(
            "New pool {pool_id} created with pledge {}",
            pledge.into_atoms()
        );

        self.pools.insert(
            pool_id,
            TestPoolInfo {
                stake_outpoint,
                delegations: BTreeSet::new(),
            },
        );

        self.push_new_height(tf).insert(pool_id, pledge);

        self.assert_balances(tf);

        (pool_id, pledge)
    }

    fn decommission_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
    ) {
        let info = self.pools.remove(pool_id).unwrap();
        let staker_balance =
            PoSAccountingStorageRead::<TipStorageTag>::get_pool_data(&tf.storage, *pool_id)
                .unwrap()
                .unwrap()
                .staker_balance()
                .unwrap();

        let tx = TransactionBuilder::new()
            .add_input(info.stake_outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(staker_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();
        make_block_builder(tf).add_transaction(tx).build_and_process(rng).unwrap();

        log::debug!("Pool {pool_id} decommissioned");

        for delegation_id in info.delegations {
            self.delegations.remove(&delegation_id);
        }

        self.decommissioned_pools.insert(*pool_id);

        self.push_new_height(tf).remove(pool_id);

        self.assert_balances(tf);
    }

    fn create_delegation(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
    ) -> (DelegationId, Amount) {
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_delegate =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge / 2..min_stake_pool_pledge * 2));

        let outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(tf.best_block_id()), 0);

        let delegation_id = pos_accounting::make_delegation_id(&outpoint);
        let tx1 = TransactionBuilder::new()
            .add_input(outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                *pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
            ))
            .build();
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

        log::debug!(
            "Delegation {delegation_id} to pool {pool_id} created, amount = {}",
            amount_to_delegate.into_atoms()
        );

        self.pools.get_mut(pool_id).unwrap().delegations.insert(delegation_id);
        self.delegations.insert(delegation_id, AccountNonce::new(0));

        self.push_height_update_expected_balance(
            tf,
            pool_id,
            amount_to_delegate.into_signed().unwrap(),
        );

        self.assert_balances(tf);

        (delegation_id, amount_to_delegate)
    }

    fn withdraw_from_delegation(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        delegation_id: &DelegationId,
    ) -> Amount {
        let amount_to_withdraw = Amount::from_atoms(rng.gen_range(1000..10_000));

        let nonce = self.next_nonce(delegation_id);

        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    nonce,
                    AccountSpending::DelegationBalance(*delegation_id, amount_to_withdraw),
                )),
                empty_witness(rng),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount_to_withdraw),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build();

        make_block_builder(tf).add_transaction(tx).build_and_process(rng).unwrap();

        log::debug!(
            "Withdrawn {} from delegation {delegation_id} to pool {pool_id}",
            amount_to_withdraw.into_atoms()
        );

        self.push_height_update_expected_balance(
            tf,
            pool_id,
            (-amount_to_withdraw.into_signed().unwrap()).unwrap(),
        );

        self.assert_balances(tf);

        amount_to_withdraw
    }

    fn add_to_delegation(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        delegation_id: &DelegationId,
    ) -> Amount {
        let amount_to_add = Amount::from_atoms(rng.gen_range(1000..10_000));

        let outpoint = UtxoOutPoint::new(OutPointSourceId::BlockReward(tf.best_block_id()), 0);

        let tx = TransactionBuilder::new()
            .add_input(outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::DelegateStaking(amount_to_add, *delegation_id))
            .build();

        make_block_builder(tf).add_transaction(tx).build_and_process(rng).unwrap();

        log::debug!(
            "Added {} to delegation {delegation_id} to pool {pool_id}",
            amount_to_add.into_atoms()
        );

        self.push_height_update_expected_balance(tf, pool_id, amount_to_add.into_signed().unwrap());

        self.assert_balances(tf);

        amount_to_add
    }

    fn add_trivial_block(&mut self, tf: &mut TestFramework, rng: &mut (impl Rng + CryptoRng)) {
        make_block_builder(tf).build_and_process(rng).unwrap();

        log::debug!("Trivial block added");

        self.push_new_height(tf);
        self.assert_balances(tf);
    }

    fn next_nonce(&mut self, delegation_id: &DelegationId) -> AccountNonce {
        let next_nonce = self.delegations.get_mut(delegation_id).unwrap();
        let result = *next_nonce;
        *next_nonce = next_nonce.increment().unwrap();
        result
    }

    fn push_height_update_expected_balance(
        &mut self,
        tf: &TestFramework,
        pool_id: &PoolId,
        balance_change: SignedAmount,
    ) {
        let new_height_data = self.push_new_height(tf);
        let cur_balance = new_height_data.entry(*pool_id).or_insert(Amount::ZERO);
        *cur_balance =
            Amount::from_signed((cur_balance.into_signed().unwrap() + balance_change).unwrap())
                .unwrap();
    }

    fn random_pool_id(&self, rng: &mut impl Rng) -> Option<PoolId> {
        self.pools.keys().choose(rng).cloned()
    }

    fn random_pool_and_delegation_id(&self, rng: &mut impl Rng) -> Option<(PoolId, DelegationId)> {
        let pool_id = self.random_pool_id(rng)?;
        let delegation_id =
            self.pools.get(&pool_id).unwrap().delegations.iter().choose(rng).copied();

        delegation_id.map(|delegation_id| (pool_id, delegation_id))
    }

    fn push_new_height(&mut self, tf: &TestFramework) -> &mut BTreeMap<PoolId, Amount> {
        let bb_height = tf.best_block_index().block_height();
        assert!(bb_height.into_int() > 0);
        let prev_balances = if bb_height.into_int() == 1 {
            assert!(self.expected_balances.is_empty());
            BTreeMap::new()
        } else {
            let (prev_height, prev_balances) = self.expected_balances.last_key_value().unwrap();
            assert_eq!(*prev_height, bb_height.prev_height().unwrap());
            prev_balances.clone()
        };

        match self.expected_balances.entry(bb_height) {
            std::collections::btree_map::Entry::Occupied(_) => panic!("Can't happen"),
            std::collections::btree_map::Entry::Vacant(e) => e.insert(prev_balances),
        }
    }

    fn assert_balances(&self, tf: &TestFramework) {
        let pool_ids = self
            .pools
            .keys()
            .chain(self.decommissioned_pools.iter())
            .copied()
            .collect::<Vec<_>>();

        let actual_balances = get_balances_at_heights(tf, &pool_ids, None, None);
        let cur_actual_balances = get_cur_balances(tf, &pool_ids);

        let bb_height = tf.best_block_index().block_height();
        let empty_map = BTreeMap::new();
        let actual_balances_at_bb_height = actual_balances.get(&bb_height).unwrap_or(&empty_map);
        assert_eq!(*actual_balances_at_bb_height, cur_actual_balances);

        let expected_balances = {
            let mut expected_balances = self.expected_balances.clone();
            expected_balances.retain(|_, pool_to_amount_map| {
                pool_to_amount_map.retain(|_, amount| *amount != Amount::ZERO);
                !pool_to_amount_map.is_empty()
            });

            expected_balances
        };

        assert_eq!(actual_balances, expected_balances);
    }
}
