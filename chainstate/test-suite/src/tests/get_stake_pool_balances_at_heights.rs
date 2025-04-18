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
use chainstate_test_framework::{
    create_custom_genesis_with_stake_pool, create_stake_pool_data_with_all_reward_to_staker,
    empty_witness, PoSBlockBuilder, TestFramework, TransactionBuilder, UtxoForSpending,
};
use chainstate_types::TipStorageTag;
use common::{
    chain::{
        self, config::ChainType, make_delegation_id, output_value::OutputValue,
        timelock::OutputTimeLock, AccountNonce, AccountOutPoint, AccountSpending, CoinUnit,
        ConsensusUpgrade, DelegationId, Destination, NetUpgrades, OutPointSourceId,
        PoSChainConfigBuilder, PoolId, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{amount::SignedAmount, Amount, BlockCount, BlockHeight, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use logging::log;
use pos_accounting::PoSAccountingStorageRead;
use randomness::{seq::IteratorRandom, CryptoRng, Rng};
use test_utils::random::{make_seedable_rng, Seed};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn basic_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework(&mut rng);
        let mut test_data = TestData::new(&mut tf);

        let initial_block_reward =
            tf.chainstate.get_chain_config().block_subsidy_at_height(&BlockHeight::one());

        let check_balances =
            |tf: &TestFramework,
             expected_balances: &BTreeMap<BlockHeight, Vec<(PoolId, Balances)>>,
             existing_pools: &[PoolId]| {
                let last_height = tf.best_block_index().block_height().into_int();

                for min_height in 0..=last_height {
                    for max_height in min_height..=last_height {
                        let actual_balances_for_range = get_balances_at_heights(
                            tf,
                            existing_pools,
                            Some(min_height),
                            Some(max_height),
                        );

                        let expected_balances_for_range = expected_balances
                            .range(BlockHeight::new(min_height)..=BlockHeight::new(max_height))
                            .map(|(k, v)| (*k, v.iter().cloned().collect::<BTreeMap<_, _>>()))
                            .collect::<BTreeMap<_, _>>();

                        assert_eq!(
                            actual_balances_for_range, expected_balances_for_range,
                            "Balances differ; min_height = {min_height}, max_height = {max_height}"
                        );
                    }
                }
            };

        let mut expected_balances = BTreeMap::new();

        let (pool1, pool1_pledge) = test_data.make_new_pool(&mut tf, &mut rng);
        expected_balances.insert(
            BlockHeight::new(1),
            vec![(pool1, Balances::new_same(pool1_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1]);

        let (pool2, pool2_pledge) = test_data.make_new_pool(&mut tf, &mut rng);
        expected_balances.insert(
            BlockHeight::new(2),
            vec![
                (pool1, Balances::new_same(pool1_pledge)),
                (pool2, Balances::new_same(pool2_pledge)),
            ],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);

        test_data.decommission_pool(&mut tf, &mut rng, &pool1);
        expected_balances.insert(
            BlockHeight::new(3),
            vec![(pool2, Balances::new_same(pool2_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);

        let (delegation, delegated_anount) = test_data.create_delegation(&mut tf, &mut rng, &pool2);
        let pool2_balance = (pool2_pledge + delegated_anount).unwrap();
        expected_balances.insert(
            BlockHeight::new(4),
            vec![(pool2, Balances::new(pool2_balance, pool2_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);

        let withdraw_amount =
            test_data.withdraw_from_delegation(&mut tf, &mut rng, &pool2, &delegation);
        let pool2_balance = (pool2_balance - withdraw_amount).unwrap();
        expected_balances.insert(
            BlockHeight::new(5),
            vec![(pool2, Balances::new(pool2_balance, pool2_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);

        let added_amount = test_data.add_to_delegation(&mut tf, &mut rng, &pool2, &delegation);
        let pool2_balance = (pool2_balance + added_amount).unwrap();
        expected_balances.insert(
            BlockHeight::new(6),
            vec![(pool2, Balances::new(pool2_balance, pool2_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);

        test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &genesis_pool_id());
        expected_balances.insert(
            BlockHeight::new(7),
            vec![(pool2, Balances::new(pool2_balance, pool2_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);

        test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &pool2);
        let pool2_balance = (pool2_balance + initial_block_reward).unwrap();
        let pool2_pledge = (pool2_pledge + initial_block_reward).unwrap();
        expected_balances.insert(
            BlockHeight::new(8),
            vec![(pool2, Balances::new(pool2_balance, pool2_pledge))],
        );
        check_balances(&tf, &expected_balances, &[pool1, pool2]);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = make_test_framework(&mut rng);
        let mut test_data = TestData::new(&mut tf);

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

            if !did_something && rng.gen_bool(0.5) {
                if let Some(pool_id) = test_data.random_pool_id(&mut rng) {
                    test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &pool_id);
                    did_something = true;
                }
            }

            if !did_something {
                test_data.produce_trivial_block_with_pool(&mut tf, &mut rng, &genesis_pool_id());
            }
        }
    });
}

fn make_test_framework(rng: &mut (impl Rng + CryptoRng)) -> TestFramework {
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
                    .build(),
            },
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).unwrap();
    let genesis = create_custom_genesis_with_stake_pool(
        staking_pk,
        vrf_pk,
        INITIAL_MINT_AMOUNT,
        INITIAL_MINT_AMOUNT, // the pool amount doesn't really matter
    );

    let chain_config = chain::config::Builder::new(ChainType::Regtest)
        .consensus_upgrades(net_upgrades)
        .genesis_custom(genesis)
        .build();

    let target_block_time = chain_config.target_block_spacing();

    let mut tf = TestFramework::builder(rng)
        .with_chain_config(chain_config)
        // Note: PoSBlockBuilder uses the current time as the starting timestamp for PoS mining,
        // so it must always be bigger than the timestamp of the previous block.
        // Though PoSBlockBuilder does advance the current time automatically, it does it after
        // producing a block, so we still need to make sure that the initial time is bigger than
        // the genesis' timestamp.
        .with_initial_time_since_genesis(target_block_time.as_secs())
        .with_chainstate_config(ChainstateConfig::new().with_heavy_checks_enabled(false))
        .build();

    tf.set_genesis_pool_keys(&H256::zero().into(), staking_sk, vrf_sk);

    tf
}

fn genesis_pool_id() -> PoolId {
    H256::zero().into()
}

fn make_block_builder_with_pool<'a>(
    tf: &'a mut TestFramework,
    pool_id: &PoolId,
) -> PoSBlockBuilder<'a> {
    tf.make_pos_block_builder().with_specific_staking_pool(pool_id)
}

fn get_balances_at_heights(
    tf: &TestFramework,
    pool_ids: &[PoolId],
    min_height: Option<u64>,
    max_height: Option<u64>,
) -> BTreeMap<BlockHeight, BTreeMap<PoolId, Balances>> {
    let min_height = BlockHeight::new(min_height.unwrap_or(0));
    let bb_height = tf.best_block_index().block_height();
    let max_height = max_height.map_or(bb_height, BlockHeight::new);

    let balances = tf
        .chainstate
        .get_stake_pool_balances_at_heights(pool_ids, min_height, max_height)
        .unwrap();

    balances
        .iter()
        .map(|(height, pool_to_balances_map)| {
            (
                *height,
                pool_to_balances_map
                    .iter()
                    .map(|(pool_id, balances)| {
                        (
                            *pool_id,
                            Balances::new(balances.total_balance(), balances.staker_balance()),
                        )
                    })
                    .collect::<BTreeMap<_, _>>(),
            )
        })
        .collect::<BTreeMap<_, _>>()
}

fn get_cur_balances(tf: &TestFramework, pool_ids: &[PoolId]) -> BTreeMap<PoolId, Balances> {
    let mut result = BTreeMap::new();

    for pool_id in pool_ids {
        let pool_balance = tf.chainstate.get_stake_pool_balance(*pool_id).unwrap();
        let pool_data = tf.chainstate.get_stake_pool_data(*pool_id).unwrap();

        match (pool_balance, pool_data) {
            (Some(balance), Some(data)) => {
                result.insert(
                    *pool_id,
                    Balances::new(balance, data.staker_balance().unwrap()),
                );
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                panic!("Pool balance presence is inconsistent with pool data's")
            }
        }
    }

    result
}

const INITIAL_MINT_AMOUNT: Amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
const MATURITY_BLOCK_COUNT: BlockCount = BlockCount::new(100);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Balances {
    total_balance: Amount,
    staker_balance: Amount,
}

impl Balances {
    fn new(total_balance: Amount, staker_balance: Amount) -> Self {
        Self {
            total_balance,
            staker_balance,
        }
    }

    fn new_same(balance: Amount) -> Self {
        Self::new(balance, balance)
    }
}

struct TestPoolInfo {
    delegations: BTreeSet<DelegationId>,
}

struct TestData {
    pools: BTreeMap<PoolId, TestPoolInfo>,
    decommissioned_pools: BTreeSet<PoolId>,
    delegations: BTreeMap<DelegationId, /*next_nonce:*/ AccountNonce>,
    expected_balances: BTreeMap<BlockHeight, BTreeMap<PoolId, Balances>>,
    utxo_for_spending: UtxoForSpending,
}

impl TestData {
    fn new(tf: &mut TestFramework) -> Self {
        Self {
            pools: BTreeMap::new(),
            decommissioned_pools: BTreeSet::new(),
            delegations: BTreeMap::new(),
            expected_balances: BTreeMap::new(),
            utxo_for_spending: UtxoForSpending::new(
                UtxoOutPoint::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                INITIAL_MINT_AMOUNT,
            ),
        }
    }

    fn make_new_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (PoolId, Amount) {
        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let pledge =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, staker_key) =
            create_stake_pool_data_with_all_reward_to_staker(rng, pledge, vrf_pk);
        let pool_id = PoolId::from_utxo(self.utxo_for_spending.outpoint());

        let tx_builder = TransactionBuilder::new().add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ));
        let tx =
            self.utxo_for_spending
                .add_input_and_build_tx(tx_builder, pledge, Amount::ZERO, rng);

        let tx_id = tx.transaction().get_id();
        let stake_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 0);
        make_block_builder_with_pool(tf, &genesis_pool_id())
            .add_transaction(tx)
            .build_and_process(rng)
            .unwrap();

        log::debug!(
            "New pool {pool_id} created with pledge {}",
            pledge.into_atoms()
        );

        self.pools.insert(
            pool_id,
            TestPoolInfo {
                delegations: BTreeSet::new(),
            },
        );

        tf.on_pool_created(pool_id, staker_key, vrf_sk, stake_outpoint);

        self.push_new_height(tf).insert(pool_id, Balances::new_same(pledge));

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

        let (_, _, outpoint) = tf.staking_pools.staking_pools().get(pool_id).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(outpoint.clone().into(), empty_witness(rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(staker_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(MATURITY_BLOCK_COUNT.to_int()),
            ))
            .build();
        make_block_builder_with_pool(tf, &genesis_pool_id())
            .add_transaction(tx)
            .build_and_process(rng)
            .unwrap();

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

        let tx1_builder = TransactionBuilder::new()
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                *pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
            ));
        let tx1 = self.utxo_for_spending.add_input_and_build_tx(
            tx1_builder,
            amount_to_delegate,
            Amount::ZERO,
            rng,
        );
        let delegation_id = make_delegation_id(tx1.inputs()).unwrap();
        let tx1_id = tx1.transaction().get_id();
        let transfer_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx1_id), 1);

        let tx2 = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        make_block_builder_with_pool(tf, &genesis_pool_id())
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
            SignedAmount::ZERO,
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
                OutputTimeLock::ForBlockCount(MATURITY_BLOCK_COUNT.to_int()),
            ))
            .build();

        make_block_builder_with_pool(tf, &genesis_pool_id())
            .add_transaction(tx)
            .build_and_process(rng)
            .unwrap();

        log::debug!(
            "Withdrawn {} from delegation {delegation_id} to pool {pool_id}",
            amount_to_withdraw.into_atoms()
        );

        self.push_height_update_expected_balance(
            tf,
            pool_id,
            (-amount_to_withdraw.into_signed().unwrap()).unwrap(),
            SignedAmount::ZERO,
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

        let tx_builder = TransactionBuilder::new()
            .add_output(TxOutput::DelegateStaking(amount_to_add, *delegation_id));
        let tx = self.utxo_for_spending.add_input_and_build_tx(
            tx_builder,
            amount_to_add,
            Amount::ZERO,
            rng,
        );

        make_block_builder_with_pool(tf, &genesis_pool_id())
            .add_transaction(tx)
            .build_and_process(rng)
            .unwrap();

        log::debug!(
            "Added {} to delegation {delegation_id} to pool {pool_id}",
            amount_to_add.into_atoms()
        );

        self.push_height_update_expected_balance(
            tf,
            pool_id,
            amount_to_add.into_signed().unwrap(),
            SignedAmount::ZERO,
        );

        self.assert_balances(tf);

        amount_to_add
    }

    fn produce_trivial_block_with_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
    ) {
        make_block_builder_with_pool(tf, pool_id).build_and_process(rng).unwrap();

        if pool_id == &genesis_pool_id() {
            log::debug!("Trivial block added via genesis pool");

            self.push_new_height(tf);
        } else {
            log::debug!("Trivial block added via pool {pool_id}");

            let reward = tf
                .chainstate
                .get_chain_config()
                .block_subsidy_at_height(&tf.best_block_index().block_height())
                .into_signed()
                .unwrap();
            self.push_height_update_expected_balance(tf, pool_id, reward, reward);
        }

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
        total_balance_change: SignedAmount,
        staker_balance_change: SignedAmount,
    ) {
        let new_height_data = self.push_new_height(tf);
        let cur_balance =
            new_height_data.entry(*pool_id).or_insert(Balances::new_same(Amount::ZERO));
        let new_total_balance = Amount::from_signed(
            (cur_balance.total_balance.into_signed().unwrap() + total_balance_change).unwrap(),
        )
        .unwrap();
        let new_staker_balance = Amount::from_signed(
            (cur_balance.staker_balance.into_signed().unwrap() + staker_balance_change).unwrap(),
        )
        .unwrap();
        *cur_balance = Balances::new(new_total_balance, new_staker_balance);
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

    fn push_new_height(&mut self, tf: &TestFramework) -> &mut BTreeMap<PoolId, Balances> {
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
            expected_balances.retain(|_, pool_to_amount_map| !pool_to_amount_map.is_empty());

            expected_balances
        };

        assert_eq!(actual_balances, expected_balances);
    }
}
