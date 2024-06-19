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

use chainstate::{BlockSource, ChainstateConfig};
use chainstate_test_framework::{
    create_custom_genesis_with_stake_pool, create_stake_pool_data_with_all_reward_to_staker,
    empty_witness, PoSBlockBuilder, PoolBalances, TestFramework, TransactionBuilder,
    UtxoForSpending,
};
use common::{
    chain::{
        self, config::ChainType, output_value::OutputValue, timelock::OutputTimeLock, AccountNonce,
        AccountOutPoint, AccountSpending, Block, CoinUnit, ConsensusUpgrade, DelegationId,
        Destination, GenBlock, NetUpgrades, OutPointSourceId, PoSChainConfigBuilder, PoolId,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{amount::SignedAmount, Amount, BlockCount, BlockHeight, Id, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use logging::log;
use randomness::{seq::IteratorRandom, CryptoRng, Rng};

pub const INITIAL_MINT_AMOUNT: Amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
pub const GENESIS_POOL_PLEDGE: Amount = Amount::from_atoms(100_000_000 * CoinUnit::ATOMS_PER_COIN);
pub const MATURITY_BLOCK_COUNT: BlockCount = BlockCount::new(100);

#[derive(Clone)]
struct TestPoolInfo {
    delegations: BTreeSet<DelegationId>,
}

#[derive(Clone)]
struct TestDataItem {
    // Pools, not including the genesis pool.
    pools: BTreeMap<PoolId, TestPoolInfo>,
    decommissioned_pools: BTreeSet<PoolId>,
    delegations: BTreeMap<DelegationId, /*next_nonce:*/ AccountNonce>,
    // Expected balances for pools, including the genesis pool.
    expected_balances: BTreeMap<PoolId, PoolBalances>,
    utxo_for_spending: UtxoForSpending,
}

pub trait BalancesMapHolder {
    fn balances_map(&self) -> &BTreeMap<PoolId, PoolBalances>;
}

impl BalancesMapHolder for BTreeMap<PoolId, PoolBalances> {
    fn balances_map(&self) -> &BTreeMap<PoolId, PoolBalances> {
        self
    }
}

impl BalancesMapHolder for TestDataItem {
    fn balances_map(&self) -> &BTreeMap<PoolId, PoolBalances> {
        &self.expected_balances
    }
}

impl TestDataItem {
    fn next_nonce(&mut self, delegation_id: &DelegationId) -> AccountNonce {
        let next_nonce = self.delegations.get_mut(delegation_id).unwrap();
        let result = *next_nonce;
        *next_nonce = next_nonce.increment().unwrap();
        result
    }

    fn update_expected_balance(
        &mut self,
        pool_id: &PoolId,
        total_balance_change: SignedAmount,
        staker_balance_change: SignedAmount,
    ) {
        let cur_balance = self
            .expected_balances
            .entry(*pool_id)
            .or_insert(PoolBalances::new_same(Amount::ZERO));
        let new_total_balance = Amount::from_signed(
            (cur_balance.total_balance.into_signed().unwrap() + total_balance_change).unwrap(),
        )
        .unwrap();
        let new_staker_balance = Amount::from_signed(
            (cur_balance.staker_balance.into_signed().unwrap() + staker_balance_change).unwrap(),
        )
        .unwrap();
        *cur_balance = PoolBalances::new(new_total_balance, new_staker_balance);
    }

    pub fn random_pool_id(&self, rng: &mut impl Rng) -> Option<PoolId> {
        self.pools.keys().choose(rng).cloned()
    }

    pub fn random_pool_and_delegation_id(
        &self,
        rng: &mut impl Rng,
    ) -> Option<(PoolId, DelegationId)> {
        let pool_id = self.random_pool_id(rng)?;
        let delegation_id =
            self.pools.get(&pool_id).unwrap().delegations.iter().choose(rng).copied();

        delegation_id.map(|delegation_id| (pool_id, delegation_id))
    }
}

pub struct TestData {
    data: BTreeMap<Id<GenBlock>, TestDataItem>,
}

impl TestData {
    pub fn new(tf: &mut TestFramework) -> Self {
        let genesis_id: Id<GenBlock> = tf.genesis().get_id().into();

        Self {
            data: BTreeMap::from([(
                genesis_id,
                TestDataItem {
                    pools: BTreeMap::new(),
                    decommissioned_pools: BTreeSet::new(),
                    delegations: BTreeMap::new(),
                    expected_balances: BTreeMap::from([(
                        genesis_pool_id(),
                        PoolBalances::new_same(GENESIS_POOL_PLEDGE),
                    )]),
                    utxo_for_spending: UtxoForSpending::new(
                        UtxoOutPoint::new(
                            OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                            0,
                        ),
                        INITIAL_MINT_AMOUNT,
                    ),
                },
            )]),
        }
    }

    pub fn make_new_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        parent_block_id: Option<Id<GenBlock>>,
    ) -> (Id<Block>, PoolId, Amount) {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let mut data_item = self.data.get(&parent_block_id).unwrap().clone();

        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let pledge =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge..(min_stake_pool_pledge * 10)));
        let (stake_pool_data, staker_key) =
            create_stake_pool_data_with_all_reward_to_staker(rng, pledge, vrf_pk);
        let pool_id = pos_accounting::make_pool_id(data_item.utxo_for_spending.outpoint());

        let tx_builder = TransactionBuilder::new().add_output(TxOutput::CreateStakePool(
            pool_id,
            Box::new(stake_pool_data),
        ));
        let tx = data_item.utxo_for_spending.add_input_and_build_tx(
            tx_builder,
            pledge,
            Amount::ZERO,
            rng,
        );

        let tx_id = tx.transaction().get_id();
        let stake_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx_id), 0);
        let block_id = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(tx)
            .build_and_process_return_block_id(rng)
            .unwrap();

        log::debug!(
            "New pool {pool_id} created with pledge {pledge} in block {block_id}",
            pledge = pledge.into_atoms()
        );

        data_item.pools.insert(
            pool_id,
            TestPoolInfo {
                delegations: BTreeSet::new(),
            },
        );
        self.update_expected_balance_after_mining(
            tf,
            &mut data_item,
            &genesis_pool_id(),
            &parent_block_id,
        );

        tf.on_pool_created(
            pool_id,
            staker_key,
            vrf_sk,
            stake_outpoint,
            &block_id.into(),
        );

        data_item.expected_balances.insert(pool_id, PoolBalances::new_same(pledge));
        self.data.insert(block_id.into(), data_item);

        (block_id, pool_id, pledge)
    }

    pub fn decommission_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        parent_block_id: Option<Id<GenBlock>>,
    ) -> Id<Block> {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let mut data_item = self.data.get(&parent_block_id).unwrap().clone();

        let info = data_item.pools.remove(pool_id).unwrap();
        let staker_balance = data_item.expected_balances.get(pool_id).unwrap().staker_balance;

        let (_, _, outpoint, _) = tf
            .staking_pools
            .staking_pools_for_base_block(&parent_block_id)
            .staking_pools()
            .get(pool_id)
            .unwrap();

        let tx = TransactionBuilder::new()
            .add_input(outpoint.clone().into(), empty_witness(rng))
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(staker_balance),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(MATURITY_BLOCK_COUNT.to_int()),
            ))
            .build();
        let block_id = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(tx)
            .build_and_process_return_block_id(rng)
            .unwrap();

        log::debug!("Pool {pool_id} decommissioned in block {block_id}");

        for delegation_id in info.delegations {
            data_item.delegations.remove(&delegation_id);
        }

        data_item.decommissioned_pools.insert(*pool_id);
        data_item.expected_balances.remove(pool_id);
        self.update_expected_balance_after_mining(
            tf,
            &mut data_item,
            &genesis_pool_id(),
            &parent_block_id,
        );
        self.data.insert(block_id.into(), data_item);

        block_id
    }

    pub fn create_delegation(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        parent_block_id: Option<Id<GenBlock>>,
    ) -> (Id<Block>, DelegationId, Amount) {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let mut data_item = self.data.get(&parent_block_id).unwrap().clone();

        let min_stake_pool_pledge =
            tf.chainstate.get_chain_config().min_stake_pool_pledge().into_atoms();
        let amount_to_delegate =
            Amount::from_atoms(rng.gen_range(min_stake_pool_pledge / 2..min_stake_pool_pledge * 2));

        let delegation_id =
            pos_accounting::make_delegation_id(data_item.utxo_for_spending.outpoint());
        let tx1_builder = TransactionBuilder::new()
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                *pool_id,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(amount_to_delegate),
                Destination::AnyoneCanSpend,
            ));
        let tx1 = data_item.utxo_for_spending.add_input_and_build_tx(
            tx1_builder,
            amount_to_delegate,
            Amount::ZERO,
            rng,
        );
        let tx1_id = tx1.transaction().get_id();
        let transfer_outpoint = UtxoOutPoint::new(OutPointSourceId::Transaction(tx1_id), 1);

        let tx2 = TransactionBuilder::new()
            .add_input(transfer_outpoint.into(), empty_witness(rng))
            .add_output(TxOutput::DelegateStaking(amount_to_delegate, delegation_id))
            .build();

        let block_id = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(tx1)
            .add_transaction(tx2)
            .build_and_process_return_block_id(rng)
            .unwrap();

        log::debug!(
            "Delegation {delegation_id} to pool {pool_id} created in block {block_id}, amount = {}",
            amount_to_delegate.into_atoms()
        );

        data_item.pools.get_mut(pool_id).unwrap().delegations.insert(delegation_id);
        data_item.delegations.insert(delegation_id, AccountNonce::new(0));
        data_item.update_expected_balance(
            pool_id,
            amount_to_delegate.into_signed().unwrap(),
            SignedAmount::ZERO,
        );
        self.update_expected_balance_after_mining(
            tf,
            &mut data_item,
            &genesis_pool_id(),
            &parent_block_id,
        );
        self.data.insert(block_id.into(), data_item);

        (block_id, delegation_id, amount_to_delegate)
    }

    pub fn withdraw_from_delegation(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        delegation_id: &DelegationId,
        parent_block_id: Option<Id<GenBlock>>,
    ) -> (Id<Block>, Amount) {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let mut data_item = self.data.get(&parent_block_id).unwrap().clone();

        let amount_to_withdraw = Amount::from_atoms(rng.gen_range(1000..10_000));

        let nonce = data_item.next_nonce(delegation_id);

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

        let block_id = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(tx)
            .build_and_process_return_block_id(rng)
            .unwrap();

        log::debug!(
            "Withdrawn {} from delegation {delegation_id} to pool {pool_id} in block {block_id}",
            amount_to_withdraw.into_atoms()
        );

        data_item.update_expected_balance(
            pool_id,
            (-amount_to_withdraw.into_signed().unwrap()).unwrap(),
            SignedAmount::ZERO,
        );
        self.update_expected_balance_after_mining(
            tf,
            &mut data_item,
            &genesis_pool_id(),
            &parent_block_id,
        );
        self.data.insert(block_id.into(), data_item);

        (block_id, amount_to_withdraw)
    }

    pub fn add_to_delegation(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        delegation_id: &DelegationId,
        parent_block_id: Option<Id<GenBlock>>,
    ) -> (Id<Block>, Amount) {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let mut data_item = self.data.get(&parent_block_id).unwrap().clone();

        let amount_to_add = Amount::from_atoms(rng.gen_range(1000..10_000));

        let tx_builder = TransactionBuilder::new()
            .add_output(TxOutput::DelegateStaking(amount_to_add, *delegation_id));
        let tx = data_item.utxo_for_spending.add_input_and_build_tx(
            tx_builder,
            amount_to_add,
            Amount::ZERO,
            rng,
        );

        let block_id = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(tx)
            .build_and_process_return_block_id(rng)
            .unwrap();

        log::debug!(
            "Added {} to delegation {delegation_id} to pool {pool_id} in block {block_id}",
            amount_to_add.into_atoms()
        );

        data_item.update_expected_balance(
            pool_id,
            amount_to_add.into_signed().unwrap(),
            SignedAmount::ZERO,
        );
        self.update_expected_balance_after_mining(
            tf,
            &mut data_item,
            &genesis_pool_id(),
            &parent_block_id,
        );
        self.data.insert(block_id.into(), data_item);

        (block_id, amount_to_add)
    }

    pub fn produce_trivial_block_with_pool(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        pool_id: &PoolId,
        parent_block_id: Option<Id<GenBlock>>,
    ) -> Id<Block> {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let mut data_item = self.data.get(&parent_block_id).unwrap().clone();

        let block_id = self
            .make_block_builder(tf, pool_id, &parent_block_id)
            .build_and_process_return_block_id(rng)
            .unwrap();

        if pool_id == &genesis_pool_id() {
            log::debug!("Trivial block {block_id} added via genesis pool");
        } else {
            log::debug!("Trivial block {block_id} added via pool {pool_id}");
        }

        self.update_expected_balance_after_mining(tf, &mut data_item, pool_id, &parent_block_id);
        self.data.insert(block_id.into(), data_item);

        block_id
    }

    fn update_expected_balance_after_mining(
        &self,
        tf: &TestFramework,
        data_item: &mut TestDataItem,
        pool_id: &PoolId,
        parent_block_id: &Id<GenBlock>,
    ) {
        let reward = tf
            .chainstate
            .get_chain_config()
            .block_subsidy_at_height(
                &tf.gen_block_index(parent_block_id).block_height().next_height(),
            )
            .into_signed()
            .unwrap();
        data_item.update_expected_balance(pool_id, reward, reward);
    }

    pub fn produce_bad_block(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        parent_block_id: Option<Id<GenBlock>>,
    ) -> Id<Block> {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let bad_tx = TransactionBuilder::new().build();
        let block = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(bad_tx)
            .build(rng);
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap_err();

        block_id
    }

    /// Produce a block that will pass the "check block" stage but fail during reorg.
    pub fn produce_seemingly_ok_block(
        &mut self,
        tf: &mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        parent_block_id: Option<Id<GenBlock>>,
    ) -> Id<Block> {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        let genesis_id = tf.genesis().get_id().into();
        assert!(parent_block_id != genesis_id);

        let bad_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id), 0),
                empty_witness(rng),
            )
            .add_output(TxOutput::Burn(OutputValue::Coin(INITIAL_MINT_AMOUNT)))
            .build();
        let block = self
            .make_block_builder(tf, &genesis_pool_id(), &parent_block_id)
            .add_transaction(bad_tx)
            .build(rng);
        let block_id = block.get_id();

        tf.process_block(block, BlockSource::Local).unwrap();

        block_id
    }

    fn make_block_builder<'a>(
        &self,
        tf: &'a mut TestFramework,
        pool_id: &PoolId,
        parent_block_id: &Id<GenBlock>,
    ) -> PoSBlockBuilder<'a> {
        let genesis_id: Id<GenBlock> = tf.genesis().get_id().into();

        let pool_balances = if *parent_block_id == genesis_id {
            PoolBalances::new_same(GENESIS_POOL_PLEDGE)
        } else {
            *self.data.get(parent_block_id).unwrap().expected_balances.get(pool_id).unwrap()
        };

        tf.make_pos_block_builder()
            .with_parent(*parent_block_id)
            // Note that the actual values don't matter much here (as long as they are consistent),
            // because the consensus has trivial difficulty.
            // But if the balances are not specified explicitly, the block builder will try obtaining
            // them from the tip, which may fail if the pool is not present at the tip.
            .with_specific_staking_pool(pool_id)
            .with_staking_pool_balances(pool_balances)
    }

    pub fn random_pool_id(
        &self,
        tf: &TestFramework,
        parent_block_id: Option<Id<GenBlock>>,
        rng: &mut impl Rng,
    ) -> Option<PoolId> {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        self.data.get(&parent_block_id).unwrap().random_pool_id(rng)
    }

    pub fn random_pool_and_delegation_id(
        &self,
        tf: &TestFramework,
        parent_block_id: Option<Id<GenBlock>>,
        rng: &mut impl Rng,
    ) -> Option<(PoolId, DelegationId)> {
        let parent_block_id = parent_block_id.unwrap_or_else(|| tf.best_block_id());
        self.data.get(&parent_block_id).unwrap().random_pool_and_delegation_id(rng)
    }

    pub fn collect_all_pool_ids(&self) -> Vec<PoolId> {
        self.data
            .iter()
            .flat_map(|(_, data_item)| {
                data_item.pools.keys().chain(data_item.decommissioned_pools.iter()).copied()
            })
            .chain(std::iter::once(genesis_pool_id()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    }

    pub fn expected_balances(&self) -> &BTreeMap<Id<GenBlock>, impl BalancesMapHolder> {
        &self.data
    }
}

pub fn make_test_framework(rng: &mut (impl Rng + CryptoRng)) -> TestFramework {
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
        GENESIS_POOL_PLEDGE,
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

pub fn genesis_pool_id() -> PoolId {
    H256::zero().into()
}
