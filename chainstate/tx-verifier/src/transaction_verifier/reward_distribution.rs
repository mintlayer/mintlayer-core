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

use static_assertions::assert_eq_size;
use std::collections::BTreeMap;

use crate::{error::ConnectTransactionError, TransactionSource};

use common::{
    chain::{Block, DelegationId, PoolId},
    primitives::{per_thousand::PerThousand, Amount, Id},
    Uint256,
};
use pos_accounting::{
    AccountingBlockRewardUndo, PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView,
};
use utils::ensure;

use super::pos_accounting_delta_adapter::PoSAccountingDeltaAdapter;

/// Distribute reward among the pool's owner and delegations
pub fn distribute_pos_reward<P: PoSAccountingView>(
    accounting_adapter: &mut PoSAccountingDeltaAdapter<P>,
    block_id: Id<Block>,
    pool_id: PoolId,
    total_reward: Amount,
) -> Result<AccountingBlockRewardUndo, ConnectTransactionError> {
    let pool_data = accounting_adapter
        .accounting_delta()
        .get_pool_data(pool_id)?
        .ok_or(ConnectTransactionError::PoolDataNotFound(pool_id))?;

    let pool_owner_reward = calculate_pool_owner_reward(
        total_reward,
        pool_data.cost_per_block(),
        pool_data.margin_ratio_per_thousand(),
    )
    .ok_or(ConnectTransactionError::PoolOwnerRewardCalculationFailed(
        block_id, pool_id,
    ))?;

    let total_delegations_reward = (total_reward - pool_owner_reward).ok_or(
        ConnectTransactionError::PoolOwnerRewardCannotExceedTotalReward(
            block_id,
            pool_id,
            pool_owner_reward,
            total_reward,
        ),
    )?;

    // Distribute reward among delegators.
    // In some cases this process can yield reward unallocated to delegators. This reward goes to the pool owner.
    let (delegation_undos, unallocated_reward) = if total_delegations_reward > Amount::ZERO {
        match accounting_adapter.accounting_delta().get_pool_delegations_shares(pool_id)? {
            Some(delegation_shares) => {
                let total_delegations_balance =
                    delegation_shares.values().copied().sum::<Option<Amount>>().ok_or(
                        ConnectTransactionError::DelegationsRewardSumFailed(block_id, pool_id),
                    )?;

                if total_delegations_balance > Amount::ZERO {
                    distribute_delegations_pos_reward(
                        accounting_adapter,
                        &delegation_shares,
                        block_id,
                        pool_id,
                        total_delegations_balance,
                        total_delegations_reward,
                    )?
                } else {
                    // If total balance of all delegations is 0 then give the reward to the pool's owner
                    (Vec::new(), total_delegations_reward)
                }
            }
            // If no delegations then give the reward to the pool's owner
            None => (Vec::new(), total_delegations_reward),
        }
    } else {
        // Do nothing if no delegations reward
        (Vec::new(), Amount::ZERO)
    };

    let total_owner_reward = (pool_owner_reward + unallocated_reward)
        .ok_or(ConnectTransactionError::RewardAdditionError(block_id))?;
    let increase_pool_balance_undo = accounting_adapter
        .operations(TransactionSource::Chain(block_id))
        .increase_pool_pledge_amount(pool_id, total_owner_reward)?;

    let undos = delegation_undos
        .into_iter()
        .chain(std::iter::once(increase_pool_balance_undo))
        .collect();

    Ok(AccountingBlockRewardUndo::new(undos))
}

fn calculate_pool_owner_reward(
    total_reward: Amount,
    cost_per_block: Amount,
    mpt: PerThousand,
) -> Option<Amount> {
    let pool_owner_reward = match total_reward - cost_per_block {
        Some(v) => (v * mpt.value().into())
            .and_then(|v| v / 1000)
            .and_then(|v| v + cost_per_block)?,
        // if cost per block > total reward then give the reward to pool owner
        None => total_reward,
    };

    debug_assert!(pool_owner_reward <= total_reward);
    Some(pool_owner_reward)
}

/// The reward is distributed among delegations proportionally to their balance
fn distribute_delegations_pos_reward<P: PoSAccountingView>(
    accounting_adapter: &mut PoSAccountingDeltaAdapter<P>,
    delegation_shares: &BTreeMap<DelegationId, Amount>,
    block_id: Id<Block>,
    pool_id: PoolId,
    total_delegations_balance: Amount,
    total_delegations_reward: Amount,
) -> Result<(Vec<PoSAccountingUndo>, Amount), ConnectTransactionError> {
    let rewards_per_delegation = calculate_rewards_per_delegation(
        delegation_shares,
        pool_id,
        total_delegations_balance,
        total_delegations_reward,
    )?;

    // increase the delegation balances
    let delegation_undos = rewards_per_delegation
        .iter()
        .map(|(delegation_id, reward)| {
            accounting_adapter
                .operations(TransactionSource::Chain(block_id))
                .delegate_staking(*delegation_id, *reward)
                .map_err(ConnectTransactionError::PoSAccountingError)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Due to integer arithmetics there can be a small remainder after all the delegations distributed.
    // This remainder goes to the pool's owner
    let total_delegations_reward_distributed =
        rewards_per_delegation.iter().map(|(_, v)| *v).sum::<Option<Amount>>().ok_or(
            ConnectTransactionError::DelegationsRewardSumFailed(block_id, pool_id),
        )?;

    let delegations_reward_remainder =
        (total_delegations_reward - total_delegations_reward_distributed).ok_or(
            ConnectTransactionError::DistributedDelegationsRewardExceedTotal(
                pool_id,
                block_id,
                total_delegations_reward_distributed,
                total_delegations_reward,
            ),
        )?;
    Ok((delegation_undos, delegations_reward_remainder))
}

fn calculate_rewards_per_delegation(
    delegation_shares: &BTreeMap<DelegationId, Amount>,
    pool_id: PoolId,
    total_delegations_amount: Amount,
    total_delegations_reward_amount: Amount,
) -> Result<Vec<(DelegationId, Amount)>, ConnectTransactionError> {
    // this condition is necessary to ensure that the multiplication of balance and rewards won't overflow;
    // if this is to change, please ensure that the output of the operations below has twice as many bits
    assert_eq_size!(Amount, common::primitives::amount::UnsignedIntType);

    ensure!(
        total_delegations_amount != Amount::ZERO,
        ConnectTransactionError::TotalDelegationBalanceZero(pool_id)
    );

    let total_delegations_balance = Uint256::from_amount(total_delegations_amount);
    let total_delegations_reward = Uint256::from_amount(total_delegations_reward_amount);
    delegation_shares
        .iter()
        .map(
            |(delegation_id, balance_amount)| -> Result<_, ConnectTransactionError> {
                let balance = Uint256::from_amount(*balance_amount);
                let numer = (total_delegations_reward * balance).expect("Source types are smaller");
                let reward = (numer / total_delegations_balance)
                    .ok_or(ConnectTransactionError::TotalDelegationBalanceZero(pool_id))?;
                let reward: common::primitives::amount::UnsignedIntType =
                    reward.try_into().map_err(|_| {
                        ConnectTransactionError::DelegationRewardOverflow(
                            *delegation_id,
                            total_delegations_amount,
                            total_delegations_reward_amount,
                            *balance_amount,
                        )
                    })?;
                Ok((*delegation_id, Amount::from_atoms(reward)))
            },
        )
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        amount_sum,
        chain::{DelegationId, Destination, PoolId},
        primitives::{per_thousand::PerThousand, Amount, H256},
    };
    use crypto::{
        random::Rng,
        vrf::{VRFKeyKind, VRFPrivateKey},
    };
    use pos_accounting::{
        DelegationData, FlushablePoSAccountingView, InMemoryPoSAccounting, PoSAccountingDB,
        PoolData,
    };
    use rstest::rstest;
    use std::collections::BTreeMap;
    use test_utils::random::{make_seedable_rng, Seed};

    fn new_pool_id(v: u64) -> PoolId {
        PoolId::new(H256::from_low_u64_be(v))
    }

    fn new_delegation_id(v: u64) -> DelegationId {
        DelegationId::new(H256::from_low_u64_be(v))
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_pool_owner_reward_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let reward = Amount::from_atoms(rng.gen_range(1..=100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(1..=reward.into_atoms()));
        let cost_per_block_over_reward =
            (reward + Amount::from_atoms(rng.gen_range(1..=100_000_000))).unwrap();
        let mpt = PerThousand::new_from_rng(&mut rng);
        let mpt_zero = PerThousand::new(0).unwrap();
        let mpt_more_than_one = PerThousand::new(rng.gen_range(2..=1000)).unwrap();

        assert!(calculate_pool_owner_reward(Amount::ZERO, Amount::ZERO, mpt_zero).is_some());
        assert!(calculate_pool_owner_reward(Amount::ZERO, Amount::ZERO, mpt).is_some());
        assert!(calculate_pool_owner_reward(reward, Amount::ZERO, mpt_zero).is_some());
        assert!(calculate_pool_owner_reward(reward, Amount::ZERO, mpt).is_some());
        assert!(calculate_pool_owner_reward(reward, Amount::ZERO, mpt_zero).is_some());
        assert!(calculate_pool_owner_reward(reward, cost_per_block, mpt_zero).is_some());
        assert!(calculate_pool_owner_reward(reward, cost_per_block, mpt).is_some());
        // negative amount
        assert_eq!(
            calculate_pool_owner_reward(Amount::ZERO, cost_per_block, mpt_zero),
            Some(Amount::ZERO)
        );
        // cost per block > reward
        assert_eq!(
            calculate_pool_owner_reward(reward, cost_per_block_over_reward, mpt_zero),
            Some(reward)
        );
        // overflow
        assert!(
            calculate_pool_owner_reward(Amount::MAX, cost_per_block, mpt_more_than_one).is_none()
        );

        // arbitrary values
        assert_eq!(
            calculate_pool_owner_reward(
                Amount::from_atoms(100),
                Amount::from_atoms(10),
                PerThousand::new(100).unwrap()
            ),
            Some(Amount::from_atoms(19))
        );
        assert_eq!(
            calculate_pool_owner_reward(
                Amount::from_atoms(1100),
                Amount::from_atoms(100),
                PerThousand::new(100).unwrap()
            ),
            Some(Amount::from_atoms(200))
        );
        assert_eq!(
            calculate_pool_owner_reward(
                Amount::from_atoms(10_000),
                Amount::from_atoms(33),
                PerThousand::new(111).unwrap()
            ),
            Some(Amount::from_atoms(1139))
        );
    }

    // Create 2 pools: pool_a and pool_b.
    // Each pool has 2 delegations with different amounts.
    // Distribute reward to pool_a and check that it was distributed proportionally
    // and that pool_b and its delegations were not affected.
    // Then undo everything and check that original state was restored.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn distribution_basic(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let block_id = Id::new(H256::random_using(&mut rng));

        let pool_id_a = new_pool_id(1);
        let pool_id_b = new_pool_id(2);

        let delegation_a_1 = new_delegation_id(1);
        let delegation_b_1 = new_delegation_id(2);
        let delegation_a_2 = new_delegation_id(3);
        let delegation_b_2 = new_delegation_id(4);

        let pledged_amount = Amount::from_atoms(100);
        let delegation_a_1_amount = Amount::from_atoms(200);
        let delegation_b_1_amount = Amount::from_atoms(200);
        let delegation_a_2_amount = Amount::from_atoms(400);
        let delegation_b_2_amount = Amount::from_atoms(400);

        let reward = Amount::from_atoms(1050);

        let pool_balance_a =
            ((pledged_amount + delegation_a_1_amount).unwrap() + delegation_a_2_amount).unwrap();
        let pool_balance_b =
            ((pledged_amount + delegation_b_1_amount).unwrap() + delegation_b_2_amount).unwrap();

        let delegation_data_a = DelegationData::new(pool_id_a, Destination::AnyoneCanSpend);
        let delegation_data_b = DelegationData::new(pool_id_b, Destination::AnyoneCanSpend);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            vrf_pk.clone(),
            PerThousand::new(100).unwrap(),
            Amount::from_atoms(50),
        );
        let expected_owner_reward = Amount::from_atoms(150);
        let expected_pool_data_a = PoolData::new(
            Destination::AnyoneCanSpend,
            (pledged_amount + expected_owner_reward).unwrap(),
            vrf_pk,
            PerThousand::new(100).unwrap(),
            Amount::from_atoms(50),
        );

        let mut store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id_a, pool_data.clone()), (pool_id_b, pool_data.clone())]),
            BTreeMap::from([(pool_id_a, pool_balance_a), (pool_id_b, pool_balance_b)]),
            BTreeMap::from([
                ((pool_id_a, delegation_a_1), delegation_a_1_amount),
                ((pool_id_b, delegation_b_1), delegation_b_1_amount),
                ((pool_id_a, delegation_a_2), delegation_a_2_amount),
                ((pool_id_b, delegation_b_2), delegation_b_2_amount),
            ]),
            BTreeMap::from_iter([
                (delegation_a_1, delegation_a_1_amount),
                (delegation_b_1, delegation_b_1_amount),
                (delegation_a_2, delegation_a_2_amount),
                (delegation_b_2, delegation_b_2_amount),
            ]),
            BTreeMap::from_iter([
                (delegation_a_1, delegation_data_a.clone()),
                (delegation_a_2, delegation_data_a.clone()),
                (delegation_b_1, delegation_data_b.clone()),
                (delegation_b_2, delegation_data_b.clone()),
            ]),
        );
        let original_store = store.clone();
        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);

        let expected_store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id_a, expected_pool_data_a), (pool_id_b, pool_data)]),
            BTreeMap::from([
                (pool_id_a, (pool_balance_a + reward).unwrap()),
                (pool_id_b, pool_balance_b),
            ]),
            BTreeMap::from([
                (
                    (pool_id_a, delegation_a_1),
                    (delegation_a_1_amount + Amount::from_atoms(300)).unwrap(),
                ),
                ((pool_id_b, delegation_b_1), delegation_b_1_amount),
                (
                    (pool_id_a, delegation_a_2),
                    (delegation_a_2_amount + Amount::from_atoms(600)).unwrap(),
                ),
                ((pool_id_b, delegation_b_2), delegation_b_2_amount),
            ]),
            BTreeMap::from_iter([
                (
                    delegation_a_1,
                    (delegation_a_1_amount + Amount::from_atoms(300)).unwrap(),
                ),
                (delegation_b_1, delegation_b_1_amount),
                (
                    delegation_a_2,
                    (delegation_a_2_amount + Amount::from_atoms(600)).unwrap(),
                ),
                (delegation_b_2, delegation_b_2_amount),
            ]),
            BTreeMap::from_iter([
                (delegation_a_1, delegation_data_a.clone()),
                (delegation_a_2, delegation_data_a),
                (delegation_b_1, delegation_data_b.clone()),
                (delegation_b_2, delegation_data_b),
            ]),
        );

        let all_undos =
            distribute_pos_reward(&mut accounting_adapter, block_id, pool_id_a, reward).unwrap();

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);

        // undo everything
        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);
        all_undos
            .into_inner()
            .into_iter()
            .try_for_each(|u| {
                accounting_adapter.operations(TransactionSource::Chain(block_id)).undo(u)
            })
            .unwrap();

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, original_store);
    }

    // Create a pool with 2 delegations and random balances and reward.
    // Check distribution properties.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn distribution_properties(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let block_id = Id::new(H256::random_using(&mut rng));

        let pool_id = new_pool_id(1);

        let delegation_id_1 = new_delegation_id(1);
        let delegation_id_2 = new_delegation_id(2);

        let original_pledged_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let delegation_1_balance = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let delegation_2_balance = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let total_delegation_shares = (delegation_1_balance + delegation_2_balance).unwrap();

        let reward = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(0..reward.into_atoms()));
        let mpt = PerThousand::new_from_rng(&mut rng);
        let total_delegation_reward =
            (reward - calculate_pool_owner_reward(reward, cost_per_block, mpt).unwrap()).unwrap();

        let original_pool_balance = amount_sum!(
            original_pledged_amount,
            delegation_1_balance,
            delegation_2_balance
        )
        .unwrap();

        let delegation_data = DelegationData::new(pool_id, Destination::AnyoneCanSpend);

        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            original_pledged_amount,
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel).1,
            mpt,
            cost_per_block,
        );

        let store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::from([
                ((pool_id, delegation_id_1), delegation_1_balance),
                ((pool_id, delegation_id_2), delegation_2_balance),
            ]),
            BTreeMap::from_iter([
                (delegation_id_1, delegation_1_balance),
                (delegation_id_2, delegation_2_balance),
            ]),
            BTreeMap::from_iter([
                (delegation_id_1, delegation_data.clone()),
                (delegation_id_2, delegation_data),
            ]),
        );
        let db = PoSAccountingDB::new(&store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        let new_pledge_amount = accounting_adapter
            .accounting_delta()
            .get_pool_data(pool_id)
            .unwrap()
            .unwrap()
            .pledge_amount();

        // check that the whole reward is added to the balance
        let expected_pool_balance = (original_pool_balance + reward).unwrap();
        assert_eq!(
            expected_pool_balance,
            accounting_adapter
                .accounting_delta()
                .get_pool_balance(pool_id)
                .unwrap()
                .unwrap()
        );

        let (consumed_data, _) = accounting_adapter.consume();
        let delegation_1_reward = consumed_data
            .delegation_balances
            .data()
            .get(&delegation_id_1)
            .map(|v| v.into_unsigned().unwrap());
        let delegation_2_reward = consumed_data
            .delegation_balances
            .data()
            .get(&delegation_id_2)
            .map(|v| v.into_unsigned().unwrap());

        // check that owner reward and delegation rewards add up to total reward
        assert_eq!(
            reward,
            amount_sum!(
                (new_pledge_amount - original_pledged_amount).unwrap(),
                delegation_1_reward.unwrap_or(Amount::ZERO),
                delegation_2_reward.unwrap_or(Amount::ZERO)
            )
            .unwrap()
        );

        // the difference between delegations can be so big that the reward can be 0
        if let (Some(delegation_1_reward), Some(delegation_2_reward)) =
            (delegation_1_reward, delegation_2_reward)
        {
            // Due to integer arithmetics there could be a rounding error in the distribution,
            // so straightforward proportion check won't work.
            // At the same time the real reward if calculated with floating point
            // must be in the range of [delegation_reward, delegation_reward + 1).
            // So we can check that balance proportion is in the corresponding reward range
            let check_reward_is_proportional_to_balance = |balance: Amount, reward: Amount| {
                let balance_proportion =
                    total_delegation_shares.into_atoms() / balance.into_atoms();

                let reward_proportion_lower_bound =
                    total_delegation_reward.into_atoms() / (reward.into_atoms() + 1);
                let reward_proportion_upper_bound =
                    total_delegation_reward.into_atoms() / reward.into_atoms();

                // the range is inclusive in case lower bound == upper bound
                assert!(
                    (reward_proportion_lower_bound..=reward_proportion_upper_bound)
                        .contains(&balance_proportion)
                );
            };

            check_reward_is_proportional_to_balance(delegation_1_balance, delegation_1_reward);
            check_reward_is_proportional_to_balance(delegation_2_balance, delegation_2_reward);
        }
    }

    // Check that if delegation is present but its balance is 0 then all the reward goes to pool owner
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn total_delegations_balance_zero(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let block_id = Id::new(H256::random_using(&mut rng));

        let pool_id = new_pool_id(1);
        let delegation_id = new_delegation_id(1);

        let pledged_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let original_pool_balance = pledged_amount;
        let delegation_id_amount = Amount::ZERO;

        let reward = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(0..reward.into_atoms()));
        let mpt = PerThousand::new_from_rng(&mut rng);

        let delegation_data = DelegationData::new(pool_id, Destination::AnyoneCanSpend);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            vrf_pk.clone(),
            mpt,
            cost_per_block,
        );
        let expected_pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            (pledged_amount + reward).unwrap(),
            vrf_pk,
            mpt,
            cost_per_block,
        );

        let mut store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data.clone())]),
        );

        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        let expected_store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, expected_pool_data)]),
            BTreeMap::from([(pool_id, (original_pool_balance + reward).unwrap())]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data)]),
        );

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);
    }

    // Check that pool owner can set its reward to 100% and the reward goes entirely to the owner
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn total_delegations_reward_zero(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let block_id = Id::new(H256::random_using(&mut rng));

        let pool_id = new_pool_id(1);
        let delegation_id = new_delegation_id(1);

        let pledged_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let original_pool_balance = pledged_amount;
        let delegation_id_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));

        let reward = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(0..reward.into_atoms()));
        let mpt = PerThousand::new(1000).unwrap();

        let delegation_data = DelegationData::new(pool_id, Destination::AnyoneCanSpend);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            vrf_pk.clone(),
            mpt,
            cost_per_block,
        );
        let expected_pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            (pledged_amount + reward).unwrap(),
            vrf_pk,
            mpt,
            cost_per_block,
        );

        let mut store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data.clone())]),
        );

        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        let expected_store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, expected_pool_data)]),
            BTreeMap::from([(pool_id, (original_pool_balance + reward).unwrap())]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data)]),
        );

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);
    }

    // Check that if there are no delegations then the whole reward goes to the pool owner
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn no_delegations(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let block_id = Id::new(H256::random_using(&mut rng));
        let pool_id = new_pool_id(1);

        let pledged_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let original_pool_balance = pledged_amount;

        let reward = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(0..reward.into_atoms()));
        let mpt = PerThousand::new_from_rng(&mut rng);

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);
        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            vrf_pk.clone(),
            mpt,
            cost_per_block,
        );
        let expected_pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            (pledged_amount + reward).unwrap(),
            vrf_pk,
            mpt,
            cost_per_block,
        );

        let mut store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        let expected_store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, expected_pool_data)]),
            BTreeMap::from([(pool_id, (original_pool_balance + reward).unwrap())]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);
    }
}
