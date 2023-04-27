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

use std::collections::BTreeMap;

use crate::{error::ConnectTransactionError, TransactionSource};

use common::{
    chain::{Block, DelegationId, PoolId},
    primitives::{Amount, Id},
    Uint256,
};
use pos_accounting::{
    AccountingBlockRewardUndo, PoSAccountingOperations, PoSAccountingUndo, PoSAccountingView,
};

use super::accounting_delta_adapter::PoSAccountingDeltaAdapter;

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

    let total_staker_reward = (total_reward - pool_data.cost_per_block())
        .and_then(|v| v * pool_data.margin_ratio_per_thousand().value().into())
        .and_then(|v| v / 1000)
        .and_then(|v| v + pool_data.cost_per_block())
        .ok_or(ConnectTransactionError::StakerRewardCalculationFailed(
            block_id, pool_id,
        ))?;

    let increase_pool_balance_undo = accounting_adapter
        .operations(TransactionSource::Chain(block_id))
        .increase_pool_balance(pool_id, total_staker_reward)?;

    let total_delegations_reward = (total_reward - total_staker_reward).ok_or(
        ConnectTransactionError::StakerRewardCannotExceedTotalReward(
            block_id,
            pool_id,
            total_staker_reward,
            total_reward,
        ),
    )?;

    let delegation_undos = if total_delegations_reward != Amount::ZERO {
        distribute_delegations_pos_reward(
            accounting_adapter,
            block_id,
            pool_id,
            total_delegations_reward,
        )?
    } else {
        None
    };

    let undos = delegation_undos
        .unwrap_or_default()
        .into_iter()
        .chain(vec![increase_pool_balance_undo].into_iter())
        .collect();

    Ok(AccountingBlockRewardUndo::new(undos))
}

/// The reward is distributed among delegations proportionally to their balance
fn distribute_delegations_pos_reward<P: PoSAccountingView>(
    accounting_adapter: &mut PoSAccountingDeltaAdapter<P>,
    block_id: Id<Block>,
    pool_id: PoolId,
    total_delegations_reward: Amount,
) -> Result<Option<Vec<PoSAccountingUndo>>, ConnectTransactionError> {
    accounting_adapter
        .accounting_delta()
        .get_pool_delegations_shares(pool_id)?
        .map(|delegation_shares| {
            let total_delegations_balance =
                delegation_shares.values().try_fold(Amount::ZERO, |acc, v| {
                    (acc + *v).ok_or(ConnectTransactionError::DelegationsRewardSumFailed(
                        block_id, pool_id,
                    ))
                })?;

            if total_delegations_balance != Amount::ZERO {
                let rewards_per_delegation = calculate_rewards_per_delegation(
                    &delegation_shares,
                    block_id,
                    total_delegations_balance,
                    total_delegations_reward,
                )?;

                let distribute_remainder_undo = distribute_delegations_reward_remainder(
                    accounting_adapter,
                    block_id,
                    pool_id,
                    total_delegations_reward,
                    &rewards_per_delegation,
                )?;

                let delegation_undos = rewards_per_delegation
                    .iter()
                    .map(|(delegation_id, reward)| {
                        accounting_adapter
                            .operations(TransactionSource::Chain(block_id))
                            .delegate_staking(*delegation_id, Amount::from_atoms(*reward))
                            .map_err(ConnectTransactionError::PoSAccountingError)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(distribute_remainder_undo
                    .unwrap_or_default()
                    .into_iter()
                    .chain(delegation_undos.into_iter())
                    .collect())
            } else {
                // if total balance of all delegations is 0 then give the reward to the pool's owner
                let increase_pool_balance_undo = accounting_adapter
                    .operations(TransactionSource::Chain(block_id))
                    .increase_pool_balance(pool_id, total_delegations_reward)?;
                Ok(vec![increase_pool_balance_undo])
            }
        })
        .transpose()
}

fn calculate_rewards_per_delegation(
    delegation_shares: &BTreeMap<DelegationId, Amount>,
    block_id: Id<Block>,
    total_delegations_balance: Amount,
    total_delegations_reward: Amount,
) -> Result<Vec<(DelegationId, u128)>, ConnectTransactionError> {
    let total_delegations_balance = Uint256::from_amount(total_delegations_balance);
    let total_delegations_reward = Uint256::from_amount(total_delegations_reward);
    delegation_shares
        .iter()
        .map(
            |(delegation_id, balance)| -> Result<_, ConnectTransactionError> {
                let balance = Uint256::from_amount(*balance);
                let reward = (total_delegations_reward * balance) / total_delegations_balance;
                let reward: u128 = reward.try_into().map_err(|_| {
                    ConnectTransactionError::DelegationRewardOverflow(*delegation_id, block_id)
                })?;
                Ok((*delegation_id, reward))
            },
        )
        .collect::<Result<Vec<_>, _>>()
}

/// Due to integer arithmetics there can be a small remainder after all the delegations distributed.
/// This remainder goes to the pool's owner
fn distribute_delegations_reward_remainder<P: PoSAccountingView>(
    accounting_adapter: &mut PoSAccountingDeltaAdapter<P>,
    block_id: Id<Block>,
    pool_id: PoolId,
    total_delegations_reward: Amount,
    rewards_per_delegation: &[(DelegationId, u128)],
) -> Result<Option<Vec<PoSAccountingUndo>>, ConnectTransactionError> {
    let total_delegations_reward_distributed = rewards_per_delegation
        .iter()
        .map(|(_, v)| Amount::from_atoms(*v))
        .try_fold(Amount::ZERO, |acc, v| {
            (acc + v).ok_or(ConnectTransactionError::DelegationsRewardSumFailed(
                block_id, pool_id,
            ))
        })?;

    let delegations_reward_remainder =
        (total_delegations_reward - total_delegations_reward_distributed).ok_or(
            ConnectTransactionError::DistributedDelegationsRewardExceedTotal(
                pool_id,
                block_id,
                total_delegations_reward_distributed,
                total_delegations_reward,
            ),
        )?;

    if delegations_reward_remainder != Amount::ZERO {
        debug_assert!(delegations_reward_remainder == Amount::from_atoms(1));
        let increase_balance_undo = accounting_adapter
            .operations(TransactionSource::Chain(block_id))
            .increase_pool_balance(pool_id, delegations_reward_remainder)?;
        Ok(Some(vec![increase_balance_undo]))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
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

        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel).1,
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
            BTreeMap::from([(pool_id_a, pool_data.clone()), (pool_id_b, pool_data)]),
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

        let pledged_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let delegation_id_1_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let delegation_id_2_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));

        let reward = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(0..reward.into_atoms()));
        let mpt = PerThousand::new(rng.gen_range(0..=1000)).unwrap();

        let original_pool_balance =
            ((pledged_amount + delegation_id_1_amount).unwrap() + delegation_id_2_amount).unwrap();

        let delegation_data = DelegationData::new(pool_id, Destination::AnyoneCanSpend);

        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel).1,
            mpt,
            cost_per_block,
        );

        let store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::from([
                ((pool_id, delegation_id_1), delegation_id_1_amount),
                ((pool_id, delegation_id_2), delegation_id_2_amount),
            ]),
            BTreeMap::from_iter([
                (delegation_id_1, delegation_id_1_amount),
                (delegation_id_2, delegation_id_2_amount),
            ]),
            BTreeMap::from_iter([
                (delegation_id_1, delegation_data.clone()),
                (delegation_id_2, delegation_data),
            ]),
        );
        let db = PoSAccountingDB::new(&store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        // check that whole reward is added to the balance
        let expected_pool_balance = (original_pool_balance + reward).unwrap();
        assert_eq!(
            expected_pool_balance,
            accounting_adapter
                .accounting_delta()
                .get_pool_balance(pool_id)
                .unwrap()
                .unwrap()
        );

        // check that that delegation's reward is proportional to their balances
        let (consumed_data, _) = accounting_adapter.consume();
        let delegation_1_reward = consumed_data.delegation_balances.data().get(&delegation_id_1);
        let delegation_2_reward = consumed_data.delegation_balances.data().get(&delegation_id_2);

        // the difference between delegations can be so big that the reward can be 0
        if let (Some(delegation_1_reward), Some(delegation_2_reward)) =
            (delegation_1_reward, delegation_2_reward)
        {
            assert_eq!(
                delegation_1_reward.into_unsigned().unwrap().into_atoms()
                    / delegation_2_reward.into_unsigned().unwrap().into_atoms(),
                delegation_id_1_amount.into_atoms() / delegation_id_2_amount.into_atoms()
            );
        }
    }

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
        let mpt = PerThousand::new(rng.gen_range(0..1000)).unwrap();

        let delegation_data = DelegationData::new(pool_id, Destination::AnyoneCanSpend);

        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel).1,
            mpt,
            cost_per_block,
        );

        let mut store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data.clone())]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data.clone())]),
        );

        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        let expected_store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, (original_pool_balance + reward).unwrap())]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data)]),
        );

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);
    }

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

        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel).1,
            mpt,
            cost_per_block,
        );

        let mut store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data.clone())]),
            BTreeMap::from([(pool_id, original_pool_balance)]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data.clone())]),
        );

        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);

        distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward).unwrap();

        let expected_store = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, (original_pool_balance + reward).unwrap())]),
            BTreeMap::from([((pool_id, delegation_id), delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_id_amount)]),
            BTreeMap::from_iter([(delegation_id, delegation_data)]),
        );

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);
    }
}
