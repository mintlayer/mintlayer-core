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

use common::{
    amount_sum,
    chain::{Block, DelegationId, PoolId, RewardDistributionVersion},
    primitives::{
        amount::UnsignedIntType as AmountUIntType, per_thousand::PerThousand, Amount, Id,
    },
    Uint256,
};
use pos_accounting::{PoSAccountingOperations, PoSAccountingView};
use thiserror::Error;
use utils::ensure;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum RewardDistributionError {
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),

    #[error("Balance of pool {0} is zero")]
    InvariantPoolBalanceIsZero(PoolId),
    #[error("In pool {0} staker balance {1:?} is greater than pool balance {2:?}")]
    InvariantStakerBalanceGreaterThanPoolBalance(PoolId, Amount, Amount),

    #[error("Block reward addition error for block {0}")]
    RewardAdditionError(Id<Block>),
    #[error("Total balance of delegations in pool {0} is zero")]
    TotalDelegationBalanceZero(PoolId),
    #[error("Data of pool {0} not found")]
    PoolDataNotFound(PoolId),
    #[error("Balance of pool {0} not found")]
    PoolBalanceNotFound(PoolId),
    #[error("Failed to calculate reward for block {0} for staker of the pool {1}")]
    StakerRewardCalculationFailed(Id<Block>, PoolId),
    #[error(
        "Reward in block {0} for the pool {1} staker which is {2:?} cannot be bigger than total reward {3:?}"
    )]
    StakerRewardCannotExceedTotalReward(Id<Block>, PoolId, Amount, Amount),
    #[error("Actually distributed delegation rewards {0} for pool {1} in block {2:?} is bigger then total delegations reward {3:?}")]
    DistributedDelegationsRewardExceedTotal(PoolId, Id<Block>, Amount, Amount),
    #[error("Reward for delegation {0} overflowed: {1:?}*{2:?}/{3:?}")]
    DelegationRewardOverflow(DelegationId, Amount, Amount, Amount),
    #[error("Failed to sum block {0} reward for pool {1} delegations")]
    DelegationsRewardSumFailed(Id<Block>, PoolId),
    #[error("Reward for staker {0} overflowed: {1:?}+{2:?}+{3:?}")]
    StakerRewardOverflow(PoolId, Amount, Amount, Amount),
}

/// Distribute reward among the staker and delegations
pub fn distribute_pos_reward<
    U,
    P: PoSAccountingView<Error = pos_accounting::Error> + PoSAccountingOperations<U>,
>(
    accounting_adapter: &mut P,
    block_id: Id<Block>,
    pool_id: PoolId,
    total_reward: Amount,
    reward_distribution_version: RewardDistributionVersion,
) -> Result<Vec<U>, RewardDistributionError> {
    let pool_data = accounting_adapter
        .get_pool_data(pool_id)?
        .ok_or(RewardDistributionError::PoolDataNotFound(pool_id))?;
    let pool_balance = accounting_adapter
        .get_pool_balance(pool_id)?
        .ok_or(RewardDistributionError::PoolBalanceNotFound(pool_id))?;

    let staker_reward = match reward_distribution_version {
        RewardDistributionVersion::V0 => calculate_staker_reward_v0(
            total_reward,
            pool_data.cost_per_block(),
            pool_data.margin_ratio_per_thousand(),
        )
        .ok_or(RewardDistributionError::StakerRewardCalculationFailed(
            block_id, pool_id,
        ))?,
        RewardDistributionVersion::V1 => calculate_staker_reward_v1(
            total_reward,
            pool_balance,
            pool_data.staker_balance()?,
            pool_data.cost_per_block(),
            pool_data.margin_ratio_per_thousand(),
            pool_id,
        )?,
    };

    let total_delegations_reward = (total_reward - staker_reward).ok_or(
        RewardDistributionError::StakerRewardCannotExceedTotalReward(
            block_id,
            pool_id,
            staker_reward,
            total_reward,
        ),
    )?;

    // Distribute reward among delegators.
    // In some cases this process can yield reward unallocated to delegators. This reward goes to the staker.
    let (delegation_undos, unallocated_reward) = if total_delegations_reward > Amount::ZERO {
        match accounting_adapter.get_pool_delegations_shares(pool_id)? {
            Some(delegation_shares) => {
                let total_delegations_balance =
                    delegation_shares.values().copied().sum::<Option<Amount>>().ok_or(
                        RewardDistributionError::DelegationsRewardSumFailed(block_id, pool_id),
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
                    // If total balance of all delegations is 0 then give the reward to the staker
                    (Vec::new(), total_delegations_reward)
                }
            }
            // If no delegations then give the reward to the staker
            None => (Vec::new(), total_delegations_reward),
        }
    } else {
        // Do nothing if no delegations reward
        (Vec::new(), Amount::ZERO)
    };

    let total_staker_reward = (staker_reward + unallocated_reward)
        .ok_or(RewardDistributionError::RewardAdditionError(block_id))?;
    let increase_pool_balance_undo =
        accounting_adapter.increase_staker_rewards(pool_id, total_staker_reward)?;

    let undos = delegation_undos
        .into_iter()
        .chain(std::iter::once(increase_pool_balance_undo))
        .collect();

    Ok(undos)
}

fn calculate_staker_reward_v0(
    total_reward: Amount,
    cost_per_block: Amount,
    mpt: PerThousand,
) -> Option<Amount> {
    let staker_reward = match total_reward - cost_per_block {
        Some(to_distribute) => (to_distribute * mpt.value().into())
            .and_then(|v| v / mpt.denominator().into())
            .and_then(|v| v + cost_per_block)?,
        // if cost per block > total reward then give the reward to staker
        None => total_reward,
    };

    Some(staker_reward)
}

fn calculate_staker_reward_v1(
    total_reward: Amount,
    pool_balance: Amount,
    staker_balance: Amount,
    cost_per_block: Amount,
    mpt: PerThousand,
    pool_id: PoolId,
) -> Result<Amount, RewardDistributionError> {
    ensure!(
        staker_balance <= pool_balance,
        RewardDistributionError::InvariantStakerBalanceGreaterThanPoolBalance(
            pool_id,
            staker_balance,
            pool_balance
        )
    );

    ensure!(
        pool_balance > Amount::ZERO,
        RewardDistributionError::InvariantPoolBalanceIsZero(pool_id)
    );

    let staker_reward = match total_reward - cost_per_block {
        Some(to_distribute) => {
            let pool_balance = Uint256::from_amount(pool_balance);
            let staker_balance = Uint256::from_amount(staker_balance);
            let numer = (Uint256::from_amount(to_distribute) * staker_balance)
                .expect("Source types are smaller");
            let pro_rata_staker_reward = (numer / pool_balance).expect("cannot be 0");
            let pro_rata_staker_reward: AmountUIntType = pro_rata_staker_reward
                .try_into()
                .expect("Cannot be greater than total_reward type");
            let pro_rata_staker_reward = Amount::from_atoms(pro_rata_staker_reward);

            let delegators_reward = (to_distribute - pro_rata_staker_reward)
                .expect("Cannot be greater than total reward");
            let delegators_reward = Uint256::from_amount(delegators_reward);

            let margin_reward: AmountUIntType = (delegators_reward
                * Uint256::from_u64(mpt.value() as u64))
            .and_then(|v| v / Uint256::from_u64(mpt.denominator() as u64))
            .expect("Source types are smaller")
            .try_into()
            .expect("Cannot overflow");

            amount_sum!(
                Amount::from_atoms(margin_reward),
                pro_rata_staker_reward,
                cost_per_block
            )
            .ok_or(RewardDistributionError::StakerRewardOverflow(
                pool_id,
                Amount::from_atoms(margin_reward),
                pro_rata_staker_reward,
                cost_per_block,
            ))?
        }
        // if cost per block > total reward then give the reward to staker
        None => total_reward,
    };

    Ok(staker_reward)
}

/// The reward is distributed among delegations proportionally to their balance
fn distribute_delegations_pos_reward<U, P: PoSAccountingView + PoSAccountingOperations<U>>(
    accounting_adapter: &mut P,
    delegation_shares: &BTreeMap<DelegationId, Amount>,
    block_id: Id<Block>,
    pool_id: PoolId,
    total_delegations_balance: Amount,
    total_delegations_reward: Amount,
) -> Result<(Vec<U>, Amount), RewardDistributionError> {
    let rewards_per_delegation = calculate_rewards_per_delegation(
        delegation_shares.iter(),
        pool_id,
        total_delegations_balance,
        total_delegations_reward,
    )?;

    // increase the delegation balances
    let delegation_undos = rewards_per_delegation
        .iter()
        .map(|(delegation_id, reward)| {
            accounting_adapter
                .delegate_staking(*delegation_id, *reward)
                .map_err(RewardDistributionError::PoSAccountingError)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Due to integer arithmetics there can be a small remainder after all the delegations distributed.
    // This remainder goes to the staker
    let total_delegations_reward_distributed =
        rewards_per_delegation.iter().map(|(_, v)| *v).sum::<Option<Amount>>().ok_or(
            RewardDistributionError::DelegationsRewardSumFailed(block_id, pool_id),
        )?;

    let delegations_reward_remainder =
        (total_delegations_reward - total_delegations_reward_distributed).ok_or(
            RewardDistributionError::DistributedDelegationsRewardExceedTotal(
                pool_id,
                block_id,
                total_delegations_reward_distributed,
                total_delegations_reward,
            ),
        )?;
    Ok((delegation_undos, delegations_reward_remainder))
}

fn calculate_rewards_per_delegation<'a, I: Iterator<Item = (&'a DelegationId, &'a Amount)>>(
    delegation_shares: I,
    pool_id: PoolId,
    total_delegations_amount: Amount,
    total_delegations_reward_amount: Amount,
) -> Result<Vec<(DelegationId, Amount)>, RewardDistributionError> {
    // this condition is necessary to ensure that the multiplication of balance and rewards won't overflow;
    // if this is to change, please ensure that the output of the operations below has twice as many bits
    assert_eq_size!(Amount, common::primitives::amount::UnsignedIntType);

    ensure!(
        total_delegations_amount != Amount::ZERO,
        RewardDistributionError::TotalDelegationBalanceZero(pool_id)
    );

    let total_delegations_balance = Uint256::from_amount(total_delegations_amount);
    let total_delegations_reward = Uint256::from_amount(total_delegations_reward_amount);
    delegation_shares
        .into_iter()
        .filter(|(_, balance_amount)| **balance_amount > Amount::ZERO)
        .map(
            |(delegation_id, balance_amount)| -> Result<_, RewardDistributionError> {
                let balance = Uint256::from_amount(*balance_amount);
                let numer = (total_delegations_reward * balance).expect("Source types are smaller");
                let reward = (numer / total_delegations_balance)
                    .ok_or(RewardDistributionError::TotalDelegationBalanceZero(pool_id))?;
                let reward: AmountUIntType = reward.try_into().map_err(|_| {
                    RewardDistributionError::DelegationRewardOverflow(
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
    use crate::{
        transaction_verifier::pos_accounting_delta_adapter::PoSAccountingDeltaAdapter,
        TransactionSource,
    };

    use super::*;
    use common::{
        amount_sum,
        chain::{DelegationId, Destination, PoolId},
        primitives::{per_thousand::PerThousand, Amount, H256},
    };
    use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
    use pos_accounting::{
        DelegationData, FlushablePoSAccountingView, InMemoryPoSAccounting, PoSAccountingDB,
        PoolData,
    };
    use randomness::Rng;
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
    fn calculate_staker_reward_test_v0(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let reward = Amount::from_atoms(rng.gen_range(1..=100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(1..=reward.into_atoms()));
        let cost_per_block_over_reward =
            (reward + Amount::from_atoms(rng.gen_range(1..=100_000_000))).unwrap();
        let mpt = PerThousand::new_from_rng(&mut rng);
        let mpt_zero = PerThousand::new(0).unwrap();
        let mpt_more_than_one = PerThousand::new(rng.gen_range(2..=1000)).unwrap();

        assert!(calculate_staker_reward_v0(Amount::ZERO, Amount::ZERO, mpt_zero).is_some());
        assert!(calculate_staker_reward_v0(Amount::ZERO, Amount::ZERO, mpt).is_some());
        assert!(calculate_staker_reward_v0(reward, Amount::ZERO, mpt_zero).is_some());
        assert!(calculate_staker_reward_v0(reward, Amount::ZERO, mpt).is_some());
        assert!(calculate_staker_reward_v0(reward, Amount::ZERO, mpt_zero).is_some());
        assert!(calculate_staker_reward_v0(reward, cost_per_block, mpt_zero).is_some());
        assert!(calculate_staker_reward_v0(reward, cost_per_block, mpt).is_some());
        // negative amount
        assert_eq!(
            calculate_staker_reward_v0(Amount::ZERO, cost_per_block, mpt_zero),
            Some(Amount::ZERO)
        );
        // cost per block > reward
        assert_eq!(
            calculate_staker_reward_v0(reward, cost_per_block_over_reward, mpt_zero),
            Some(reward)
        );
        // overflow
        assert!(
            calculate_staker_reward_v0(Amount::MAX, cost_per_block, mpt_more_than_one).is_none()
        );

        // arbitrary values
        assert_eq!(
            calculate_staker_reward_v0(
                Amount::from_atoms(100),
                Amount::from_atoms(10),
                PerThousand::new(100).unwrap()
            ),
            Some(Amount::from_atoms(19))
        );
        assert_eq!(
            calculate_staker_reward_v0(
                Amount::from_atoms(1100),
                Amount::from_atoms(100),
                PerThousand::new(100).unwrap()
            ),
            Some(Amount::from_atoms(200))
        );
        assert_eq!(
            calculate_staker_reward_v0(
                Amount::from_atoms(10_000),
                Amount::from_atoms(33),
                PerThousand::new(111).unwrap()
            ),
            Some(Amount::from_atoms(1139))
        );
    }

    #[test]
    fn calculate_staker_reward_test_v1_continuity() {
        // Ensure that results are continuous when there's delegation and where there's none

        let pool_id = new_pool_id(1);

        {
            // No delegators, all goes to staker
            assert_eq!(
                calculate_staker_reward_v1(
                    Amount::from_atoms(100),
                    Amount::from_atoms(100),
                    Amount::from_atoms(100),
                    Amount::from_atoms(0),
                    PerThousand::new(0).unwrap(),
                    pool_id
                ),
                Ok(Amount::from_atoms(100))
            );
        }

        {
            // With and without cost-per-block, the only difference is subtracting at the beginning
            assert_eq!(
                calculate_staker_reward_v1(
                    Amount::from_atoms(100),
                    Amount::from_atoms(100),
                    Amount::from_atoms(90),
                    Amount::from_atoms(0),
                    PerThousand::new(0).unwrap(),
                    pool_id
                ),
                Ok(Amount::from_atoms(90))
            );

            let cost_per_block = 50;
            assert_eq!(
                calculate_staker_reward_v1(
                    Amount::from_atoms(100 + cost_per_block),
                    Amount::from_atoms(100),
                    Amount::from_atoms(90),
                    Amount::from_atoms(cost_per_block),
                    PerThousand::new(0).unwrap(),
                    pool_id
                ),
                Ok(Amount::from_atoms(90 + cost_per_block))
            );
        }

        {
            // When a margin ratio exists, we subtract the share then multiply the ratio by what's left to get the reward for staker from delegators' share
            let total_reward = 100;
            let pool_balance = 100;
            let staker_balance = 90;
            assert_eq!(
                calculate_staker_reward_v1(
                    Amount::from_atoms(total_reward),
                    Amount::from_atoms(pool_balance),
                    Amount::from_atoms(staker_balance),
                    Amount::from_atoms(0),
                    PerThousand::new(0).unwrap(),
                    pool_id
                ),
                Ok(Amount::from_atoms(90))
            );

            let margin_ratio_for_staker = 100; // 100/10=10%
            let expected_share_from_delegators_reward =
                (total_reward - (total_reward * staker_balance) / pool_balance) * 10 / 100;
            assert_eq!(expected_share_from_delegators_reward, 1);
            assert_eq!(
                calculate_staker_reward_v1(
                    Amount::from_atoms(total_reward),
                    Amount::from_atoms(pool_balance),
                    Amount::from_atoms(staker_balance),
                    Amount::from_atoms(0),
                    PerThousand::new(margin_ratio_for_staker).unwrap(),
                    pool_id
                ),
                Ok(Amount::from_atoms(
                    90 + expected_share_from_delegators_reward
                ))
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_staker_reward_test_v1(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let pool_id = new_pool_id(1);
        let reward = Amount::from_atoms(rng.gen_range(1..=100_000_000));
        let pool_balance = Amount::from_atoms(rng.gen_range(1..=100_000_000));
        let staker_balance = Amount::from_atoms(rng.gen_range(1..=pool_balance.into_atoms()));

        let cost_per_block = Amount::from_atoms(rng.gen_range(1..=reward.into_atoms()));
        let cost_per_block_over_reward =
            (reward + Amount::from_atoms(rng.gen_range(1..=100_000_000))).unwrap();
        let mpt = PerThousand::new_from_rng(&mut rng);
        let mpt_zero = PerThousand::new(0).unwrap();
        let mpt_more_than_one = PerThousand::new(rng.gen_range(2..=1000)).unwrap();

        assert_eq!(
            calculate_staker_reward_v1(
                Amount::ZERO,
                Amount::ZERO,
                Amount::ZERO,
                Amount::ZERO,
                mpt_zero,
                pool_id
            ),
            Err(RewardDistributionError::InvariantPoolBalanceIsZero(pool_id))
        );
        assert_eq!(
            calculate_staker_reward_v1(
                reward,
                Amount::ZERO,
                Amount::ZERO,
                cost_per_block,
                mpt_zero,
                pool_id
            ),
            Err(RewardDistributionError::InvariantPoolBalanceIsZero(pool_id))
        );
        assert!(calculate_staker_reward_v1(
            reward,
            pool_balance,
            staker_balance,
            Amount::ZERO,
            mpt_zero,
            pool_id
        )
        .is_ok());
        assert!(calculate_staker_reward_v1(
            reward,
            pool_balance,
            staker_balance,
            Amount::ZERO,
            mpt,
            pool_id
        )
        .is_ok());
        assert!(calculate_staker_reward_v1(
            reward,
            pool_balance,
            Amount::ZERO,
            Amount::ZERO,
            mpt,
            pool_id
        )
        .is_ok());
        // negative amount
        assert_eq!(
            calculate_staker_reward_v1(
                Amount::ZERO,
                pool_balance,
                staker_balance,
                cost_per_block,
                mpt_zero,
                pool_id
            ),
            Ok(Amount::ZERO)
        );
        // cost per block > reward
        assert_eq!(
            calculate_staker_reward_v1(
                reward,
                pool_balance,
                staker_balance,
                cost_per_block_over_reward,
                mpt_zero,
                pool_id
            ),
            Ok(reward)
        );
        // overflow
        assert!(calculate_staker_reward_v1(
            Amount::MAX,
            pool_balance,
            staker_balance,
            cost_per_block,
            mpt_more_than_one,
            pool_id
        )
        .is_ok());

        // arbitrary values
        assert_eq!(
            calculate_staker_reward_v1(
                Amount::from_atoms(100),
                Amount::from_atoms(1000),
                Amount::from_atoms(500),
                Amount::from_atoms(10),
                PerThousand::new(100).unwrap(),
                pool_id
            ),
            Ok(Amount::from_atoms(59))
        );
        assert_eq!(
            calculate_staker_reward_v1(
                Amount::from_atoms(1100),
                Amount::from_atoms(1000),
                Amount::from_atoms(500),
                Amount::from_atoms(100),
                PerThousand::new(100).unwrap(),
                pool_id
            ),
            Ok(Amount::from_atoms(650))
        );
        assert_eq!(
            calculate_staker_reward_v1(
                Amount::from_atoms(10_000),
                Amount::from_atoms(700),
                Amount::from_atoms(55),
                Amount::from_atoms(33),
                PerThousand::new(111).unwrap(),
                pool_id
            ),
            Ok(Amount::from_atoms(1835))
        );
    }

    // Create 2 pools: pool_a and pool_b.
    // Each pool has 2 delegations with different amounts.
    // Distribute reward to pool_a and check that it was distributed proportionally
    // and that pool_b and its delegations were not affected.
    // Then undo everything and check that original state was restored.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V0)]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V1)]
    fn distribution_basic(#[case] seed: Seed, #[case] version: RewardDistributionVersion) {
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
            Amount::ZERO,
            vrf_pk.clone(),
            PerThousand::new(100).unwrap(),
            Amount::from_atoms(50),
        );

        let expected_staker_reward = match version {
            RewardDistributionVersion::V0 => Amount::from_atoms(150),
            RewardDistributionVersion::V1 => Amount::from_atoms(278),
        };
        let expected_pool_data_a = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            expected_staker_reward,
            vrf_pk,
            PerThousand::new(100).unwrap(),
            Amount::from_atoms(50),
        );
        let expected_delegation_a_1_reward = match version {
            RewardDistributionVersion::V0 => Amount::from_atoms(300),
            RewardDistributionVersion::V1 => Amount::from_atoms(257),
        };
        let expected_delegation_a_2_reward = match version {
            RewardDistributionVersion::V0 => Amount::from_atoms(600),
            RewardDistributionVersion::V1 => Amount::from_atoms(515),
        };

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
                    (delegation_a_1_amount + expected_delegation_a_1_reward).unwrap(),
                ),
                ((pool_id_b, delegation_b_1), delegation_b_1_amount),
                (
                    (pool_id_a, delegation_a_2),
                    (delegation_a_2_amount + expected_delegation_a_2_reward).unwrap(),
                ),
                ((pool_id_b, delegation_b_2), delegation_b_2_amount),
            ]),
            BTreeMap::from_iter([
                (
                    delegation_a_1,
                    (delegation_a_1_amount + expected_delegation_a_1_reward).unwrap(),
                ),
                (delegation_b_1, delegation_b_1_amount),
                (
                    delegation_a_2,
                    (delegation_a_2_amount + expected_delegation_a_2_reward).unwrap(),
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

        let all_undos = {
            let mut accounting_adapter =
                accounting_adapter.operations(TransactionSource::Chain(block_id));
            distribute_pos_reward(
                &mut accounting_adapter,
                block_id,
                pool_id_a,
                reward,
                version,
            )
            .unwrap()
        };

        let (consumed, _) = accounting_adapter.consume();
        db.batch_write_delta(consumed).unwrap();

        assert_eq!(store, expected_store);

        // undo everything
        let mut db = PoSAccountingDB::new(&mut store);
        let mut accounting_adapter = PoSAccountingDeltaAdapter::new(&mut db);
        all_undos
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
    #[case(Seed::from_entropy(), RewardDistributionVersion::V0)]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V1)]
    fn distribution_properties(#[case] seed: Seed, #[case] version: RewardDistributionVersion) {
        let mut rng = make_seedable_rng(seed);
        let block_id = Id::new(H256::random_using(&mut rng));

        let pool_id = new_pool_id(1);

        let delegation_id_1 = new_delegation_id(1);
        let delegation_id_2 = new_delegation_id(2);

        let original_pledged_amount = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let delegation_1_balance = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let delegation_2_balance = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let total_delegation_shares = (delegation_1_balance + delegation_2_balance).unwrap();

        let original_pool_balance = amount_sum!(
            original_pledged_amount,
            delegation_1_balance,
            delegation_2_balance
        )
        .unwrap();

        let reward = Amount::from_atoms(rng.gen_range(0..100_000_000));
        let cost_per_block = Amount::from_atoms(rng.gen_range(0..reward.into_atoms()));
        let mpt = PerThousand::new_from_rng(&mut rng);
        let staker_reward = match version {
            RewardDistributionVersion::V0 => {
                calculate_staker_reward_v0(reward, cost_per_block, mpt).unwrap()
            }
            RewardDistributionVersion::V1 => calculate_staker_reward_v1(
                reward,
                original_pool_balance,
                original_pledged_amount,
                cost_per_block,
                mpt,
                pool_id,
            )
            .unwrap(),
        };
        let total_delegation_reward = (reward - staker_reward).unwrap();

        let delegation_data = DelegationData::new(pool_id, Destination::AnyoneCanSpend);

        let pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            original_pledged_amount,
            Amount::ZERO,
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

        {
            let mut accounting_adapter =
                accounting_adapter.operations(TransactionSource::Chain(block_id));
            distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward, version)
                .unwrap()
        };

        let staker_reward = accounting_adapter
            .accounting_delta()
            .get_pool_data(pool_id)
            .unwrap()
            .unwrap()
            .staker_rewards();

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

        // check that staker reward and delegation rewards add up to total reward
        assert_eq!(
            reward,
            amount_sum!(
                staker_reward,
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

    // Check that if delegation is present but its balance is 0 then all the reward goes to staker
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V0)]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V1)]
    fn total_delegations_balance_zero(
        #[case] seed: Seed,
        #[case] version: RewardDistributionVersion,
    ) {
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
            Amount::ZERO,
            vrf_pk.clone(),
            mpt,
            cost_per_block,
        );
        let expected_pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            reward,
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

        {
            let mut accounting_adapter =
                accounting_adapter.operations(TransactionSource::Chain(block_id));
            distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward, version)
                .unwrap()
        };

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

    // Check that staker can set its reward to 100% and the reward goes entirely to the staker
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V0)]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V1)]
    fn total_delegations_reward_zero(
        #[case] seed: Seed,
        #[case] version: RewardDistributionVersion,
    ) {
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
            Amount::ZERO,
            vrf_pk.clone(),
            mpt,
            cost_per_block,
        );
        let expected_pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            reward,
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

        {
            let mut accounting_adapter =
                accounting_adapter.operations(TransactionSource::Chain(block_id));
            distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward, version)
                .unwrap()
        };

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

    // Check that if there are no delegations then the whole reward goes to the staker
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V0)]
    #[case(Seed::from_entropy(), RewardDistributionVersion::V1)]
    fn no_delegations(#[case] seed: Seed, #[case] version: RewardDistributionVersion) {
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
            Amount::ZERO,
            vrf_pk.clone(),
            mpt,
            cost_per_block,
        );
        let expected_pool_data = PoolData::new(
            Destination::AnyoneCanSpend,
            pledged_amount,
            reward,
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

        {
            let mut accounting_adapter =
                accounting_adapter.operations(TransactionSource::Chain(block_id));
            distribute_pos_reward(&mut accounting_adapter, block_id, pool_id, reward, version)
                .unwrap()
        };

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
