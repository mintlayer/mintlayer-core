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

use common::{
    primitives::{rational::Rational, Amount},
    Uint256,
};
use thiserror::Error;
use utils::ensure;

/// Decentralization parameter which ensures that no pool is more powerful than 1/k of the whole network
const K: u128 = 1000;
const POOL_SATURATION_LEVEL: Rational<u128> = Rational::<u128>::new(1, K);

/// Parameter determines the influence of the reward on the result. It was chosen such that if a pool
/// doubles minimum pledge the the result increases by 0.5%.
/// If the minimum pledge changes it should be recalculated.
const DEFAULT_PLEDGE_INFLUENCE_PARAMETER: Rational<u128> = Rational::<u128>::new(75, 1000);

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PoolWeightError {
    #[error("Arithmetics error while calculating pools weight")]
    ArithmeticsError,
    #[error("Final supply cannot be 0")]
    FinalSupplyZero,
    #[error("Pool balance {0:?} cannot be greater than total supply: {1:?}")]
    PoolBalanceGreaterThanSupply(Amount, Amount),
    #[error("Pool pledge {0:?} cannot be greater than pool balance {1:?}")]
    PoolPledgeGreaterThanBalance(Amount, Amount),
}

/// The function determines pool's weight based on its balance and pledge. In the simplest case
/// pool's weight is proportional to its balance but we want to incentivize pool's operators to
/// pledge, so this function takes pledge into account. The weight of a pool grows until the
/// proportion of pledge to delegated amount reaches 1:1.
pub fn pool_weight(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<Rational<Uint256>, PoolWeightError> {
    pool_weight_impl(
        pledge_amount,
        pool_balance,
        final_supply,
        POOL_SATURATION_LEVEL,
        DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
    )
}

fn pool_weight_impl(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
    pool_saturation_level: Rational<u128>,
    pledge_influence: Rational<u128>,
) -> Result<Rational<Uint256>, PoolWeightError> {
    ensure!(
        final_supply > Amount::ZERO,
        PoolWeightError::FinalSupplyZero
    );

    ensure!(
        pool_balance < final_supply,
        PoolWeightError::PoolBalanceGreaterThanSupply(pool_balance, final_supply)
    );

    ensure!(
        pledge_amount <= pool_balance,
        PoolWeightError::PoolPledgeGreaterThanBalance(pledge_amount, pool_balance)
    );

    let relative_pool_stake =
        Rational::<u128>::new(pool_balance.into_atoms(), final_supply.into_atoms());
    let relative_pledge_amount =
        Rational::<u128>::new(pledge_amount.into_atoms(), final_supply.into_atoms());

    let relative_pool_stake: Rational<Uint256> = relative_pool_stake.into();
    let relative_pledge_amount: Rational<Uint256> = relative_pledge_amount.into();

    let a: Rational<Uint256> = pledge_influence.into();
    let sigma = std::cmp::min(relative_pool_stake, pool_saturation_level.into());
    let s = std::cmp::min(relative_pledge_amount, pool_saturation_level.into());
    let m = Uint256::from_u128(u128::MAX);

    // "relative" means relative to some total. In this case, the total is the final supply. There are security
    //      arguments using Nash Equilibrium on why we want to use the final supply as the total, and not the
    //      total stake in all pools. This is because the total stake changes over time, and the Nash Equilibrium
    //      is a dynamic equilibrium, not a static one.
    //      The final supply is the total amount of coins that will ever exist, and hence is a static value.
    //      This way, stakers can make decisions based on the final supply, and not have to worry about
    //      the total stake changing over time. Hence, the incentive structure is more stable.
    //
    // z = 1/k: The size of the saturated pool
    // a: The pledge influence parameter. When a=0,
    //      the pledge has no additional effect other than proportional to the relative stake.
    //      while a increases, the pledge has more effect on the pool weight, and hence increases the reward
    //      more compared to delegation. The parameter a can be controlled to incentivize pools to pledge more.
    // s:     The relative pledge amount
    // sigma: The relative pool stake (pledge + delegated)
    //
    // Given that z = 1/k, scale the original formula by the factor of m
    //
    //                 ⎛            ⎛z - sigma⎞⎞
    //                 ⎜sigma - s ⋅ ⎜─────────⎟⎟
    //                 ⎜            ⎝    z    ⎠⎟
    // sigma + s ⋅ a ⋅ ⎜───────────────────────⎟
    //                 ⎝            z          ⎠        m sigma + s a (m sigma - (m s - m s sigma k)) k
    // ─────────────────────────────────────────  =>   ──────────────────────────────────────────────────
    //                a + 1                                               m a + m

    // Break it into terms for simplicity
    // term1 = m s - m s sigma k
    let term1 = {
        let m_s = m
            .checked_mul(s.numer())
            .and_then(|v| v.checked_div(s.denom()))
            .ok_or(PoolWeightError::ArithmeticsError)?;
        let m_s_sigma_k = m
            .checked_mul(s.numer())
            .and_then(|v| v.checked_div(s.denom()))
            .and_then(|v| v.checked_mul(sigma.numer()))
            .and_then(|v| v.checked_div(sigma.denom()))
            .and_then(|v| v.checked_mul(&(*pool_saturation_level.denom()).into()))
            .ok_or(PoolWeightError::ArithmeticsError)?;
        m_s.checked_sub(&m_s_sigma_k).ok_or(PoolWeightError::ArithmeticsError)?
    };

    // term2 = (m sigma - term1) k
    let term2 = {
        let m_sigma = m
            .checked_mul(sigma.numer())
            .and_then(|v| v.checked_div(sigma.denom()))
            .ok_or(PoolWeightError::ArithmeticsError)?;
        m_sigma
            .checked_sub(&term1)
            .and_then(|v| v.checked_mul(&(*pool_saturation_level.denom()).into()))
            .ok_or(PoolWeightError::ArithmeticsError)?
    };

    // result = (m sigma + s a term2) / (m + m a)
    let result_numer = {
        let m_sigma = m
            .checked_mul(sigma.numer())
            .and_then(|v| v.checked_div(sigma.denom()))
            .ok_or(PoolWeightError::ArithmeticsError)?;
        let term2_s_a = term2
            .checked_mul(a.numer())
            .and_then(|v| v.checked_div(a.denom()))
            .and_then(|v| v.checked_mul(s.numer()))
            .and_then(|v| v.checked_div(s.denom()))
            .ok_or(PoolWeightError::ArithmeticsError)?;
        m_sigma.checked_add(&term2_s_a).ok_or(PoolWeightError::ArithmeticsError)?
    };
    let result_denom = m
        .checked_mul(a.numer())
        .and_then(|v| v.checked_div(a.denom()))
        .and_then(|v| v.checked_add(&m))
        .ok_or(PoolWeightError::ArithmeticsError)?;
    assert_ne!(result_denom, Uint256::ZERO);

    Ok(Rational::<Uint256>::new(result_numer, result_denom))
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::{chain::Mlt, primitives::Amount};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn pool_weight_float_impl(
        pledge_amount: Amount,
        pool_balance: Amount,
        final_supply: Amount,
        pool_saturation_level: Rational<u128>,
        pledge_influence: Rational<u128>,
    ) -> f64 {
        let relative_pool_stake =
            pool_balance.into_atoms() as f64 / final_supply.into_atoms() as f64;
        let relative_pledge_amount =
            pledge_amount.into_atoms() as f64 / final_supply.into_atoms() as f64;

        let z = *pool_saturation_level.numer() as f64 / *pool_saturation_level.denom() as f64;
        let a = *pledge_influence.numer() as f64 / *pledge_influence.denom() as f64;
        let sigma = f64::min(relative_pool_stake, z);
        let s = f64::min(relative_pledge_amount, z);

        (sigma + s * a * ((sigma - s * ((z - sigma) / z)) / z)) / (a + 1.0)
    }

    fn to_float(r: Rational<Uint256>, precision: u32) -> f64 {
        let m = 10u128.pow(precision);
        let i = (*r.numer()) * Uint256::from_u128(m) / (*r.denom());
        u128::try_from(i).unwrap() as f64 / m as f64
    }

    fn compare_results(actual: Rational<Uint256>, expected: f64) {
        let tolerance: f64 = 1e-9;
        let actual_f64 = to_float(actual, 10);
        assert!(
            (actual_f64 - expected).abs() < tolerance,
            "actual: {}; expected: {}",
            actual_f64,
            expected
        );
    }

    #[test]
    fn calculate_pool_weight_zero_balance() {
        let final_supply = Amount::from_atoms(600_000_000);
        let pool_balance = Amount::ZERO;
        let pledge_amount = Amount::ZERO;

        let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
        assert_eq!(actual.numer(), &Uint256::ZERO);
        assert_ne!(actual.denom(), &Uint256::ZERO);
    }

    #[test]
    fn calculate_pool_weight_fixed_values() {
        let final_supply = Mlt::from_mlt(600_000_000).to_amount_atoms();

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(40_000).to_amount_atoms();

            let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
            compare_results(actual, 0.000311421);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(80_000).to_amount_atoms();

            let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
            compare_results(actual, 0.000312351);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(150_000).to_amount_atoms();

            let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
            compare_results(actual, 0.000312984);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = pool_balance;

            let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
            compare_results(actual, 0.000312661);
        }
    }

    // If `a` parameter is 0 then the result is simply proportional to the relative stake balance
    // and pledge has no effect
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_pool_weight_a_zero(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let final_supply = Amount::from_atoms(600_000_000);
        let pool_balance = Amount::from_atoms(rng.gen_range(2..final_supply.into_atoms()));
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        let actual = pool_weight_impl(
            pledge_amount,
            pool_balance,
            final_supply,
            POOL_SATURATION_LEVEL,
            Rational::<u128>::new(0, 1),
        )
        .unwrap();

        let expected = f64::min(
            *POOL_SATURATION_LEVEL.numer() as f64 / *POOL_SATURATION_LEVEL.denom() as f64,
            pool_balance.into_atoms() as f64 / final_supply.into_atoms() as f64,
        );

        compare_results(actual, expected);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), Amount::from_atoms(600_000))]
    #[trace]
    #[case(Seed::from_entropy(), Mlt::from_mlt(600_000_000).to_amount_atoms())]
    fn calculate_pool_weight_not_saturated(#[case] seed: Seed, #[case] final_supply: Amount) {
        let mut rng = make_seedable_rng(seed);

        let pool_balance = Amount::from_atoms(rng.gen_range(2..(final_supply.into_atoms() / K)));
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
        let expected = pool_weight_float_impl(
            pledge_amount,
            pool_balance,
            final_supply,
            POOL_SATURATION_LEVEL,
            DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
        );
        compare_results(actual, expected);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), Amount::from_atoms(600_000))]
    #[trace]
    #[case(Seed::from_entropy(), Mlt::from_mlt(600_000_000).to_amount_atoms())]
    fn calculate_pool_weight_capped(#[case] seed: Seed, #[case] final_supply: Amount) {
        let mut rng = make_seedable_rng(seed);

        let pool_balance = Amount::from_atoms(
            rng.gen_range((final_supply.into_atoms() / K)..final_supply.into_atoms()),
        );
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        let actual = pool_weight(pledge_amount, pool_balance, final_supply).unwrap();
        let expected = pool_weight_float_impl(
            pledge_amount,
            pool_balance,
            final_supply,
            POOL_SATURATION_LEVEL,
            DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
        );
        compare_results(actual, expected);
        assert!(to_float(actual, 10) < 0.1);
    }

    // If a pool is saturated (balance == supply/k) then the result is directly proportional to the pledge
    #[test]
    fn saturated_pool_result_prop() {
        let final_supply = Mlt::from_mlt(600_000_000).to_amount_atoms();
        let pool_balance = (final_supply / K).unwrap();

        let step = Mlt::from_mlt(1000).to_amount_atoms().into_atoms();

        let weights: Vec<f64> = (0..(pool_balance.into_atoms() / 2))
            .step_by(step as usize)
            .map(|pledge| {
                let w =
                    pool_weight(Amount::from_atoms(pledge), pool_balance, final_supply).unwrap();
                to_float(w, 10)
            })
            .collect();

        assert!(weights.windows(2).all(|w| w[0] < w[1]));
    }

    // If a pool is not saturated (balance != supply/k), specifically if balance == supply/k^2,
    // then then result is a concave down parabola to the pledge. The maximum point is exactly
    // at pool_balance/2.
    #[test]
    fn non_saturated_pool_result_curve() {
        let final_supply = Mlt::from_mlt(600_000_000).to_amount_atoms();
        let pool_balance = (final_supply / K).and_then(|f| f / K).unwrap();

        let step = Mlt::from_mlt(1000).to_amount_atoms().into_atoms();

        // check that the result increases for the first half of possible pledge values
        {
            let weights: Vec<f64> = (0..(pool_balance.into_atoms() / 2))
                .step_by(step as usize)
                .map(|pledge| {
                    let w = pool_weight(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap();
                    to_float(w, 10)
                })
                .collect();

            assert!(weights.windows(2).all(|w| w[0] < w[1]));
        }

        // check that the result decreases for the second half of possible pledge values
        {
            let weights: Vec<f64> = ((pool_balance.into_atoms() / 2)..=pool_balance.into_atoms())
                .step_by(step as usize)
                .map(|pledge| {
                    let w = pool_weight(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap();
                    to_float(w, 10)
                })
                .collect();

            assert!(weights.windows(2).all(|w| w[0] > w[1]));
        }
    }

    #[test]
    fn check_a0_value_calculation() {
        let final_supply = common::chain::config::create_mainnet()
            .final_supply()
            .unwrap()
            .to_amount_atoms();
        let pool_balance = (final_supply / K).unwrap();

        let pledge_amount1 = Mlt::from_mlt(40_000).to_amount_atoms();
        let weight1 = pool_weight(pledge_amount1, pool_balance, final_supply).unwrap();
        let weight1 = to_float(weight1, 10);

        let pledge_amount2 = Mlt::from_mlt(80_000).to_amount_atoms();
        let weight2 = pool_weight(pledge_amount2, pool_balance, final_supply).unwrap();
        let weight2 = to_float(weight2, 10);

        let actual = weight2 - weight1;
        let expected = weight1 * 0.005;
        let tolerance: f64 = 3e-8;
        assert!((actual - expected).abs() < tolerance);
    }
}
