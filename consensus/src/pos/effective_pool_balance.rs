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
pub const POOL_SATURATION_LEVEL: Rational<u128> = Rational::<u128>::new(1, K);

/// Parameter determines the influence of the reward on the result. It was chosen such that if a pool
/// doubles minimum pledge the the result increases by 0.5%.
/// If the minimum pledge changes it should be recalculated.
const DEFAULT_PLEDGE_INFLUENCE_PARAMETER: Rational<u128> =
    Rational::<u128>::new(75375728, 1_000_000_000); // 0.075375728

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EffectivePoolBalanceError {
    #[error("Arithmetic error while calculating pools weight")]
    ArithmeticError,
    #[error("Final supply cannot be 0")]
    FinalSupplyZero,
    #[error("Pool balance {0:?} cannot be greater than total supply: {1:?}")]
    PoolBalanceGreaterThanSupply(Amount, Amount),
    #[error("Pool pledge {0:?} cannot be greater than pool balance {1:?}")]
    PoolPledgeGreaterThanBalance(Amount, Amount),
    #[error("Adjustment to balance must feet into Amount type")]
    AdjustmentMustFeetIntoAmount,
}

/// The function determines pool's effective balance based on its pledge. In the simplest case
/// pool's weight is proportional to its balance but we want to incentivize pool's operators to
/// pledge, so this function takes pledge into account.
pub fn effective_pool_balance(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<Amount, EffectivePoolBalanceError> {
    effective_pool_balance_impl(
        pledge_amount,
        pool_balance,
        final_supply,
        POOL_SATURATION_LEVEL,
        DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
    )
}

fn effective_pool_balance_impl(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
    pool_saturation_level: Rational<u128>,
    pledge_influence: Rational<u128>,
) -> Result<Amount, EffectivePoolBalanceError> {
    ensure!(
        final_supply > Amount::ZERO,
        EffectivePoolBalanceError::FinalSupplyZero
    );

    ensure!(
        pool_balance < final_supply,
        EffectivePoolBalanceError::PoolBalanceGreaterThanSupply(pool_balance, final_supply)
    );

    ensure!(
        pledge_amount <= pool_balance,
        EffectivePoolBalanceError::PoolPledgeGreaterThanBalance(pledge_amount, pool_balance)
    );

    let z = final_supply
        .into_atoms()
        .checked_mul(*pool_saturation_level.numer())
        .and_then(|v| v.checked_div(*pool_saturation_level.denom()))
        .ok_or(EffectivePoolBalanceError::ArithmeticError)?;

    // If the pool is saturated, then the effective balance is capped to z
    if pool_balance.into_atoms() > z {
        return Ok(Amount::from_atoms(z));
    }

    let a = pledge_influence;
    let sigma = pool_balance.into_atoms();
    let s = pledge_amount.into_atoms();

    let z_squared = z.checked_mul(z).ok_or(EffectivePoolBalanceError::ArithmeticError)?;
    let z_squared: Uint256 = z_squared.into();

    // There are security arguments using Nash Equilibrium on why we want to use the final supply as the total,
    // and not the total stake in all pools. This is because the total stake changes over time, and the Nash Equilibrium
    // is a dynamic equilibrium, not a static one.
    // The final supply is the total amount of coins that will ever exist, and hence is a static value.
    // This way, stakers can make decisions based on the final supply, and not have to worry about
    // the total stake changing over time. Hence, the incentive structure is more stable.
    //
    // z = 1/k: The size of the saturated pool
    // Saturated pool: A pool is saturated if its relative stake (pledge + delegated) is equal to
    //      the size given by z = 1/k. A pool that has reached saturation will not have additional
    //      rewards if the total stake is increased. This is to prevent pools from growing too large.
    //
    // a: The pledge influence parameter. When a=0,
    //      the pledge has no additional effect other than proportional to the relative stake.
    //      while `a` increases, the pledge has more effect on the pool weight, and hence increases the reward
    //      more compared to delegation. The parameter a can be controlled to incentivize pools to pledge more.
    // s:     The pool's pledge amount
    // sigma: The pool's stake (pledge + delegated)
    //
    // The formula is rewritten as follows to represent the result as sigma minus some adjustment.
    // Also it makes it more suitable for integer arithmetic because there is a single division at the end.
    //
    //                 ⎛            ⎛z - sigma⎞⎞
    //                 ⎜sigma - s ⋅ ⎜─────────⎟⎟
    //                 ⎜            ⎝    z    ⎠⎟
    // sigma + s ⋅ a ⋅ ⎜───────────────────────⎟
    //                 ⎝            z          ⎠               a     ⎛ sigma z^2 - s (z sigma - s (z - sigma))⎞
    // ─────────────────────────────────────────  => sigma - ──────  ⎜────────────────────────────────────────⎟
    //                a + 1                                  a + 1   ⎝                 z^2                    ⎠
    //
    //
    // Maximizing the gains from a pool with pledges:
    //     As a function of the total stake (sigma = pledge + delegations), the pool's effective balance is a concave down parabola.
    //     The maximum point is very close to sigma = s/2 if sigma << z. Meaning: pledge = delegations maximizes the
    //     effective balance.
    //     The true peak can be calculated by calculating the derivative of the function and equating it to zero. The
    //     result there is s_max = z⋅sigma/(2⋅(z-sigma)), where s_max is the pledge that maximizes the effective balance.
    //     In that equation we can see if sigma << z, then it simplifies to s_max = sigma/2.

    // Break the formula down into terms for simplicity
    // term1 = s (z - sigma)
    let term1 = z
        .checked_sub(sigma)
        .and_then(|v| v.checked_mul(s))
        .ok_or(EffectivePoolBalanceError::ArithmeticError)?;

    // term2 = s (z sigma - term1)
    let term2 = {
        let z: Uint256 = z.into();
        z.checked_mul(&sigma.into())
            .and_then(|v| v.checked_sub(&term1.into()))
            .and_then(|v| v.checked_mul(&s.into()))
            .ok_or(EffectivePoolBalanceError::ArithmeticError)?
    };

    // a.n (sigma z z - term2)
    let adjustment_numerator = {
        let sigma: Uint256 = sigma.into();
        sigma
            .checked_mul(&z_squared)
            .and_then(|v| v.checked_sub(&term2))
            .and_then(|v| v.checked_mul(&(*a.numer()).into()))
            .ok_or(EffectivePoolBalanceError::ArithmeticError)?
    };

    // (a.n + a.d) z^2
    let adjustment_denominator = a
        .numer()
        .checked_add(*a.denom())
        .and_then(|v| z_squared.checked_mul(&v.into()))
        .ok_or(EffectivePoolBalanceError::ArithmeticError)?;

    let adjustment: u128 = adjustment_numerator
        .checked_div(&adjustment_denominator)
        .ok_or(EffectivePoolBalanceError::ArithmeticError)?
        .try_into()
        .map_err(|_| EffectivePoolBalanceError::AdjustmentMustFeetIntoAmount)?;

    let effective_balance = sigma
        .checked_sub(adjustment)
        .ok_or(EffectivePoolBalanceError::ArithmeticError)?;
    assert!(effective_balance <= sigma);

    Ok(Amount::from_atoms(effective_balance))
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::{chain::Mlt, primitives::Amount};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn abs_diff(a: Amount, b: Amount) -> Amount {
        if a > b {
            (a - b).expect("cannot be negative")
        } else {
            (b - a).expect("cannot be negative")
        }
    }

    fn effective_pool_balance_float_impl(
        pledge_amount: Amount,
        pool_balance: Amount,
        final_supply: Amount,
        pool_saturation_level: Rational<u128>,
        pledge_influence: Rational<u128>,
    ) -> Amount {
        let z = final_supply.into_atoms() as f64 / *pool_saturation_level.denom() as f64
            * (*pool_saturation_level.numer() as f64);
        let a = *pledge_influence.numer() as f64 / *pledge_influence.denom() as f64;
        let sigma = f64::min(pool_balance.into_atoms() as f64, z);
        let s = f64::min(pledge_amount.into_atoms() as f64, z);

        let result = (sigma + s * a * ((sigma - s * ((z - sigma) / z)) / z)) / (a + 1.0);
        Amount::from_atoms(result as u128)
    }

    #[test]
    fn calculate_pool_weight_zero_balance() {
        let final_supply = Amount::from_atoms(600_000_000);
        let pool_balance = Amount::ZERO;
        let pledge_amount = Amount::ZERO;

        let effective_balance =
            effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
        assert_eq!(effective_balance, pool_balance);
    }

    #[test]
    fn calculate_pool_weight_fixed_values() {
        let final_supply = Mlt::from_mlt(600_000_000).to_amount_atoms();

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(40_000).to_amount_atoms();

            let actual = effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
            let expected = Amount::from_atoms(18679146570104142);
            assert_eq!(actual, expected);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(80_000).to_amount_atoms();

            let actual = effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
            let expected = Amount::from_atoms(18735220536467646);
            assert_eq!(actual, expected);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(150_000).to_amount_atoms();

            let actual = effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
            let expected = Amount::from_atoms(18773381985798363);
            assert_eq!(actual, expected);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = pool_balance;

            let actual = effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
            let expected = Amount::from_atoms(18753911858588813);
            assert_eq!(actual, expected);
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

        let actual = effective_pool_balance_impl(
            pledge_amount,
            pool_balance,
            final_supply,
            POOL_SATURATION_LEVEL,
            Rational::<u128>::new(0, 1),
        )
        .unwrap();

        let expected = std::cmp::min(
            pool_balance,
            (final_supply * (*POOL_SATURATION_LEVEL.numer()))
                .and_then(|v| v / *POOL_SATURATION_LEVEL.denom())
                .unwrap(),
        );

        assert_eq!(actual, expected);
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

        let actual = effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
        let expected = effective_pool_balance_float_impl(
            pledge_amount,
            pool_balance,
            final_supply,
            POOL_SATURATION_LEVEL,
            DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
        );
        assert!(abs_diff(actual, expected).into_atoms() <= 100);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy(), Amount::from_atoms(600_000))]
    #[trace]
    #[case(Seed::from_entropy(), Mlt::from_mlt(600_000_000).to_amount_atoms())]
    fn calculate_effective_balance_capped(#[case] seed: Seed, #[case] final_supply: Amount) {
        let mut rng = make_seedable_rng(seed);

        let cap = (final_supply * (*POOL_SATURATION_LEVEL.numer()))
            .and_then(|v| v / *POOL_SATURATION_LEVEL.denom())
            .unwrap();

        let pool_balance =
            Amount::from_atoms(rng.gen_range(cap.into_atoms()..final_supply.into_atoms()));
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        let actual = effective_pool_balance(pledge_amount, pool_balance, final_supply).unwrap();
        assert_eq!(actual, cap);
        assert!(actual <= pool_balance);
    }

    // If a pool balance == supply/k value then the target is directly proportional to the pledge
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn effective_balance_proportional(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let final_supply = Mlt::from_mlt(rng.gen_range(1_000_000..600_000_000)).to_amount_atoms();
        let pool_balance = (final_supply / 1000).unwrap();

        let step = Mlt::from_mlt(1000).to_amount_atoms().into_atoms();

        let effective_balances: Vec<Amount> = (0..pool_balance.into_atoms())
            .step_by(step as usize)
            .map(|pledge| {
                effective_pool_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                    .unwrap()
            })
            .collect();

        let initial_diff = (effective_balances[1] - effective_balances[0]).unwrap();
        assert!(effective_balances.windows(2).all(|t| {
            let ascending = t[0] < t[1];
            let equidistant =
                abs_diff((t[1] - t[0]).unwrap(), initial_diff) <= Amount::from_atoms(1); // allow for rounding error
            ascending && equidistant
        }));
    }

    // If a pool is not saturated (balance < supply/k) then then result is a concave down parabola to the pledge.
    // The maximum point is exactly at s_max = z⋅sigma/(2⋅(z-sigma))
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn effective_balance_curve(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let final_supply = Mlt::from_mlt(rng.gen_range(10_000..600_000_000)).to_amount_atoms();

        let min_pool_balance = Mlt::from_mlt(1).to_amount_atoms();
        let max_pool_balance = (final_supply * (*POOL_SATURATION_LEVEL.numer()))
            .and_then(|v| v / *POOL_SATURATION_LEVEL.denom())
            .unwrap();
        let pool_balance = Amount::from_atoms(
            rng.gen_range(min_pool_balance.into_atoms()..max_pool_balance.into_atoms()),
        );

        let step = Mlt::from_mlt(1000).to_amount_atoms().into_atoms();

        // calculate the peak point of the curve
        let pledge_peak = {
            let sigma = Rational::new(pool_balance.into_atoms(), final_supply.into_atoms());
            let sigma = *sigma.numer() as f64 / *sigma.denom() as f64;
            let z = *POOL_SATURATION_LEVEL.numer() as f64 / *POOL_SATURATION_LEVEL.denom() as f64;
            let s_max = z * sigma / (2.0 * (z - sigma));
            (s_max * final_supply.into_atoms() as f64) as u128
        };

        // it's possible that peak point is outside of the range of pool balance values
        let pledge_peak = std::cmp::min(pledge_peak, pool_balance.into_atoms());

        // check that the result increases until it reaches peak of possible pledge values
        {
            let effective_balances: Vec<Amount> = (0..pledge_peak)
                .step_by(step as usize)
                .map(|pledge| {
                    effective_pool_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap()
                })
                .collect();

            assert!(effective_balances.windows(2).all(|t| t[0] < t[1]));
        }

        // check that the result decreases after the peak value; if peak if outside of the range then this loop does nothing
        {
            let effective_balances: Vec<Amount> = (pledge_peak..=pool_balance.into_atoms())
                .step_by(step as usize)
                .map(|pledge| {
                    effective_pool_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap()
                })
                .collect();

            assert!(effective_balances.windows(2).all(|t| t[0] > t[1]));
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
        let effective_balance1 =
            effective_pool_balance(pledge_amount1, pool_balance, final_supply).unwrap();

        let pledge_amount2 = Mlt::from_mlt(80_000).to_amount_atoms();
        let effective_balance2 =
            effective_pool_balance(pledge_amount2, pool_balance, final_supply).unwrap();

        let actual = effective_balance2.into_atoms() as f64 * 100.0
            / effective_balance1.into_atoms() as f64
            - 100.0;
        let expected = 0.5;

        let tolerance: f64 = 3e-8;
        assert!((expected - actual).abs() < tolerance);
    }
}
