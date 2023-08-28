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

use common::{primitives::Amount, Uint256};

// Note: rational is used as a convenient representation type and must not be used
//       for actual calculation because the result has to be predictable and reliable
type Rational128 = num::rational::Ratio<u128>;

/// Decentralization parameter which ensures that no pool is more powerful than 1/k of the whole network
const K: u128 = 1000;
const POOL_SATURATION_LEVEL: Rational128 = Rational128::new_raw(1, K);

/// Parameter determines the influence of the reward on the result. It was chosen such that if a pool
/// doubles minimum pledge the the result increases by 5%.
/// If the minimum pledge changes it should be recalculated.
const DEFAULT_PLEDGE_INFLUENCE_PARAMETER: Rational128 = Rational128::new_raw(789, 1000);

/// The function determines pool's weight based on its balance and pledge. In the simplest case
/// pool's weight is proportional to its balance but we want to incentivize pool's operators to
/// pledge, so this function takes pledge into account. The weight of a pool grows until the
/// proportion of pledge to delegated amount reaches 1:1.
///
/// The result is a pair that represents a ratio: (numerator, denominator), which is always < 1
pub fn pool_weight(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> (Uint256, Uint256) {
    pool_weight_impl(
        pledge_amount,
        pool_balance,
        final_supply,
        DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
    )
}

fn pool_weight_impl(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
    pledge_influence: Rational128,
) -> (Uint256, Uint256) {
    assert!(
        pool_balance < final_supply,
        "Pool balance cannot be greater than total supply"
    );
    assert!(
        pledge_amount <= pool_balance,
        "Pledge cannot be greater than pool balance"
    );

    let relative_pool_stake =
        Rational128::new(pool_balance.into_atoms(), final_supply.into_atoms());
    let relative_pledge_amount =
        Rational128::new(pledge_amount.into_atoms(), final_supply.into_atoms());

    let a = pledge_influence;
    let sigma = std::cmp::min(relative_pool_stake, POOL_SATURATION_LEVEL);
    let s = std::cmp::min(relative_pledge_amount, POOL_SATURATION_LEVEL);
    let m = Uint256::from_u128(u128::MAX);

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
        let m_s = m * (*s.numer()).into() / (*s.denom()).into();
        let m_s_sigma_k = m * (*s.numer()).into() / (*s.denom()).into() * (*sigma.numer()).into()
            / (*sigma.denom()).into()
            * K.into();
        m_s - m_s_sigma_k
    };

    // term2 = (m sigma - term1) k
    let term2 = {
        let m_sigma = m * (*sigma.numer()).into() / (*sigma.denom()).into();
        (m_sigma - term1) * K.into()
    };

    // result = (m sigma + s a term2) / (m + m a)
    let result_numer = {
        let m_sigma = m * (*sigma.numer()).into() / (*sigma.denom()).into();
        let term2_s_a = term2 * (*a.numer()).into() / (*a.denom()).into() * (*s.numer()).into()
            / (*s.denom()).into();
        m_sigma + term2_s_a
    };
    let result_denom = m + m * (*a.numer()).into() / (*a.denom()).into();

    (result_numer, result_denom)
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::{chain::Mlt, primitives::Amount};
    use crypto::random::Rng;
    use num::{ToPrimitive, Zero};
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn pool_weight_float_impl(
        pledge_amount: Amount,
        pool_balance: Amount,
        final_supply: Amount,
        pledge_influence: Rational128,
    ) -> f64 {
        let relative_pool_stake =
            pool_balance.into_atoms() as f64 / final_supply.into_atoms() as f64;
        let relative_pledge_amount =
            pledge_amount.into_atoms() as f64 / final_supply.into_atoms() as f64;

        let z = POOL_SATURATION_LEVEL.to_f64().unwrap();
        let a = pledge_influence.to_f64().unwrap();
        let sigma = f64::min(relative_pool_stake, z);
        let s = f64::min(relative_pledge_amount, z);

        (sigma + s * a * ((sigma - s * ((z - sigma) / z)) / z)) / (a + 1.0)
    }

    fn to_float(numer: Uint256, denom: Uint256, precision: u32) -> f64 {
        let m = 10u128.pow(precision);
        let i = numer * Uint256::from_u128(m) / denom;
        u128::try_from(i).unwrap() as f64 / m as f64
    }

    fn compare_results(actual: (Uint256, Uint256), expected: f64) {
        let tolerance: f64 = 1e-9;
        let actual_f64 = to_float(actual.0, actual.1, 10);
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

        let actual = pool_weight(pledge_amount, pool_balance, final_supply);
        assert_eq!(actual.0, Uint256::ZERO);
        assert_ne!(actual.1, Uint256::ZERO);
    }

    #[test]
    fn calculate_pool_weight_fixed_values() {
        let final_supply = Mlt::from_mlt(600_000_000).to_amount_atoms();

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(40_000).to_amount_atoms();

            let actual = pool_weight(pledge_amount, pool_balance, final_supply);
            compare_results(actual, 0.000194818);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(80_000).to_amount_atoms();

            let actual = pool_weight(pledge_amount, pool_balance, final_supply);
            compare_results(actual, 0.000200698);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = Mlt::from_mlt(150_000).to_amount_atoms();

            let actual = pool_weight(pledge_amount, pool_balance, final_supply);
            compare_results(actual, 0.0002047);
        }

        {
            let pool_balance = Mlt::from_mlt(200_000).to_amount_atoms();
            let pledge_amount = pool_balance;

            let actual = pool_weight(pledge_amount, pool_balance, final_supply);
            compare_results(actual, 0.000202658);
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
            Rational128::zero(),
        );

        let expected = f64::min(
            POOL_SATURATION_LEVEL.to_f64().unwrap(),
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

        let actual = pool_weight(pledge_amount, pool_balance, final_supply);
        let expected = pool_weight_float_impl(
            pledge_amount,
            pool_balance,
            final_supply,
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

        let actual = pool_weight(pledge_amount, pool_balance, final_supply);
        let expected = pool_weight_float_impl(
            pledge_amount,
            pool_balance,
            final_supply,
            DEFAULT_PLEDGE_INFLUENCE_PARAMETER,
        );
        compare_results(actual, expected);
        assert!(to_float(actual.0, actual.1, 10) < 0.1);
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
                let w = pool_weight(Amount::from_atoms(pledge), pool_balance, final_supply);
                to_float(w.0, w.1, 10)
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
                    let w = pool_weight(Amount::from_atoms(pledge), pool_balance, final_supply);
                    to_float(w.0, w.1, 10)
                })
                .collect();

            assert!(weights.windows(2).all(|w| w[0] < w[1]));
        }

        // check that the result decreases for the second half of possible pledge values
        {
            let weights: Vec<f64> = ((pool_balance.into_atoms() / 2)..=pool_balance.into_atoms())
                .step_by(step as usize)
                .map(|pledge| {
                    let w = pool_weight(Amount::from_atoms(pledge), pool_balance, final_supply);
                    to_float(w.0, w.1, 10)
                })
                .collect();

            assert!(weights.windows(2).all(|w| w[0] > w[1]));
        }
    }
}
