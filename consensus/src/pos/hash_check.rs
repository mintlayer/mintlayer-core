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

use chainstate_types::pos_randomness::PoSRandomness;
use common::{
    chain::{
        block::{consensus_data::PoSData, timestamp::BlockTimestamp},
        config::EpochIndex,
        PoSConsensusVersion,
    },
    primitives::{rational::Rational, Amount},
    Uint256, Uint512,
};
use crypto::vrf::VRFPublicKey;
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

use super::pool_weight::{pool_weight, POOL_SATURATION_LEVEL};

fn check_pos_hash_v0(
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    pos_data: &PoSData,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pool_balance: Amount,
) -> Result<(), ConsensusPoSError> {
    let target: Uint256 = pos_data
        .compact_target()
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(pos_data.compact_target()))?;

    let hash: Uint256 = PoSRandomness::from_block(
        epoch_index,
        block_timestamp,
        random_seed,
        pos_data,
        vrf_pub_key,
    )?
    .value()
    .into();

    let hash: Uint512 = hash.into();
    let pool_balance: Uint512 = pool_balance.into();

    ensure!(
        hash <= pool_balance * target.into(),
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(())
}

/// The balance of the pool capped by the saturation value
fn capped_balance(balance: Amount, final_supply: Amount) -> Option<Amount> {
    if Rational::new(balance.into_atoms(), final_supply.into_atoms()) > POOL_SATURATION_LEVEL {
        (final_supply * (*POOL_SATURATION_LEVEL.numer()))
            .and_then(|v| v / *POOL_SATURATION_LEVEL.denom())
    } else {
        Some(balance)
    }
}

/// The effective balance is the balance of the pool adjusted by the pool weight.
fn effective_balance(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<Uint512, ConsensusPoSError> {
    let pool_weight = pool_weight(pledge_amount, pool_balance, final_supply)?;
    let weight_numerator = (*pool_weight.numer()).into();
    let weight_denominator = (*pool_weight.denom()).into();

    // The balance of the pool is capped to prevent centralization
    let capped_balance = capped_balance(pool_balance, final_supply)
        .ok_or(ConsensusPoSError::FailedToCalculateCappedBalance)?;
    let capped_balance = Uint512::from_amount(capped_balance);

    // Delta is the extra balance that the pool gets according to the weight formula
    let delta = capped_balance * weight_numerator / weight_denominator;
    Ok(capped_balance + delta)
}

#[allow(clippy::too_many_arguments)]
fn check_pos_hash_v1(
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    pos_data: &PoSData,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<(), ConsensusPoSError> {
    let target: Uint256 = pos_data
        .compact_target()
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(pos_data.compact_target()))?;

    let hash: Uint256 = PoSRandomness::from_block(
        epoch_index,
        block_timestamp,
        random_seed,
        pos_data,
        vrf_pub_key,
    )?
    .value()
    .into();
    let hash: Uint512 = hash.into();

    let effective_balance = effective_balance(pledge_amount, pool_balance, final_supply)?;

    ensure!(
        hash <= effective_balance * target.into(),
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn check_pos_hash(
    consensus_version: PoSConsensusVersion,
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    pos_data: &PoSData,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<(), ConsensusPoSError> {
    match consensus_version {
        PoSConsensusVersion::V0 => check_pos_hash_v0(
            epoch_index,
            random_seed,
            pos_data,
            vrf_pub_key,
            block_timestamp,
            pool_balance,
        ),
        PoSConsensusVersion::V1 => check_pos_hash_v1(
            epoch_index,
            random_seed,
            pos_data,
            vrf_pub_key,
            block_timestamp,
            pledge_amount,
            pool_balance,
            final_supply,
        ),
        _ => Err(ConsensusPoSError::UnsupportedConsensusVersion),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::{chain::Mlt, primitives::Amount};
    use crypto::random::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    fn abs_diff(a: Uint512, b: Uint512) -> Uint512 {
        if a > b {
            a - b
        } else {
            b - a
        }
    }

    // If a pool balance == supply/k value then the target is directly proportional to the pledge
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn effective_balance_proportional(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let final_supply = Mlt::from_mlt(rng.gen_range(10_000..600_000_000)).to_amount_atoms();
        let pool_balance = (final_supply / 1000).unwrap();

        let step = Mlt::from_mlt(1000).to_amount_atoms().into_atoms();

        let effective_balances: Vec<Uint512> = (0..pool_balance.into_atoms())
            .step_by(step as usize)
            .map(|pledge| {
                effective_balance(Amount::from_atoms(pledge), pool_balance, final_supply).unwrap()
            })
            .collect();

        let initial_diff = effective_balances[1] - effective_balances[0];
        assert!(effective_balances.windows(2).all(|t| {
            let ascending = t[0] < t[1];
            let equidistant = abs_diff(t[1] - t[0], initial_diff) <= Uint512::ONE; // allow for rounding error
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
            let effective_balances: Vec<Uint512> = (0..pledge_peak)
                .step_by(step as usize)
                .map(|pledge| {
                    effective_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap()
                })
                .collect();

            assert!(effective_balances.windows(2).all(|t| t[0] < t[1]));
        }

        // check that the result decreases after the peak value; if peak if outside of the range then this loop does nothing
        {
            let effective_balances: Vec<Uint512> = (pledge_peak..=pool_balance.into_atoms())
                .step_by(step as usize)
                .map(|pledge| {
                    effective_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap()
                })
                .collect();

            assert!(effective_balances.windows(2).all(|t| t[0] > t[1]));
        }
    }

    // If a is saturated meaning pool balance >= supply/k then increasing the pool balance doesn't change the effective balance
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn effective_balance_capped(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let final_supply = Mlt::from_mlt(rng.gen_range(10_000..600_000_000)).to_amount_atoms();

        let pool_balance1 = (final_supply * (*POOL_SATURATION_LEVEL.numer()))
            .and_then(|v| v / *POOL_SATURATION_LEVEL.denom())
            .unwrap();
        let pledge1 = pool_balance1;

        let pool_balance2 = Amount::from_atoms(
            rng.gen_range(pool_balance1.into_atoms()..final_supply.into_atoms()),
        );
        let pledge2 = pool_balance2;

        let effective_balance1 = effective_balance(pledge1, pool_balance1, final_supply).unwrap();
        let effective_balance2 = effective_balance(pledge2, pool_balance2, final_supply).unwrap();
        assert_eq!(effective_balance1, effective_balance2);
    }
}
