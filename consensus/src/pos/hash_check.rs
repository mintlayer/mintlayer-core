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
    primitives::Amount,
    Uint256, Uint512,
};
use crypto::vrf::VRFPublicKey;
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

use super::pool_weight::pool_weight;

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

/// The effective balance is the balance of the pool adjusted by the pool weight.
fn effective_balance(
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<Uint512, ConsensusPoSError> {
    let pool_weight = pool_weight(pledge_amount, pool_balance, final_supply)?;
    let weight_numerator = (*pool_weight.numer()).into();
    let weight_denominator = (*pool_weight.denom()).into();

    let pool_balance = Uint512::from_amount(pool_balance);

    // Delta is the extra balance that the pool gets according to the weight formula
    let delta = pool_balance * weight_numerator / weight_denominator;
    Ok(pool_balance + delta)
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

    // If a pool is saturated (balance == supply/k) then the target is directly proportional to the pledge
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
            let equidistant = t[1] - t[0] - initial_diff <= Uint512::ONE; // allow for rounding errors
            ascending && equidistant
        }));
    }

    // If a pool is not saturated (balance != supply/k), specifically if balance == supply/k^2,
    // then then result is a concave down parabola to the pledge. The maximum point is exactly
    // at pool_balance/2.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn adjust_target_curve(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let final_supply = Mlt::from_mlt(rng.gen_range(10_000..600_000_000)).to_amount_atoms();
        let pool_balance = (final_supply / 1000).and_then(|f| f / 1000).unwrap();

        let step = Mlt::from_mlt(1000).to_amount_atoms().into_atoms();

        // check that the result increases for the first half of possible pledge values
        {
            let effective_balances: Vec<Uint512> = (0..(pool_balance.into_atoms() / 2))
                .step_by(step as usize)
                .map(|pledge| {
                    effective_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap()
                })
                .collect();

            assert!(effective_balances.windows(2).all(|t| t[0] < t[1]));
        }

        // check that the result decreases for the second half of possible pledge values
        {
            let effective_balances: Vec<Uint512> = ((pool_balance.into_atoms() / 2)
                ..=pool_balance.into_atoms())
                .step_by(step as usize)
                .map(|pledge| {
                    effective_balance(Amount::from_atoms(pledge), pool_balance, final_supply)
                        .unwrap()
                })
                .collect();

            assert!(effective_balances.windows(2).all(|t| t[0] > t[1]));
        }
    }
}
