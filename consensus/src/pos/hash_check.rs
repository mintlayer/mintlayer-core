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
        PoSChainConfig, PoSConsensusVersion,
    },
    primitives::Amount,
    Uint256, Uint512,
};
use crypto::vrf::VRFPublicKey;
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

type Rational128 = num::rational::Ratio<u128>;

const K: u128 = 1000;
const POOL_SATURATION_LEVEL: Rational128 = Rational128::new_raw(1, K);
const PLEDGE_INFLUENCE_PARAMETER: Rational128 = Rational128::new_raw(789, 1000);

fn pool_balance_power_integer(
    pledge_amount: Amount,
    pool_balance: Amount,
    total_supply: Amount,
) -> (Uint256, Uint256) {
    assert!(
        pool_balance < total_supply,
        "Pool balance cannot be greater than total supply"
    );
    assert!(
        pledge_amount <= pool_balance,
        "Pledge cannot be greater than pool balance"
    );

    let relative_pool_stake =
        Rational128::new(pool_balance.into_atoms(), total_supply.into_atoms());
    let relative_pledge_amount =
        Rational128::new(pledge_amount.into_atoms(), total_supply.into_atoms());

    let a = PLEDGE_INFLUENCE_PARAMETER;
    let sigma = std::cmp::min(relative_pool_stake, POOL_SATURATION_LEVEL); // FIXME: multiplication inside
    let s = std::cmp::min(relative_pledge_amount, POOL_SATURATION_LEVEL);
    let m = Uint256::from_u128(u128::MAX);

    // Given that z = 1/k, scale the original formula by the factor of m
    //
    //                 ⎛            ⎛z - sigma⎞⎞
    //                 ⎜sigma - s ⋅ ⎜─────────⎟⎟
    //                 ⎜            ⎝    z    ⎠⎟                     ⎛ m sigma - (m sigma - m s sigma k)⎞
    // sigma + s ⋅ a ⋅ ⎜───────────────────────⎟       m sigma + s a ⎜──────────────────────────────────⎟
    //                 ⎝            z          ⎠                     ⎝               z                  ⎠
    // ─────────────────────────────────────────  =>   ──────────────────────────────────────────────────
    //                a + 1                                                 m a + m

    // Break it into terms for simplicity

    // term1 = m s - m s sigma k
    let term1 = {
        let temp1 = m * (*s.numer()).into() / (*s.denom()).into();
        let temp2 = m * (*s.numer()).into() / (*s.denom()).into() * (*sigma.numer()).into()
            / (*sigma.denom()).into()
            * K.into();
        temp1 - temp2
    };

    // term2 = (m sigma - term1) k
    let term2 = {
        let temp = m * (*sigma.numer()).into() / (*sigma.denom()).into();
        (temp - term1) * K.into()
    };

    // result = (m sigma + s a term) / (m + m a)
    let result_numer = {
        let temp1 = m * (*sigma.numer()).into() / (*sigma.denom()).into();
        let temp2 = term2 * (*a.numer()).into() / (*a.denom()).into() * (*s.numer()).into()
            / (*s.denom()).into();
        temp1 + temp2
    };
    let result_denom = { m + m * (*a.numer()).into() / (*a.denom()).into() };

    (result_numer, result_denom)
}

fn check_pos_hash_v1(
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    pos_data: &PoSData,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pledge_amount: Amount,
    pool_balance: Amount,
    total_supply: Amount,
) -> Result<(), ConsensusPoSError> {
    let target: Uint256 = pos_data
        .compact_target()
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(pos_data.compact_target()))?;
    let target: Uint512 = target.into();

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

    let pool_balance_power = pool_balance_power_integer(pledge_amount, pool_balance, total_supply);
    let adjusted_target = target * pool_balance_power.0.into() / pool_balance_power.1.into();

    ensure!(
        hash <= adjusted_target,
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(())
}

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

pub fn check_pos_hash(
    pos_config: &PoSChainConfig,
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    pos_data: &PoSData,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pledge_amount: Amount,
    pool_balance: Amount,
    total_supply: Amount,
) -> Result<(), ConsensusPoSError> {
    match pos_config.consensus_version() {
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
            total_supply,
        ),
        _ => Err(ConsensusPoSError::UnsupportedConsensusVersion),
    }
}

// FIXME: functional test with netupgrade

#[cfg(test)]
mod tests {
    use super::*;

    use common::{chain::Mlt, primitives::Amount};
    use crypto::random::Rng;
    use num::ToPrimitive;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    // Note: use with caution because it can overflow for big Amounts
    fn pool_balance_power_float(
        pledge_amount: Amount,
        pool_balance: Amount,
        total_supply: Amount,
    ) -> f64 {
        let relative_pool_stake =
            pool_balance.into_atoms() as f64 / total_supply.into_atoms() as f64;
        let relative_pledge_amount =
            pledge_amount.into_atoms() as f64 / total_supply.into_atoms() as f64;

        let z = POOL_SATURATION_LEVEL.to_f64().unwrap();
        let a = PLEDGE_INFLUENCE_PARAMETER.to_f64().unwrap();
        let sigma = f64::min(relative_pool_stake, z);
        let s = f64::min(relative_pledge_amount, z);

        let result = (sigma + s * a * ((sigma - s * ((z - sigma) / z)) / z)) / (a + 1.0);
        result
    }

    fn to_float(numer: Uint256, denom: Uint256, precision: u32) -> f64 {
        let m = 10u128.pow(precision);
        let t = numer * Uint256::from_u128(m) / denom;
        let t = u128::try_from(t).unwrap();
        t as f64 / m as f64
    }

    #[rstest]
    #[trace]
    //#[case(Seed::from_entropy())]
    #[case(17060523886728314668.into())]
    fn calculate_pool_balance_power_not_saturated(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let total_supply = Amount::from_atoms(600_000_000);
        let pool_balance = Amount::from_atoms(rng.gen_range(2..(total_supply.into_atoms() / K)));
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        println!(
            "pledge: {:?}, balance: {:?}, total_supply: {:?}",
            pledge_amount, pool_balance, total_supply
        );

        let (e, d) = pool_balance_power_integer(pledge_amount, pool_balance, total_supply);
        println!("result as float: {}", to_float(e, d, 11));

        let f = pool_balance_power_float(pledge_amount, pool_balance, total_supply);
        println!("floating: {}", f);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_pool_balance_power_capped(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let total_supply = Amount::from_atoms(600_000_000);
        let pool_balance = Amount::from_atoms(
            rng.gen_range((total_supply.into_atoms() / K)..total_supply.into_atoms()),
        );
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        println!(
            "pledge: {:?}, balance: {:?}, total_supply: {:?}",
            pledge_amount, pool_balance, total_supply
        );

        let (e, d) = pool_balance_power_integer(pledge_amount, pool_balance, total_supply);
        println!("result as float: {}", to_float(e, d, 6));

        let f = pool_balance_power_float(pledge_amount, pool_balance, total_supply);
        println!("floating: {}", f);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_pool_balance_power_real_supply_under_k(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let total_supply = Mlt::from_mlt(600_000_000).to_amount_atoms();
        let pool_balance = Amount::from_atoms(rng.gen_range(2..(total_supply.into_atoms() / K)));
        let pledge_amount = Amount::from_atoms(rng.gen_range(1..pool_balance.into_atoms()));

        println!(
            "pledge: {:?}, balance: {:?}, total_supply: {:?}",
            pledge_amount, pool_balance, total_supply
        );

        let (e, d) = pool_balance_power_integer(pledge_amount, pool_balance, total_supply);
        println!("result as float: {}", to_float(e, d, 6));

        let f = pool_balance_power_float(pledge_amount, pool_balance, total_supply);
        println!("floating: {}", f);
    }
}
