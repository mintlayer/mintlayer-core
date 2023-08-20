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
use num::{CheckedAdd, CheckedDiv, CheckedMul, CheckedSub};
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

type Rational128 = num::rational::Ratio<u128>;

const POOL_SATURATION_LEVEL: Rational128 = Rational128::new_raw(1, 1000);
const PLEDGE_INFLUENCE_PARAMETER: Rational128 = Rational128::new_raw(789, 1000);

fn pool_balance_power(
    pledge_amount: Amount,
    pool_balance: Amount,
    total_supply: Amount,
) -> Option<Rational128> {
    //println!(
    //    "pledge: {:?}, balance: {:?}, total_supply: {:?}",
    //    pledge_amount, pool_balance, total_supply
    //);

    let relative_pool_stake =
        Rational128::new(pool_balance.into_atoms(), total_supply.into_atoms());
    let relative_pledge_amount =
        Rational128::new(pledge_amount.into_atoms(), total_supply.into_atoms());

    let z = POOL_SATURATION_LEVEL;
    let a = PLEDGE_INFLUENCE_PARAMETER;
    let sigma = std::cmp::min(relative_pool_stake, POOL_SATURATION_LEVEL);
    let s = std::cmp::min(relative_pledge_amount, POOL_SATURATION_LEVEL);

    assert!(
        sigma <= z,
        "Relative stake cannot be greater then saturation level"
    );
    assert!(
        s <= sigma,
        "Relative pledge cannot be greater then relative stake"
    );

    //                 ⎛            ⎛z - sigma⎞⎞
    //                 ⎜sigma - s ⋅ ⎜─────────⎟⎟
    //                 ⎜            ⎝    z    ⎠⎟
    // sigma + s ⋅ a ⋅ ⎜───────────────────────⎟
    //                 ⎝            z          ⎠
    // ─────────────────────────────────────────
    //                a + 1

    // t1 = (z - sigma) / z * s
    let t1 = z
        .checked_sub(&sigma)
        .and_then(|v| v.checked_div(&z))
        .and_then(|v| v.checked_mul(&s))?;
    // t2 = (sigma - t1) / z * a * s
    let t2 = sigma
        .checked_sub(&t1)
        .and_then(|v| v.checked_div(&z))
        .and_then(|v| v.checked_mul(&a))
        .and_then(|v| v.checked_mul(&s))?;
    // t3 = a + 1
    let t3 = a.checked_add(&1.into())?;
    let result = sigma.checked_add(&t2).and_then(|v| v.checked_div(&t3));
    result
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
    let pool_balance_power = pool_balance_power(pledge_amount, pool_balance, total_supply)
        .ok_or(ConsensusPoSError::PoolBalancePowerArithmeticsFailed)?;
    // FIXME: multiplication can overflow
    let pool_balance: Uint512 =
        (pool_balance_power * pool_balance.into_atoms()).to_integer().into();

    ensure!(
        hash <= pool_balance * target.into(),
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

// FIXME: test with netupgrade
