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
use crypto::vrf::{VRFPublicKey, VRFReturn};
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

use super::{effective_pool_balance::effective_pool_balance, PosDataExt};

fn check_pos_hash_v0(
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    target: &Uint256,
    vrf_data: &VRFReturn,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pool_balance: Amount,
) -> Result<(), ConsensusPoSError> {
    let hash: Uint256 = PoSRandomness::from_block(
        epoch_index,
        block_timestamp,
        random_seed,
        vrf_data,
        vrf_pub_key,
    )?
    .value()
    .into();

    let hash: Uint512 = hash.into();
    let pool_balance: Uint512 = pool_balance.into();

    ensure!(
        hash <= (pool_balance * (*target).into())
            .expect("Cannot fail because both were converted from smaller type"),
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_pos_hash_v1(
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    target: &Uint256,
    vrf_data: &VRFReturn,
    vrf_pub_key: &VRFPublicKey,
    block_timestamp: BlockTimestamp,
    pledge_amount: Amount,
    pool_balance: Amount,
    final_supply: Amount,
) -> Result<(), ConsensusPoSError> {
    let hash: Uint256 = PoSRandomness::from_block(
        epoch_index,
        block_timestamp,
        random_seed,
        vrf_data,
        vrf_pub_key,
    )?
    .value()
    .into();
    let hash: Uint512 = hash.into();

    let effective_balance = effective_pool_balance(pledge_amount, pool_balance, final_supply)?;
    let effective_balance: Uint512 = effective_balance.into();

    ensure!(
        hash <= (effective_balance * (*target).into())
            .expect("Cannot fail because both were converted from smaller type"),
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn check_pos_hash(
    consensus_version: PoSConsensusVersion,
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    target: &Uint256,
    vrf_data: &VRFReturn,
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
            target,
            vrf_data,
            vrf_pub_key,
            block_timestamp,
            pool_balance,
        ),
        PoSConsensusVersion::V1 => check_pos_hash_v1(
            epoch_index,
            random_seed,
            target,
            vrf_data,
            vrf_pub_key,
            block_timestamp,
            pledge_amount,
            pool_balance,
            final_supply,
        ),
        _ => Err(ConsensusPoSError::UnsupportedConsensusVersion),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn check_pos_hash_for_pos_data(
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
    check_pos_hash(
        consensus_version,
        epoch_index,
        random_seed,
        &pos_data.target()?,
        pos_data.vrf_data(),
        vrf_pub_key,
        block_timestamp,
        pledge_amount,
        pool_balance,
        final_supply,
    )
}
