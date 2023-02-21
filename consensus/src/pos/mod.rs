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

pub mod error;
pub mod kernel;

use chainstate_types::{vrf_tools::verify_vrf_and_get_vrf_output, BlockIndexHandle};
use common::{
    chain::{
        block::{consensus_data::PoSData, BlockHeader},
        config::EpochIndex,
        ChainConfig, OutputPurpose, TxOutput,
    },
    primitives::{Idable, H256},
    Uint256, Uint512,
};
use pos_accounting::PoSAccountingView;
use utils::ensure;
use utxo::UtxosView;

use crate::pos::{error::ConsensusPoSError, kernel::get_kernel_output};

fn check_stake_kernel_hash<P: PoSAccountingView>(
    epoch_index: EpochIndex,
    random_seed: &H256,
    pos_data: &PoSData,
    kernel_output: &TxOutput,
    spender_block_header: &BlockHeader,
    pos_accounting_view: &P,
) -> Result<(), ConsensusPoSError> {
    let target: Uint256 = (*pos_data.bits())
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(*pos_data.bits()))?;

    let pool_data = match kernel_output.purpose() {
        OutputPurpose::Transfer(_)
        | OutputPurpose::LockThenTransfer(_, _)
        | OutputPurpose::Burn => {
            // only pool outputs can be staked
            return Err(ConsensusPoSError::InvalidOutputPurposeInStakeKernel(
                spender_block_header.get_id(),
            ));
        }

        OutputPurpose::StakePool(d) => d.as_ref(),
    };

    let hash_pos: Uint256 = verify_vrf_and_get_vrf_output(
        epoch_index,
        random_seed,
        pos_data.vrf_data(),
        pool_data.vrf_public_key(),
        spender_block_header,
    )?
    .into();

    let hash_pos_arith: Uint512 = hash_pos.into();

    let stake_pool_id = *pos_data.stake_pool_id();
    let pool_balance: Uint512 = pos_accounting_view
        .get_pool_balance(stake_pool_id)?
        .ok_or(ConsensusPoSError::PoolBalanceNotFound(stake_pool_id))?
        .into();

    ensure!(
        hash_pos_arith <= pool_balance * target.into(),
        ConsensusPoSError::StakeKernelHashTooHigh
    );

    Ok(())
}

fn randomness_of_sealed_epoch<H: BlockIndexHandle>(
    chain_config: &ChainConfig,
    current_epoch_index: EpochIndex,
    block_index_handle: &H,
) -> Result<H256, ConsensusPoSError> {
    let sealed_epoch_distance_from_tip = chain_config.sealed_epoch_distance_from_tip() as u64;
    let random_seed = if current_epoch_index >= sealed_epoch_distance_from_tip {
        let sealed_epoch_index = current_epoch_index
            .checked_sub(sealed_epoch_distance_from_tip)
            .expect("must've been already checked for underflow");
        let epoch_data = block_index_handle.get_epoch_data(sealed_epoch_index)?;
        match epoch_data {
            Some(d) => d.randomness(),
            None => {
                // TODO: no epoch_data means either that no epoch was created yet or
                // that the data is actually missing
                chain_config.initial_randomness()
            }
        }
    } else {
        chain_config.initial_randomness()
    };
    Ok(random_seed)
}

pub fn check_proof_of_stake<H, U, P>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    pos_data: &PoSData,
    block_index_handle: &H,
    utxos_view: &U,
    pos_accounting_view: &P,
) -> Result<(), ConsensusPoSError>
where
    H: BlockIndexHandle,
    U: UtxosView,
    P: PoSAccountingView,
{
    let prev_block_index = block_index_handle
        .get_gen_block_index(header.prev_block_id())?
        .ok_or_else(|| ConsensusPoSError::PrevBlockIndexNotFound(header.get_id()))?;

    let kernel_output = get_kernel_output(pos_data, utxos_view)?;

    let epoch_index =
        chain_config.epoch_index_from_height(&prev_block_index.block_height().next_height());

    let random_seed = randomness_of_sealed_epoch(chain_config, epoch_index, block_index_handle)?;

    check_stake_kernel_hash(
        epoch_index,
        &random_seed,
        pos_data,
        &kernel_output,
        header,
        pos_accounting_view,
    )?;
    Ok(())
}
