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

use chainstate_types::{pos_randomness::PoSRandomness, BlockIndexHandle};
use common::{
    chain::{
        block::{consensus_data::PoSData, BlockHeader},
        config::EpochIndex,
        ChainConfig, TxOutput,
    },
    primitives::{BlockHeight, Idable},
    Uint256, Uint512,
};
use pos_accounting::PoSAccountingView;
use utils::ensure;
use utxo::UtxosView;

use crate::pos::{error::ConsensusPoSError, kernel::get_kernel_output};

fn check_stake_kernel_hash<P: PoSAccountingView>(
    epoch_index: EpochIndex,
    random_seed: &PoSRandomness,
    pos_data: &PoSData,
    kernel_output: &TxOutput,
    spender_block_header: &BlockHeader,
    pos_accounting_view: &P,
) -> Result<(), ConsensusPoSError> {
    let target: Uint256 = (*pos_data.target())
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(*pos_data.target()))?;

    let hash_pos: Uint256 = PoSRandomness::from_block(
        epoch_index,
        spender_block_header,
        random_seed,
        kernel_output,
        pos_data,
    )?
    .value()
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
    current_height: BlockHeight,
    block_index_handle: &H,
) -> Result<PoSRandomness, ConsensusPoSError> {
    let sealed_epoch_index = chain_config.sealed_epoch_index(&current_height);

    let random_seed = match sealed_epoch_index {
        Some(sealed_epoch_index) => {
            let epoch_data = block_index_handle.get_epoch_data(sealed_epoch_index)?;
            match epoch_data {
                Some(d) => d.randomness().clone(),
                None => {
                    // TODO: no epoch_data means either that no epoch was created yet or
                    // that the data is actually missing
                    PoSRandomness::at_genesis(chain_config)
                }
            }
        }
        None => PoSRandomness::at_genesis(chain_config),
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

    let current_height = prev_block_index.block_height().next_height();
    let random_seed = randomness_of_sealed_epoch(chain_config, current_height, block_index_handle)?;

    let current_epoch_index = chain_config.epoch_index_from_height(&current_height);
    let kernel_output = get_kernel_output(pos_data.kernel_inputs(), utxos_view)?;
    check_stake_kernel_hash(
        current_epoch_index,
        &random_seed,
        pos_data,
        &kernel_output,
        header,
        pos_accounting_view,
    )?;
    Ok(())
}
