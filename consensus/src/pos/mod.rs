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

pub mod block_sig;
pub mod error;
pub mod hash_check;
pub mod input_data;
pub mod kernel;
pub mod target;

mod effective_pool_balance;
use common::chain::config::EpochIndex;
use common::chain::CoinUnit;
use common::primitives::Amount;
use common::Uint256;
use crypto::vrf::VRFPrivateKey;
use crypto::vrf::VRFPublicKey;
use crypto::vrf::VRFReturn;
pub use effective_pool_balance::effective_pool_balance as calculate_effective_pool_balance;
pub use effective_pool_balance::EffectivePoolBalanceError;

use chainstate_types::{
    pos_randomness::{PoSRandomness, PoSRandomnessError},
    vrf_tools::construct_transcript,
    BlockIndexHandle, EpochStorageRead, GenBlockIndex,
};
use common::{
    chain::{
        block::{
            consensus_data::PoSData, signed_block_header::SignedBlockHeader,
            timestamp::BlockTimestamp,
        },
        ChainConfig, PoSChainConfig, PoSStatus, TxOutput,
    },
    primitives::{BlockHeight, Idable},
};
use pos_accounting::PoSAccountingView;
use utils::ensure;
use utxo::UtxosView;

use crate::{
    pos::{block_sig::check_block_signature, error::ConsensusPoSError, kernel::get_kernel_output},
    PoSFinalizeBlockInputData,
};

pub trait PosDataExt {
    fn target(&self) -> Result<Uint256, ConsensusPoSError>;
}

impl PosDataExt for PoSData {
    fn target(&self) -> Result<Uint256, ConsensusPoSError> {
        let target: Uint256 = self
            .compact_target()
            .try_into()
            .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(self.compact_target()))?;
        Ok(target)
    }
}

fn randomness_of_sealed_epoch<S: EpochStorageRead>(
    chain_config: &ChainConfig,
    current_height: BlockHeight,
    epoch_storage: &S,
) -> Result<PoSRandomness, ConsensusPoSError> {
    let sealed_epoch_index = chain_config.sealed_epoch_index(&current_height);

    let random_seed = match sealed_epoch_index {
        Some(sealed_epoch_index) => {
            let epoch_data = epoch_storage.get_epoch_data(sealed_epoch_index)?;
            match epoch_data {
                Some(d) => *d.randomness(),
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

/// Proof of stake cannot have timestamp equal to previous block, since stake hash would be the same
pub fn enforce_timestamp_ordering(
    prev_block_index: &GenBlockIndex,
    header: &SignedBlockHeader,
) -> Result<(), ConsensusPoSError> {
    let prev_block_timestamp = prev_block_index.block_timestamp();

    ensure!(
        header.timestamp() > prev_block_timestamp,
        ConsensusPoSError::PoSBlockTimeStrictOrderInvalid(header.get_id())
    );

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn check_proof_of_stake<H, E, U, P>(
    chain_config: &ChainConfig,
    pos_status: &PoSStatus,
    header: &SignedBlockHeader,
    pos_data: &PoSData,
    block_index_handle: &H,
    epoch_data_storage: &E,
    utxos_view: &U,
    pos_accounting_view: &P,
) -> Result<(), ConsensusPoSError>
where
    H: BlockIndexHandle,
    E: EpochStorageRead,
    U: UtxosView,
    P: PoSAccountingView<Error = pos_accounting::Error>,
{
    let target = target::calculate_target_required(
        chain_config,
        pos_status,
        *header.prev_block_id(),
        block_index_handle,
    )?;

    utils::ensure!(
        target == pos_data.compact_target(),
        ConsensusPoSError::InvalidTarget(pos_data.compact_target())
    );

    let prev_block_index = block_index_handle
        .get_gen_block_index(header.prev_block_id())?
        .ok_or_else(|| ConsensusPoSError::PrevBlockIndexNotFound(header.get_id()))?;

    enforce_timestamp_ordering(&prev_block_index, header)?;

    let current_height = prev_block_index.block_height().next_height();
    let random_seed = randomness_of_sealed_epoch(chain_config, current_height, epoch_data_storage)?;

    let current_epoch_index = chain_config.epoch_index_from_height(&current_height);
    let kernel_output = get_kernel_output(pos_data.kernel_inputs(), utxos_view)?;

    // Proof of stake mandates signing the block with the same key of the kernel output
    check_block_signature(header, &kernel_output)?;

    let vrf_pub_key = match kernel_output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_) => {
            // only pool outputs can be staked
            return Err(ConsensusPoSError::RandomnessError(
                PoSRandomnessError::InvalidOutputTypeInStakeKernel(header.get_id()),
            ));
        }
        TxOutput::CreateStakePool(_, d) => d.as_ref().vrf_public_key().clone(),
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            let pool_data = pos_accounting_view
                .get_pool_data(pool_id)?
                .ok_or(ConsensusPoSError::PoolDataNotFound(pool_id))?;
            pool_data.vrf_public_key().clone()
        }
    };

    let stake_pool_id = *pos_data.stake_pool_id();
    let pool_balance = pos_accounting_view
        .get_pool_balance(stake_pool_id)?
        .ok_or(ConsensusPoSError::PoolBalanceNotFound(stake_pool_id))?;
    let staker_balance = pos_accounting_view
        .get_pool_data(stake_pool_id)?
        .ok_or(ConsensusPoSError::PoolDataNotFound(stake_pool_id))?
        .staker_balance()?;
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    hash_check::check_pos_hash_for_pos_data(
        pos_status.get_chain_config().consensus_version(),
        current_epoch_index,
        &random_seed,
        pos_data,
        &vrf_pub_key,
        header.timestamp(),
        staker_balance,
        pool_balance,
        final_supply.to_amount_atoms(),
    )?;

    Ok(())
}

pub fn find_timestamp_for_staking(
    chain_config: &ChainConfig,
    pos_config: &PoSChainConfig,
    target: &Uint256,
    first_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    finalize_pos_data: &PoSFinalizeBlockInputData,
) -> Result<Option<(BlockTimestamp, VRFReturn)>, ConsensusPoSError> {
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    find_timestamp_for_staking_impl(
        final_supply,
        pos_config,
        target,
        first_timestamp,
        max_timestamp,
        finalize_pos_data.sealed_epoch_randomness(),
        finalize_pos_data.epoch_index(),
        finalize_pos_data.pledge_amount(),
        finalize_pos_data.pool_balance(),
        finalize_pos_data.vrf_private_key(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn find_timestamp_for_staking_impl(
    final_supply: CoinUnit,
    pos_config: &PoSChainConfig,
    target: &Uint256,
    first_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    sealed_epoch_randomness: &PoSRandomness,
    epoch_index: EpochIndex,
    pledge_amount: Amount,
    pool_balance: Amount,
    vrf_private_key: &VRFPrivateKey,
) -> Result<Option<(BlockTimestamp, VRFReturn)>, ConsensusPoSError> {
    let vrf_pk = VRFPublicKey::from_private_key(vrf_private_key);

    ensure!(
        first_timestamp <= max_timestamp,
        ConsensusPoSError::FutureTimestampInThePast
    );

    let mut timestamp = first_timestamp;

    loop {
        let vrf_data = {
            let transcript =
                construct_transcript(epoch_index, &sealed_epoch_randomness.value(), timestamp);

            vrf_private_key.produce_vrf_data(transcript)
        };

        if hash_check::check_pos_hash(
            pos_config.consensus_version(),
            epoch_index,
            sealed_epoch_randomness,
            target,
            &vrf_data,
            &vrf_pk,
            timestamp,
            pledge_amount,
            pool_balance,
            final_supply.to_amount_atoms(),
        )
        .is_ok()
        {
            return Ok(Some((timestamp, vrf_data)));
        }

        if timestamp == max_timestamp {
            return Ok(None);
        }

        timestamp = timestamp
            .add_int_seconds(1)
            .expect("timestamp can't overflow if it's below the maximum");
    }
}
