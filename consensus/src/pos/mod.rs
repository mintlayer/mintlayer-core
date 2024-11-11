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

use chainstate_types::{
    pos_randomness::{PoSRandomness, PoSRandomnessError},
    vrf_tools::construct_transcript,
    BlockIndexHandle, EpochStorageRead, GenBlockIndex,
};
use common::{
    address::Address,
    chain::{
        block::{
            consensus_data::PoSData, signed_block_header::SignedBlockHeader,
            timestamp::BlockTimestamp, BlockHeader, ConsensusData,
        },
        config::EpochIndex,
        ChainConfig, CoinUnit, PoSChainConfig, PoSStatus, TxOutput,
    },
    primitives::{Amount, BlockHeight, Compact, DecimalAmount, Idable},
    Uint256,
};
use crypto::vrf::{VRFPrivateKey, VRFPublicKey, VRFReturn};
use logging::log;
use pos_accounting::PoSAccountingView;
use randomness::{CryptoRng, Rng};
use utils::ensure;
use utxo::UtxosView;

use crate::{
    pos::{block_sig::check_block_signature, error::ConsensusPoSError, kernel::get_kernel_output},
    PoSFinalizeBlockInputData,
};

pub use effective_pool_balance::{
    effective_pool_balance as calculate_effective_pool_balance, EffectivePoolBalanceError,
};
pub use hash_check::check_pos_hash;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeResult {
    Success,
    Failed,
    Stopped,
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

pub fn compact_target_to_target(compact_target: Compact) -> Result<Uint256, ConsensusPoSError> {
    let target: Uint256 = compact_target
        .try_into()
        .map_err(|_| ConsensusPoSError::BitsToTargetConversionFailed(compact_target))?;
    Ok(target)
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
        | TxOutput::DataDeposit(_)
        | TxOutput::Htlc(_, _)
        | TxOutput::CreateOrder(_) => {
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
    let pool_balance = pos_accounting_view.get_pool_balance(stake_pool_id)?;
    let staker_balance = pos_accounting_view
        .get_pool_data(stake_pool_id)?
        .ok_or(ConsensusPoSError::PoolDataNotFound(stake_pool_id))?
        .staker_balance()?;
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    hash_check::calc_and_check_pos_hash(
        pos_status.get_chain_config().consensus_version(),
        current_epoch_index,
        &random_seed,
        &compact_target_to_target(pos_data.compact_target())?,
        pos_data.vrf_data(),
        &vrf_pub_key,
        header.timestamp(),
        staker_balance,
        pool_balance,
        final_supply.to_amount_atoms(),
    )?;

    Ok(())
}

pub fn stake(
    chain_config: &ChainConfig,
    pos_config: &PoSChainConfig,
    pos_data: PoSData,
    block_header: &mut BlockHeader,
    block_timestamp: &mut BlockTimestamp,
    max_block_timestamp: BlockTimestamp,
    finalize_pos_data: PoSFinalizeBlockInputData,
) -> Result<StakeResult, ConsensusPoSError> {
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    let first_timestamp = *block_timestamp;

    // log::debug!(
    //     "Search for a valid block ({}..{}), pool_id: {}, pool balance: {}, pool pledge: {}",
    //     first_timestamp,
    //     max_block_timestamp,
    //     Address::new(chain_config, *pos_data.stake_pool_id())
    //         .expect("Pool id to address cannot fail"),
    //     DecimalAmount::from_amount_no_padding(
    //         finalize_pos_data.pool_balance(),
    //         chain_config.coin_decimals()
    //     ),
    //     DecimalAmount::from_amount_no_padding(
    //         finalize_pos_data.pledge_amount(),
    //         chain_config.coin_decimals()
    //     ),
    // );

    let tracing_span = tracing::span!(
        tracing::Level::DEBUG,
        "stake",
        pool_id = Address::new(chain_config, *pos_data.stake_pool_id())
            .expect("Pool id to address cannot fail")
            .to_string(),
        min_ts = first_timestamp.as_int_seconds(),
        max_ts = max_block_timestamp.as_int_seconds()
    );
    let _enter = tracing_span.enter();

    if let Some((found_timestamp, vrf_data)) = find_timestamp_for_staking(
        final_supply,
        pos_config,
        pos_data.compact_target(),
        first_timestamp,
        max_block_timestamp,
        finalize_pos_data.sealed_epoch_randomness(),
        finalize_pos_data.epoch_index(),
        finalize_pos_data.pledge_amount(),
        finalize_pos_data.pool_balance(),
        finalize_pos_data.vrf_private_key(),
        &mut randomness::make_true_rng(),
    )? {
        log::info!(
            "Valid block found, timestamp: {}, pool_id: {}",
            found_timestamp,
            pos_data.stake_pool_id()
        );

        let mut pos_data = pos_data;
        pos_data.update_vrf_data(vrf_data);
        block_header.update_consensus_data(ConsensusData::PoS(Box::new(pos_data)));
        block_header.update_timestamp(found_timestamp);

        *block_timestamp = found_timestamp;

        Ok(StakeResult::Success)
    } else {
        *block_timestamp = max_block_timestamp;
        Ok(StakeResult::Failed)
    }
}

pub fn calc_pos_hash_from_prv_key(
    epoch_index: EpochIndex,
    sealed_epoch_randomness: &PoSRandomness,
    block_timestamp: BlockTimestamp,
    vrf_pub_key: &VRFPublicKey,
    vrf_prv_key: &VRFPrivateKey,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Uint256, ConsensusPoSError> {
    let vrf_data = produce_vrf_data(
        epoch_index,
        sealed_epoch_randomness,
        block_timestamp,
        vrf_prv_key,
        rng,
    );

    let hash: Uint256 = PoSRandomness::from_block(
        epoch_index,
        block_timestamp,
        sealed_epoch_randomness,
        &vrf_data,
        vrf_pub_key,
    )?
    .value()
    .into();

    Ok(hash)
}

pub fn produce_vrf_data(
    epoch_index: EpochIndex,
    sealed_epoch_randomness: &PoSRandomness,
    timestamp: BlockTimestamp,
    vrf_prv_key: &VRFPrivateKey,
    rng: &mut (impl Rng + CryptoRng),
) -> VRFReturn {
    let transcript = construct_transcript(epoch_index, &sealed_epoch_randomness.value(), timestamp)
        .with_rng(&mut *rng);

    vrf_prv_key.produce_vrf_data(transcript)
}

#[allow(clippy::too_many_arguments)]
pub fn find_timestamp_for_staking(
    final_supply: CoinUnit,
    pos_config: &PoSChainConfig,
    target: Compact,
    first_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    sealed_epoch_randomness: &PoSRandomness,
    epoch_index: EpochIndex,
    pledge_amount: Amount,
    pool_balance: Amount,
    vrf_prv_key: &VRFPrivateKey,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Option<(BlockTimestamp, VRFReturn)>, ConsensusPoSError> {
    let vrf_pub_key = VRFPublicKey::from_private_key(vrf_prv_key);
    let target = compact_target_to_target(target)?;
    let final_supply = final_supply.to_amount_atoms();

    ensure!(
        first_timestamp <= max_timestamp,
        ConsensusPoSError::FutureTimestampInThePast
    );

    for timestamp in first_timestamp.iter_up_to_including(max_timestamp) {
        let vrf_data = produce_vrf_data(
            epoch_index,
            sealed_epoch_randomness,
            timestamp,
            vrf_prv_key,
            rng,
        );

        if hash_check::calc_and_check_pos_hash(
            pos_config.consensus_version(),
            epoch_index,
            sealed_epoch_randomness,
            &target,
            &vrf_data,
            &vrf_pub_key,
            timestamp,
            pledge_amount,
            pool_balance,
            final_supply,
        )
        .is_ok()
        {
            return Ok(Some((timestamp, vrf_data)));
        }
    }

    Ok(None)
}
