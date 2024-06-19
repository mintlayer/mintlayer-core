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
pub mod pos_block_candidate_info;
pub mod target;

mod effective_pool_balance;

use std::sync::Arc;

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
            timestamp::BlockTimestamp,
        },
        config::EpochIndex,
        get_pos_block_proof, ChainConfig, CoinUnit, PoSStatus, PoolId, TxOutput,
    },
    primitives::{BlockHeight, Compact, Idable},
    Uint256,
};
use crypto::vrf::{VRFPrivateKey, VRFPublicKey, VRFReturn};
use logging::log;
use pos_accounting::PoSAccountingView;
use randomness::{CryptoRng, Rng};
use sorted_iter::SortedIterator;
use tokio::sync::watch;
use utils::{atomics::RelaxedAtomicBool, ensure};
use utxo::UtxosView;

use crate::{
    calc_and_check_pos_hash,
    pos::{block_sig::check_block_signature, error::ConsensusPoSError, kernel::get_kernel_output},
    PoSBlockCandidateInfoCmpByParentTS,
};

pub use effective_pool_balance::{
    effective_pool_balance as calculate_effective_pool_balance, EffectivePoolBalanceError,
};
pub use hash_check::check_pos_hash;

use self::pos_block_candidate_info::PoSBlockCandidateInfo;

#[must_use]
#[derive(Debug, Clone)]
pub enum StakeResult<'a> {
    Success {
        block_candidate_info: &'a PoSBlockCandidateInfo,
        timestamp: BlockTimestamp,
        vrf_data: VRFReturn,
    },
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

/// For each timestamp in the range, try to stake using all possible parent blocks that
/// can be chosen for a block with that timestamp. The information about possible parents
/// is provided via `candidate_infos_iter`.
/// If multiple parents can be chosen, use the one that gives the biggest chain trust.
#[allow(clippy::too_many_arguments)]
pub fn stake<'a>(
    chain_config: &ChainConfig,
    pool_id: &PoolId,
    vrf_prv_key: &VRFPrivateKey,
    candidate_infos_iter: impl SortedIterator<Item = &'a PoSBlockCandidateInfoCmpByParentTS> + Clone,
    min_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    last_used_block_timestamp_sender: Option<&watch::Sender<BlockTimestamp>>,
    stop_flag: Option<Arc<RelaxedAtomicBool>>,
) -> Result<StakeResult<'a>, ConsensusPoSError> {
    let final_supply = chain_config
        .final_supply()
        .ok_or(ConsensusPoSError::FiniteTotalSupplyIsRequired)?;

    log::debug!(
        "Search for a valid block ({}..{}), pool_id: {}",
        min_timestamp,
        max_timestamp,
        Address::new(chain_config, *pool_id).expect("Pool id to address cannot fail")
    );

    let stake_result = stake_impl(
        final_supply,
        vrf_prv_key,
        candidate_infos_iter,
        min_timestamp,
        max_timestamp,
        last_used_block_timestamp_sender,
        stop_flag,
        &mut randomness::make_true_rng(),
    )?;

    if let StakeResult::Success {
        block_candidate_info: _,
        timestamp,
        vrf_data: _vrf_data,
    } = &stake_result
    {
        log::info!(
            "Valid block found, timestamp: {}, pool_id: {}",
            timestamp,
            pool_id
        );
    }

    Ok(stake_result)
}

/// A lower-level variant of `stake` to be called from tests.
#[allow(clippy::too_many_arguments)]
pub fn stake_impl<'a>(
    final_supply: CoinUnit,
    vrf_prv_key: &VRFPrivateKey,
    candidate_infos_iter: impl SortedIterator<Item = &'a PoSBlockCandidateInfoCmpByParentTS> + Clone,
    min_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    last_used_block_timestamp_sender: Option<&watch::Sender<BlockTimestamp>>,
    stop_flag: Option<Arc<RelaxedAtomicBool>>,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<StakeResult<'a>, ConsensusPoSError> {
    let final_supply = final_supply.to_amount_atoms();
    let vrf_pub_key = VRFPublicKey::from_private_key(vrf_prv_key);

    ensure!(
        min_timestamp <= max_timestamp,
        ConsensusPoSError::FutureTimestampInThePast
    );

    for timestamp in min_timestamp.iter_up_to_including(max_timestamp) {
        let mut best_result = None;
        let candidate_infos_iter = candidate_infos_iter.clone();

        for candidate_info in candidate_infos_iter {
            let candidate_info = &candidate_info.0;
            if candidate_info.parent_timestamp >= timestamp {
                break;
            }

            let vrf_data = produce_vrf_data(
                candidate_info.epoch_index,
                &candidate_info.sealed_epoch_randomness,
                timestamp,
                vrf_prv_key,
                rng,
            );

            if calc_and_check_pos_hash(
                candidate_info.pos_chain_config.consensus_version(),
                candidate_info.epoch_index,
                &candidate_info.sealed_epoch_randomness,
                &candidate_info.target,
                &vrf_data,
                &vrf_pub_key,
                timestamp,
                candidate_info.staker_balance,
                candidate_info.total_balance,
                final_supply,
            )
            .is_ok()
            {
                let block_proof = get_pos_block_proof(candidate_info.parent_timestamp, timestamp)
                    .ok_or(ConsensusPoSError::BlockProofCalculationError {
                    parent_block_timestamp: candidate_info.parent_timestamp,
                    new_block_timestamp: timestamp,
                })?;
                let chain_trust = (candidate_info.parent_chain_trust + block_proof).ok_or(
                    ConsensusPoSError::ChainTrustCalculationOverflow {
                        parent_block_chain_trust: candidate_info.parent_chain_trust,
                        new_block_proof: block_proof,
                    },
                )?;

                let prev_best_chain_trust =
                    best_result.as_ref().map_or(Uint256::ZERO, |(chain_trust, _, _)| *chain_trust);

                if chain_trust > prev_best_chain_trust {
                    best_result = Some((chain_trust, vrf_data, candidate_info));
                }
            }
        }

        if let Some(last_used_block_timestamp_sender) = last_used_block_timestamp_sender {
            let _ = last_used_block_timestamp_sender.send(timestamp);
        }

        if let Some((_, vrf_data, block_candidate_info)) = best_result {
            return Ok(StakeResult::Success {
                block_candidate_info,
                timestamp,
                vrf_data,
            });
        }

        if stop_flag.as_ref().is_some_and(|stop_flag| stop_flag.load()) {
            return Ok(StakeResult::Stopped);
        }
    }

    Ok(StakeResult::Failed)
}
