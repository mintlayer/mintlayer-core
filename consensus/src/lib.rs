// Copyright (c) 2021-2022 RBB S.r.l
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

//! A consensus related logic.

mod error;
mod pos;
mod pow;
mod validator;

use std::{ops::Deref, sync::Arc};

use chainstate_types::{BlockIndex, BlockIndexHandle, GenBlockIndex};
use common::{
    chain::{
        block::{
            signed_block_header::{
                BlockHeaderSignature, BlockHeaderSignatureData, SignedBlockHeader,
            },
            timestamp::BlockTimestamp,
            BlockHeader, BlockReward, ConsensusData,
        },
        output_value::OutputValue,
        timelock::OutputTimeLock,
        Block, ChainConfig, Destination, GenBlock, PoolId, RequiredConsensus, TxOutput,
    },
    primitives::{BlockHeight, Id},
};
use crypto::key::SigAuxDataProvider;
use serialization::{Decode, Encode};
use utils::atomics::RelaxedAtomicBool;

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError,
        calc_pos_hash_from_prv_key, check_pos_hash, compact_target_to_target,
        error::ConsensusPoSError,
        find_timestamp_for_staking,
        hash_check::calc_and_check_pos_hash,
        input_data::{
            generate_pos_consensus_data_and_reward, PoSFinalizeBlockInputData,
            PoSGenerateBlockInputData, PoSTimestampSearchInputData,
        },
        kernel::get_kernel_output,
        stake,
        target::{calculate_target_required, calculate_target_required_from_block_index},
        EffectivePoolBalanceError, StakeResult,
    },
    pow::{
        calculate_work_required, check_proof_of_work,
        input_data::{generate_pow_consensus_data_and_reward, PoWGenerateBlockInputData},
        mine, ConsensusPoWError, MiningResult,
    },
    validator::validate_consensus,
};

pub use pos::calculate_effective_pool_balance;

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusCreationError {
    #[error("Mining error: {0}")]
    MiningError(#[from] ConsensusPoWError),
    #[error("Mining stopped")]
    MiningStopped,
    #[error("Mining failed")]
    MiningFailed,
    #[error("Staking error: {0}")]
    StakingError(#[from] ConsensusPoSError),
    #[error("Staking failed")]
    StakingFailed,
    #[error("Staking stopped")]
    StakingStopped,
    #[error("Overflowed when calculating a block timestamp: {0} + {1}")]
    TimestampOverflow(BlockTimestamp, u64),
}

// TODO: include the original chainstate::ChainstateError in each error below.
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ChainstateError {
    #[error("Failed to obtain epoch data for epoch {epoch_index}: {error}")]
    FailedToObtainEpochData { epoch_index: u64, error: String },
    #[error("Failed to calculate median time past starting from block {0}: {1}")]
    FailedToCalculateMedianTimePast(Id<GenBlock>, String),
    #[error("Failed to obtain block index for block {0}: {1}")]
    FailedToObtainBlockIndex(Id<GenBlock>, String),
    #[error("Failed to obtain best block index: {0}")]
    FailedToObtainBestBlockIndex(String),
    #[error("Failed to obtain block id from height {0}: {1}")]
    FailedToObtainBlockIdFromHeight(BlockHeight, String),
    #[error("Failed to obtain ancestor of block {0} at height {1}: {2}")]
    FailedToObtainAncestor(Id<Block>, BlockHeight, String),
    #[error("Failed to read data of pool {0}: {1}")]
    StakePoolDataReadError(PoolId, String),
    #[error("Failed to read balance of pool {0}: {1}")]
    PoolBalanceReadError(PoolId, String),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum GenerateBlockInputData {
    #[codec(index = 0)]
    None,
    #[codec(index = 1)]
    PoW(Box<PoWGenerateBlockInputData>),
    #[codec(index = 2)]
    PoS(Box<PoSGenerateBlockInputData>),
}

#[derive(Debug, Clone)]
pub enum FinalizeBlockInputData {
    PoW,
    PoS(PoSFinalizeBlockInputData),
    None,
}

pub fn generate_consensus_data_and_reward_ignore_consensus(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> Result<(ConsensusData, BlockReward), ConsensusCreationError> {
    let consensus_data = ConsensusData::None;

    let time_lock = {
        let block_count = chain_config.empty_consensus_reward_maturity_block_count();
        OutputTimeLock::ForBlockCount(block_count.to_int())
    };

    let block_reward = BlockReward::new(vec![TxOutput::LockThenTransfer(
        OutputValue::Coin(chain_config.block_subsidy_at_height(&block_height)),
        Destination::AnyoneCanSpend,
        time_lock,
    )]);

    Ok((consensus_data, block_reward))
}

#[allow(clippy::too_many_arguments)]
pub fn finalize_consensus_data<AuxP: SigAuxDataProvider + ?Sized>(
    chain_config: &ChainConfig,
    block_header: &mut BlockHeader,
    block_height: BlockHeight,
    block_timestamp_for_pos: &mut BlockTimestamp,
    max_block_timestamp_for_pos: BlockTimestamp,
    stop_flag: Arc<RelaxedAtomicBool>,
    finalize_data: FinalizeBlockInputData,
    sig_aux_data_provider: &mut AuxP,
) -> Result<SignedBlockHeader, ConsensusCreationError> {
    match chain_config.consensus_upgrades().consensus_status(block_height.next_height()) {
        RequiredConsensus::IgnoreConsensus => Ok(block_header.clone().with_no_signature()),
        RequiredConsensus::PoS(pos_status) => match block_header.consensus_data() {
            ConsensusData::None => Err(ConsensusCreationError::StakingError(
                ConsensusPoSError::NoInputDataProvided,
            )),
            ConsensusData::PoW(_) => Err(ConsensusCreationError::StakingError(
                ConsensusPoSError::PoWInputDataProvided,
            )),
            ConsensusData::PoS(pos_data) => match finalize_data {
                FinalizeBlockInputData::None => Err(ConsensusCreationError::StakingError(
                    ConsensusPoSError::NoInputDataProvided,
                )),
                FinalizeBlockInputData::PoW => Err(ConsensusCreationError::StakingError(
                    ConsensusPoSError::PoWInputDataProvided,
                )),
                FinalizeBlockInputData::PoS(finalize_pos_data) => {
                    let stake_private_key = finalize_pos_data.stake_private_key().clone();

                    let stake_result = stake(
                        chain_config,
                        pos_status.get_chain_config(),
                        pos_data.deref().clone(),
                        block_header,
                        block_timestamp_for_pos,
                        max_block_timestamp_for_pos,
                        finalize_pos_data,
                    )?;

                    let signed_block_header = stake_private_key
                        .sign_message(&block_header.encode(), sig_aux_data_provider)
                        .map_err(|_| {
                            ConsensusCreationError::StakingError(
                                ConsensusPoSError::FailedToSignBlockHeader,
                            )
                        })
                        .map(BlockHeaderSignatureData::new)
                        .map(BlockHeaderSignature::HeaderSignature)
                        .map(|signed_data| block_header.clone().with_signature(signed_data))?;

                    match stake_result {
                        StakeResult::Success => Ok(signed_block_header),
                        StakeResult::Failed => Err(ConsensusCreationError::StakingFailed),
                        StakeResult::Stopped => Err(ConsensusCreationError::StakingStopped),
                    }
                }
            },
        },
        RequiredConsensus::PoW(_) => match block_header.consensus_data() {
            ConsensusData::None => Err(ConsensusCreationError::MiningError(
                ConsensusPoWError::NoInputDataProvided,
            )),
            ConsensusData::PoS(_) => Err(ConsensusCreationError::MiningError(
                ConsensusPoWError::PoSInputDataProvided,
            )),
            ConsensusData::PoW(pow_data) => {
                let mine_result = mine(block_header, u128::MAX, pow_data.bits(), stop_flag)?;

                match mine_result {
                    MiningResult::Success => Ok(block_header.clone().with_no_signature()),
                    MiningResult::Failed => Err(ConsensusCreationError::MiningFailed),
                    MiningResult::Stopped => Err(ConsensusCreationError::MiningStopped),
                }
            }
        },
    }
}

fn get_ancestor_from_block_index_handle(
    block_handle: &impl BlockIndexHandle,
    block_index: &BlockIndex,
    ancestor_height: BlockHeight,
) -> Result<GenBlockIndex, crate::ChainstateError> {
    block_handle.get_ancestor(block_index, ancestor_height).map_err(|err| {
        crate::ChainstateError::FailedToObtainAncestor(
            *block_index.block_id(),
            ancestor_height,
            err.to_string(),
        )
    })
}
