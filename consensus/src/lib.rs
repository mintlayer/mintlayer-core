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

pub use pos::calculate_effective_pool_balance;

use std::sync::Arc;

use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, GenBlockIndex, PropertyQueryError,
};
use common::{
    chain::block::{
        signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData, SignedBlockHeader},
        timestamp::BlockTimestamp,
        BlockHeader, BlockReward, ConsensusData,
    },
    chain::{
        output_value::OutputValue, timelock::OutputTimeLock, ChainConfig, Destination,
        RequiredConsensus, TxOutput,
    },
    primitives::BlockHeight,
};
use serialization::{Decode, Encode};
use utils::atomics::{AcqRelAtomicU64, RelaxedAtomicBool};

use crate::pos::input_data::generate_pos_consensus_data_and_reward;
use crate::pow::input_data::generate_pow_consensus_data_and_reward;

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError,
        error::{ChainstateError, ConsensusPoSError},
        hash_check::check_pos_hash,
        input_data::{PoSFinalizeBlockInputData, PoSGenerateBlockInputData},
        kernel::get_kernel_output,
        stake,
        target::calculate_target_required,
        target::calculate_target_required_from_block_index,
        StakeResult,
    },
    pow::{
        calculate_work_required, check_proof_of_work, input_data::PoWGenerateBlockInputData, mine,
        ConsensusPoWError, MiningResult,
    },
    validator::validate_consensus,
};

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusCreationError {
    #[error("Best block index not found")]
    BestBlockIndexNotFound,
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

pub fn generate_consensus_data_and_reward<G>(
    chain_config: &ChainConfig,
    prev_block_index: &GenBlockIndex,
    sealed_epoch_randomness: PoSRandomness,
    input_data: GenerateBlockInputData,
    block_timestamp: BlockTimestamp,
    block_height: BlockHeight,
    get_ancestor: G,
) -> Result<(ConsensusData, BlockReward), ConsensusCreationError>
where
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    match chain_config.consensus_upgrades().consensus_status(block_height) {
        RequiredConsensus::IgnoreConsensus => {
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
        RequiredConsensus::PoS(pos_status) => match input_data {
            GenerateBlockInputData::PoS(pos_input_data) => generate_pos_consensus_data_and_reward(
                chain_config,
                prev_block_index,
                *pos_input_data,
                pos_status,
                sealed_epoch_randomness,
                block_timestamp,
                block_height,
                get_ancestor,
            ),
            GenerateBlockInputData::PoW(_) => Err(ConsensusPoSError::PoWInputDataProvided)?,
            GenerateBlockInputData::None => Err(ConsensusPoSError::NoInputDataProvided)?,
        },
        RequiredConsensus::PoW(pow_status) => match input_data {
            GenerateBlockInputData::PoW(pow_input_data) => generate_pow_consensus_data_and_reward(
                chain_config,
                prev_block_index,
                block_timestamp,
                &pow_status,
                get_ancestor,
                *pow_input_data,
                block_height,
            )
            .map_err(ConsensusCreationError::MiningError),
            GenerateBlockInputData::PoS(_) => Err(ConsensusCreationError::MiningError(
                ConsensusPoWError::PoSInputDataProvided,
            )),
            GenerateBlockInputData::None => Err(ConsensusCreationError::MiningError(
                ConsensusPoWError::NoInputDataProvided,
            )),
        },
    }
}

pub fn finalize_consensus_data(
    chain_config: &ChainConfig,
    block_header: &mut BlockHeader,
    block_height: BlockHeight,
    block_timestamp_seconds: Arc<AcqRelAtomicU64>,
    stop_flag: Arc<RelaxedAtomicBool>,
    finalize_data: FinalizeBlockInputData,
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
                        &mut pos_data.clone(),
                        block_header,
                        Arc::clone(&block_timestamp_seconds),
                        finalize_pos_data,
                        stop_flag,
                    )?;

                    let signed_block_header = stake_private_key
                        .sign_message(&block_header.encode())
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
