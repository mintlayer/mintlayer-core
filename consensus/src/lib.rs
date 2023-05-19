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

use std::sync::{atomic::AtomicBool, Arc};

use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, GenBlockIndex, PropertyQueryError,
};
use common::{
    chain::block::{
        consensus_data::PoWData,
        signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData, SignedBlockHeader},
        timestamp::BlockTimestamp,
        BlockHeader, ConsensusData,
    },
    chain::{ChainConfig, RequiredConsensus},
    primitives::BlockHeight,
};
use serialization::{Decode, Encode};

use crate::pos::input_data::generate_pos_consensus_data;

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError,
        check_pos_hash,
        error::ConsensusPoSError,
        input_data::{PoSFinalizeBlockInputData, PoSGenerateBlockInputData},
        kernel::get_kernel_output,
        stake,
        target::calculate_target_required,
        target::calculate_target_required_from_block_index,
        StakeResult,
    },
    pow::{calculate_work_required, check_proof_of_work, mine, ConsensusPoWError, MiningResult},
    validator::validate_consensus,
};

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusCreationError {
    #[error("Mining error")]
    MiningError(#[from] ConsensusPoWError),
    #[error("Mining stopped")]
    MiningStopped,
    #[error("Mining failed")]
    MiningFailed,
    #[error("Staking error")]
    StakingError(#[from] ConsensusPoSError),
    #[error("Staking failed")]
    StakingFailed,
    #[error("Staking stopped")]
    StakingStopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum GenerateBlockInputData {
    #[codec(index = 0)]
    PoW,
    #[codec(index = 1)]
    PoS(Box<PoSGenerateBlockInputData>),
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum FinalizeBlockInputData {
    PoW,
    PoS(PoSFinalizeBlockInputData),
}

pub fn generate_consensus_data<G>(
    chain_config: &ChainConfig,
    prev_block_index: &GenBlockIndex,
    sealed_epoch_randomness: Option<PoSRandomness>,
    input_data: Option<GenerateBlockInputData>,
    block_timestamp: BlockTimestamp,
    block_height: BlockHeight,
    get_ancestor: G,
) -> Result<ConsensusData, ConsensusCreationError>
where
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    match chain_config.net_upgrade().consensus_status(block_height) {
        RequiredConsensus::IgnoreConsensus => Ok(ConsensusData::None),
        RequiredConsensus::PoS(pos_status) => match input_data {
            Some(GenerateBlockInputData::PoS(pos_input_data)) => generate_pos_consensus_data(
                chain_config,
                prev_block_index,
                *pos_input_data,
                pos_status,
                sealed_epoch_randomness,
                block_timestamp,
                block_height,
                get_ancestor,
            ),
            Some(GenerateBlockInputData::PoW) => Err(ConsensusPoSError::PoWInputDataProvided)?,
            None => Err(ConsensusPoSError::NoInputDataProvided)?,
        },
        RequiredConsensus::PoW(pow_status) => {
            let work_required = calculate_work_required(
                chain_config,
                prev_block_index,
                block_timestamp,
                &pow_status,
                get_ancestor,
            )?;

            Ok(ConsensusData::PoW(PoWData::new(work_required, 0)))
        }
    }
}

pub fn finalize_consensus_data(
    chain_config: &ChainConfig,
    block_header: &mut BlockHeader,
    block_height: BlockHeight,
    stop_flag: Arc<AtomicBool>,
    finalize_data: Option<FinalizeBlockInputData>,
) -> Result<SignedBlockHeader, ConsensusCreationError> {
    match chain_config.net_upgrade().consensus_status(block_height.next_height()) {
        RequiredConsensus::IgnoreConsensus => Ok(block_header.clone().with_no_signature()),
        RequiredConsensus::PoS(_) => match block_header.consensus_data() {
            ConsensusData::None => Err(ConsensusCreationError::StakingError(
                ConsensusPoSError::NoInputDataProvided,
            )),
            ConsensusData::PoW(_) => Err(ConsensusCreationError::StakingError(
                ConsensusPoSError::PoWInputDataProvided,
            )),
            ConsensusData::PoS(pos_data) => match finalize_data {
                None => Err(ConsensusCreationError::StakingError(
                    ConsensusPoSError::NoInputDataProvided,
                )),
                Some(FinalizeBlockInputData::PoW) => Err(ConsensusCreationError::StakingError(
                    ConsensusPoSError::PoWInputDataProvided,
                )),
                Some(FinalizeBlockInputData::PoS(finalize_pos_data)) => {
                    let stake_private_key = finalize_pos_data.stake_private_key().clone();

                    let stake_result = stake(
                        &mut pos_data.clone(),
                        block_header,
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
