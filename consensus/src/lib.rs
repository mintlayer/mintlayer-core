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
    vrf_tools::construct_transcript, BlockIndex, EpochData, GenBlockIndex, PropertyQueryError,
};
use common::{
    chain::block::{
        consensus_data::{PoSData, PoWData},
        signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData, SignedBlockHeader},
        timestamp::BlockTimestamp,
        BlockHeader, BlockRewardTransactable, ConsensusData,
    },
    chain::{
        signature::{
            inputsig::{standard_signature::StandardInputSignature, InputWitness},
            sighash::sighashtype::SigHashType,
        },
        ChainConfig, Destination, RequiredConsensus, TxOutput,
    },
    primitives::BlockHeight,
};
use serialization::{Decode, Encode};

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
    sealed_epoch_randomness: Option<EpochData>,
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
        RequiredConsensus::PoS(pos_status) => {
            let pos_input_data = match input_data {
                Some(GenerateBlockInputData::PoS(pos_input_data)) => pos_input_data,
                Some(GenerateBlockInputData::PoW) => Err(ConsensusPoSError::PoWInputDataProvided)?,
                None => Err(ConsensusPoSError::NoInputDataProvided)?,
            };

            let reward_destination = Destination::PublicKey(pos_input_data.stake_public_key());

            let kernel_output = vec![TxOutput::ProduceBlockFromStake(
                reward_destination.clone(),
                pos_input_data.pool_id(),
            )];

            let block_reward = BlockRewardTransactable::new(
                Some(pos_input_data.kernel_inputs()),
                Some(&kernel_output),
                None,
            );

            let kernel_input_utxos = pos_input_data.kernel_input_utxos();

            let signature = StandardInputSignature::produce_uniparty_signature_for_input(
                pos_input_data.stake_private_key(),
                SigHashType::default(),
                reward_destination,
                &block_reward,
                &kernel_input_utxos.iter().collect::<Vec<_>>(),
                0,
            )
            .map_err(|_| ConsensusPoSError::FailedToSignKernel)?;

            let input_witness = InputWitness::Standard(StandardInputSignature::new(
                SigHashType::default(),
                signature.encode(),
            ));

            let vrf_data = {
                let sealed_epoch_randomness = sealed_epoch_randomness
                    .ok_or(ConsensusPoSError::NoEpochData)?
                    .randomness()
                    .value();

                let transcript = construct_transcript(
                    chain_config.epoch_index_from_height(&block_height),
                    &sealed_epoch_randomness,
                    block_timestamp,
                );

                pos_input_data.vrf_private_key().produce_vrf_data(transcript.into())
            };

            let target_required = calculate_target_required_from_block_index(
                chain_config,
                &pos_status,
                prev_block_index,
                get_ancestor,
            )?;

            Ok(ConsensusData::PoS(Box::new(PoSData::new(
                pos_input_data.kernel_inputs().clone(),
                vec![input_witness],
                pos_input_data.pool_id(),
                vrf_data,
                target_required,
            ))))
        }
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
