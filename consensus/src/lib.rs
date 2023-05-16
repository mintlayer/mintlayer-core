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
    pos_randomness::PoSRandomness, vrf_tools::construct_transcript, BlockIndex, EpochData,
    GenBlockIndex, PropertyQueryError,
};
use common::{
    chain::block::{
        consensus_data::{PoSData, PoWData},
        signed_block_header::SignedBlockHeader,
        timestamp::BlockTimestamp,
        BlockHeader, ConsensusData,
    },
    chain::{
        block::signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData},
        config::EpochIndex,
        signature::inputsig::InputWitness,
        ChainConfig, PoolId, RequiredConsensus, TxInput,
    },
    primitives::{Amount, BlockHeight},
};
use crypto::{
    key::PrivateKey,
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use serialization::{Decode, Encode};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError, check_pos_hash, error::ConsensusPoSError,
        kernel::get_kernel_output, stake, target::calculate_target_required,
        target::calculate_target_required_from_block_index, StakeResult,
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
    PoW,
    PoS(Box<PoSGenerateBlockInputData>),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PoSGenerateBlockInputData {
    stake_private_key: PrivateKey,
    vrf_private_key: VRFPrivateKey,
    pool_id: PoolId,
    kernel_input: TxInput,
    kernel_witness: InputWitness,
}

impl PoSGenerateBlockInputData {
    pub fn kernel_input(&self) -> &TxInput {
        &self.kernel_input
    }

    pub fn kernel_witness(&self) -> &InputWitness {
        &self.kernel_witness
    }

    pub fn pool_id(&self) -> PoolId {
        self.pool_id
    }

    pub fn stake_private_key(&self) -> &PrivateKey {
        &self.stake_private_key
    }

    pub fn vrf_private_key(&self) -> &VRFPrivateKey {
        &self.vrf_private_key
    }
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum FinalizeBlockInputData {
    PoW,
    PoS(PoSFinalizeBlockInputData),
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct PoSFinalizeBlockInputData {
    stake_private_key: PrivateKey,
    vrf_private_key: VRFPrivateKey,
    epoch_index: EpochIndex,
    sealed_epoch_randomness: PoSRandomness,
    previous_block_timestamp: BlockTimestamp,
    max_block_timestamp: BlockTimestamp,
    pool_balance: Amount,
}

impl PoSFinalizeBlockInputData {
    pub fn new(
        stake_private_key: PrivateKey,
        vrf_private_key: VRFPrivateKey,
        epoch_index: EpochIndex,
        sealed_epoch_randomness: PoSRandomness,
        previous_block_timestamp: BlockTimestamp,
        max_block_timestamp: BlockTimestamp,
        pool_balance: Amount,
    ) -> Self {
        Self {
            stake_private_key,
            vrf_private_key,
            epoch_index,
            sealed_epoch_randomness,
            previous_block_timestamp,
            max_block_timestamp,
            pool_balance,
        }
    }

    pub fn epoch_index(&self) -> EpochIndex {
        self.epoch_index
    }

    pub fn max_block_timestamp(&self) -> BlockTimestamp {
        self.max_block_timestamp
    }

    pub fn pool_balance(&self) -> Amount {
        self.pool_balance
    }

    pub fn previous_block_timestamp(&self) -> BlockTimestamp {
        self.previous_block_timestamp
    }

    pub fn sealed_epoch_randomness(&self) -> &PoSRandomness {
        &self.sealed_epoch_randomness
    }

    pub fn stake_private_key(&self) -> &PrivateKey {
        &self.stake_private_key
    }

    pub fn vrf_private_key(&self) -> &VRFPrivateKey {
        &self.vrf_private_key
    }

    pub fn vrf_public_key(&self) -> VRFPublicKey {
        VRFPublicKey::from_private_key(&self.vrf_private_key)
    }
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

            let vrf_data = {
                let sealed_epoch_randomness =
                    sealed_epoch_randomness.ok_or(ConsensusPoSError::NoEpochData)?;

                let transcript = construct_transcript(
                    chain_config.epoch_index_from_height(&block_height),
                    &sealed_epoch_randomness.randomness().value(),
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
                vec![pos_input_data.kernel_input().clone()],
                vec![pos_input_data.kernel_witness().clone()],
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
