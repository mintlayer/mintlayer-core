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

use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
use common::{
    chain::block::{consensus_data::PoWData, ConsensusData},
    chain::{
        block::{timestamp::BlockTimestamp, BlockHeader},
        ChainConfig, RequiredConsensus,
    },
    primitives::BlockHeight,
};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        block_sig::BlockSignatureError, check_pos_hash, error::ConsensusPoSError,
        kernel::get_kernel_output, target::calculate_target_required,
        target::calculate_target_required_from_block_index,
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
}

pub fn generate_consensus_data<G>(
    chain_config: &ChainConfig,
    prev_block_index: &GenBlockIndex,
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
            let _target_required = calculate_target_required_from_block_index(
                chain_config,
                &pos_status,
                prev_block_index,
                get_ancestor,
            );

            unimplemented!();
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
) -> Result<(), ConsensusCreationError> {
    match chain_config.net_upgrade().consensus_status(block_height.next_height()) {
        RequiredConsensus::IgnoreConsensus => Ok(()),
        RequiredConsensus::PoS(_) => unimplemented!(),
        RequiredConsensus::PoW(_) => match block_header.consensus_data() {
            ConsensusData::None => Ok(()),
            ConsensusData::PoS(_) => unimplemented!(),
            ConsensusData::PoW(pow_data) => {
                let mine_result = mine(block_header, u128::MAX, pow_data.bits(), stop_flag)?;

                match mine_result {
                    MiningResult::Success => Ok(()),
                    MiningResult::Failed => Err(ConsensusCreationError::MiningFailed),
                    MiningResult::Stopped => Err(ConsensusCreationError::MiningStopped),
                }
            }
        },
    }
}
