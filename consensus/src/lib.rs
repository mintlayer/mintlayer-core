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

use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
use common::{
    chain::block::{consensus_data::PoWData, BlockHeader, ConsensusData},
    chain::{Block, ChainConfig, RequiredConsensus},
    primitives::{BlockHeight, Id},
};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{
        check_pos_hash, error::ConsensusPoSError, kernel::get_kernel_output,
        target::calculate_target_required,
    },
    pow::{calculate_work_required, check_proof_of_work, mine, ConsensusPoWError},
    validator::validate_consensus,
};

pub fn generate_consensus_data<F, G>(
    chain_config: &ChainConfig,
    header: &BlockHeader,
    block_height: BlockHeight,
    get_block_index: F,
    get_ancestor: G,
) -> Result<ConsensusData, ConsensusVerificationError>
where
    F: Fn(&Id<Block>) -> Result<Option<BlockIndex>, PropertyQueryError>,
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    match chain_config.net_upgrade().consensus_status(block_height) {
        RequiredConsensus::IgnoreConsensus => Ok(ConsensusData::None),
        RequiredConsensus::PoS(_) => unimplemented!(),
        RequiredConsensus::PoW(pow_status) => {
            let work_required = calculate_work_required(
                chain_config,
                header,
                &pow_status,
                get_block_index,
                get_ancestor,
            )
            .map_err(ConsensusVerificationError::PoWError)?;

            Ok(ConsensusData::PoW(PoWData::new(work_required, 0)))
        }
    }
}

pub fn finalize_consensus_data(
    chain_config: &ChainConfig,
    block: &mut Block,
    block_height: BlockHeight,
) -> Result<(), ConsensusVerificationError> {
    match chain_config.net_upgrade().consensus_status(block_height.next_height()) {
        RequiredConsensus::IgnoreConsensus => Ok(()),
        RequiredConsensus::PoS(_) => unimplemented!(),
        RequiredConsensus::PoW(_) => match block.consensus_data() {
            ConsensusData::None => Ok(()),
            ConsensusData::PoS(_) => unimplemented!(),
            ConsensusData::PoW(pow_data) => {
                mine(block, u128::MAX, pow_data.bits())
                    .map_err(ConsensusVerificationError::PoWError)?;

                Ok(())
            }
        },
    }
}
