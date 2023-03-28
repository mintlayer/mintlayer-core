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
    chain::block::{consensus_data::PoWData, ConsensusData},
    chain::{Block, ChainConfig, RequiredConsensus},
    primitives::{BlockHeight, Id},
};

pub use crate::{
    error::ConsensusVerificationError,
    pos::{check_pos_hash, error::ConsensusPoSError, kernel::get_kernel_output},
    pow::{calculate_work_required, check_proof_of_work, mine, ConsensusPoWError},
    validator::validate_consensus,
};

#[allow(unreachable_code)]
pub fn initialize_consensus_data<F, G>(
    chain_config: &ChainConfig,
    block: &mut Block,
    block_height: BlockHeight,
    get_block_index: F,
    get_ancestor: G,
) -> Result<(), ConsensusVerificationError>
where
    F: Fn(&Id<Block>) -> Result<Option<BlockIndex>, PropertyQueryError>,
    G: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    match chain_config.net_upgrade().consensus_status(block_height.next_height()) {
        RequiredConsensus::IgnoreConsensus => {}
        RequiredConsensus::DSA | RequiredConsensus::PoS => unimplemented!(),
        RequiredConsensus::PoW(pow_status) => {
            let work_required = calculate_work_required(
                chain_config,
                block.header(),
                &pow_status,
                get_block_index,
                get_ancestor,
            )
            .map_err(ConsensusVerificationError::PoWError)?;

            let pow_data = PoWData::new(work_required, 0);
            block.update_consensus_data(ConsensusData::PoW(pow_data));
        }
    }

    Ok(())
}
