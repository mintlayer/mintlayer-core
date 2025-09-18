// Copyright (c) 2025 RBB S.r.l
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

use common::{
    chain::{block::ConsensusData, Block},
    primitives::Compact,
    Uint256,
};

pub fn get_block_compact_target(block: &Block) -> Option<Compact> {
    match block.consensus_data() {
        ConsensusData::None => None,
        ConsensusData::PoW(data) => Some(data.bits()),
        ConsensusData::PoS(data) => Some(data.compact_target()),
    }
}

pub fn unpack_block_compact_target(
    compact_target: Compact,
) -> Result<Uint256, BlockCompactTargetUnpackingError> {
    let target = Uint256::try_from(compact_target)
        .map_err(|_| BlockCompactTargetUnpackingError(compact_target))?;
    Ok(target)
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("Compact target {0:?} cannot be converted to an integer")]
pub struct BlockCompactTargetUnpackingError(Compact);
