// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): Anton Sinitsyn

use common::primitives::{BlockHeight, H256};
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    Unknown,
    Valid,
    Failed,
    NoLongerOnMainChain,
    // To be expanded
}

#[allow(dead_code)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum BlockError {
    #[error("Unknown error")]
    Unknown,
    // Orphan block
    #[error("Orphan")]
    Orphan,
    #[error("Invalid block height `{0}`")]
    InvalidBlockHeight(BlockHeight),
    #[error("The previous block invalid")]
    PrevBlockInvalid,
    #[error("The storage cause failure `{0}`")]
    StorageFailure(blockchain_storage::Error),
    #[error("The block not found")]
    NotFound,
    // To be expanded
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Tip {
    /// Height of the tip (max height of the fork)
    pub height_tip: BlockHeight,
    /// The last block pushed to the fork
    pub last_block_hash: H256,
    /// The previous block
    pub prev_block_hash: H256,
}

#[cfg(test)]
mod tests {
    // use super::*;
}
