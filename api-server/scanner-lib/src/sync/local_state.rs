// Copyright (c) 2023 RBB S.r.l
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
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

/// An abstraction that represents the state of the API server locally.
/// This state is updated by the sync process, which uses a RemoteNode to fetch new blocks.
pub trait LocalBlockchainState {
    type Error: std::error::Error;

    /// Returns the current best known block (may be genesis)
    fn best_block(&self) -> (Id<GenBlock>, BlockHeight);

    /// Scan new blocks:
    /// 1. Reset local blocks to the common block height
    /// (it will be lower than the current block height in case of reorg).
    /// 2. Append new blocks.
    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error>;
}
