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

use chainstate_types::BlockIndex;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id, Idable},
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct RpcBlock {
    id: Id<Block>,
    prev_block_id: Id<GenBlock>,
    height: BlockHeight,
    transaction_count_in_block: u32,
    chain_transaction_count: u128,
    block: Block,
}

impl RpcBlock {
    pub fn new(block: Block, block_index: BlockIndex) -> Self {
        Self {
            id: block.get_id(),
            prev_block_id: block.prev_block_id(),
            height: block_index.block_height(),
            transaction_count_in_block: block.transactions().len() as u32,
            chain_transaction_count: block_index.chain_transaction_count(),
            block,
        }
    }
}
