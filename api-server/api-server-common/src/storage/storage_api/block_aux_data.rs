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
    chain::Block,
    primitives::{BlockHeight, Id},
};
use serialization::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode, PartialEq, Eq)]
pub struct BlockAuxData {
    block_id: Id<Block>,
    block_height: BlockHeight,
}

impl BlockAuxData {
    pub fn new(block_id: Id<Block>, block_height: BlockHeight) -> Self {
        Self {
            block_id,
            block_height,
        }
    }

    pub fn block_id(&self) -> Id<Block> {
        self.block_id
    }

    pub fn block_height(&self) -> BlockHeight {
        self.block_height
    }
}
