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
// Author(s): C. Yap

#![allow(dead_code, unused_variables)]
// TODO: Temporary placeholders. Should be deleted once an actual representation/implementation is ready.

use common::chain::block::consensus_data::PoWData;
use common::chain::block::Block;
use common::primitives::{BlockHeight, Id};

pub struct BlockIndex {
    pub height: BlockHeight,
    pub data: PoWData,
}

impl BlockIndex {
    pub fn get_block_time(&self) -> u32 {
        todo!()
    }

    pub fn get_ancestor(&self, height: BlockHeight) -> BlockIndex {
        todo!()
    }

    pub fn prev(&self) -> Option<Id<Block>> {
        todo!()
    }
}

impl From<Block> for BlockIndex {
    fn from(_: Block) -> Self {
        todo!()
    }
}
