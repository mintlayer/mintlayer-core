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
    primitives::{id::WithId, Id},
};

use super::{OrphanAddError, OrphanBlocksMut, OrphanBlocksPool, OrphanBlocksRef};

impl OrphanBlocksRef for OrphanBlocksPool {
    fn len(&self) -> usize {
        self.len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.is_already_an_orphan(block_id)
    }
}

impl OrphanBlocksMut for OrphanBlocksPool {
    fn clear(&mut self) {
        self.clear()
    }

    fn add_block(&mut self, block: WithId<Block>) -> Result<(), Box<OrphanAddError>> {
        self.add_block(block)
    }

    fn take_all_children_of(&mut self, block_id: &Id<GenBlock>) -> Vec<WithId<Block>> {
        self.take_all_children_of(block_id)
    }
}
