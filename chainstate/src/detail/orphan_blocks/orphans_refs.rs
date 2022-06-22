// Copyright (c) 2022 RBB S.r.l
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
// Author(s): S. Afach

use super::{OrphanAddError, OrphanBlocksPool};
use common::{chain::block::Block, primitives::Id};

pub trait OrphanBlocks {
    fn len(&self) -> usize;
    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool;
}

pub trait OrphanBlocksMut: OrphanBlocks {
    fn clear(&mut self);
    fn add_block(&mut self, block: Block) -> Result<(), OrphanAddError>;
    fn take_all_children_of(&mut self, block_id: &Id<Block>) -> Vec<Block>;
}

pub struct OrphanBlocksRef<'a> {
    inner: &'a OrphanBlocksPool,
}

impl<'a> OrphanBlocksRef<'a> {
    pub fn new(inner: &'a OrphanBlocksPool) -> Self {
        Self { inner }
    }
}

impl<'a> OrphanBlocks for OrphanBlocksRef<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.inner.is_already_an_orphan(block_id)
    }
}

pub struct OrphanBlocksRefMut<'a> {
    inner: &'a mut OrphanBlocksPool,
}

impl<'a> OrphanBlocksRefMut<'a> {
    pub fn new(inner: &'a mut OrphanBlocksPool) -> Self {
        Self { inner }
    }
}

impl<'a> OrphanBlocks for OrphanBlocksRefMut<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.inner.is_already_an_orphan(block_id)
    }
}

impl<'a> OrphanBlocksMut for OrphanBlocksRefMut<'a> {
    fn clear(&mut self) {
        self.inner.clear()
    }

    fn add_block(&mut self, block: Block) -> Result<(), OrphanAddError> {
        self.inner.add_block(block)
    }

    fn take_all_children_of(&mut self, block_id: &Id<Block>) -> Vec<Block> {
        self.inner.take_all_children_of(block_id)
    }
}
