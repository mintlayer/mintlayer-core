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

use std::ops::{Deref, DerefMut};

use common::{
    chain::{Block, GenBlock},
    primitives::{id::WithId, Id},
};

use super::{OrphanAddError, OrphanBlocksMut, OrphanBlocksRef, OrphansProxy};

const RECV_ERR_MSG: &str = "Failed to recv from orphan blocks proxy. This should never happen as the destruction of the proxy should end the communication; but something else did";

mod orphans_proxy_ref_impls {
    use super::*;

    pub fn len(this: &OrphansProxy) -> usize {
        this.deref().call(move |o| o.len()).recv().expect(RECV_ERR_MSG)
    }

    pub fn is_already_an_orphan(this: &OrphansProxy, block_id: &Id<Block>) -> bool {
        let block_id = *block_id;
        this.deref()
            .call(move |o| o.is_already_an_orphan(&block_id))
            .recv()
            .expect(RECV_ERR_MSG)
    }
}

impl OrphanBlocksRef for &OrphansProxy {
    fn len(&self) -> usize {
        orphans_proxy_ref_impls::len(self)
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        orphans_proxy_ref_impls::is_already_an_orphan(self, block_id)
    }
}

impl OrphanBlocksRef for &mut OrphansProxy {
    fn len(&self) -> usize {
        orphans_proxy_ref_impls::len(self)
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        orphans_proxy_ref_impls::is_already_an_orphan(self, block_id)
    }
}

impl OrphanBlocksMut for &mut OrphansProxy {
    fn clear(&mut self) {
        self.deref_mut().call_mut(move |o| o.clear()).recv().expect(RECV_ERR_MSG)
    }

    fn add_block(&mut self, block: WithId<Block>) -> Result<(), Box<OrphanAddError>> {
        self.deref_mut()
            .call_mut(move |o| o.add_block(block))
            .recv()
            .expect(RECV_ERR_MSG)
    }

    fn take_all_children_of(&mut self, block_id: &Id<GenBlock>) -> Vec<WithId<Block>> {
        let block_id = *block_id;
        self.deref_mut()
            .call_mut(move |o| o.take_all_children_of(&block_id))
            .recv()
            .expect(RECV_ERR_MSG)
    }
}
