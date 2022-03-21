// Copyright (c) 2021-2022 RBB S.r.l
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
// Author(s): A. Altonen
#![cfg(not(loom))]

use crate::{
    error::P2pError,
    sync::mock_consensus::{Block, BlockHeader, BlockId},
};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct BlockIndex {
    id: BlockId,
    prev_id: Option<BlockId>,
    next_id: Option<BlockId>,
}

#[derive(Debug)]
pub struct PeerBlockIndex {
    blks: BTreeMap<BlockId, BlockIndex>,
    active: Option<BlockId>,
    orphans: Vec<BlockHeader>,
}

impl Default for PeerBlockIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerBlockIndex {
    pub fn new() -> Self {
        Self {
            blks: BTreeMap::new(),
            active: None,
            orphans: vec![],
        }
    }

    pub fn from_headers(headers: &[BlockHeader]) -> Self {
        let mut prev = None;
        let mut blks: BTreeMap<BlockId, BlockIndex> = BTreeMap::new();

        for header in headers {
            let blkidx = BlockIndex {
                id: header.id,
                prev_id: prev,
                next_id: None,
            };

            if let Some(id) = prev {
                (*blks.get_mut(&id).expect("Entry to exist")).next_id = Some(header.id);
            }

            blks.insert(header.id, blkidx);
            prev = Some(header.id);
        }

        Self {
            blks,
            active: prev,
            orphans: vec![],
        }
    }

    pub fn connect_block(&mut self, header: BlockHeader) {
        let active_id = self.active.expect("Expected active block");

        (*self.blks.get_mut(&active_id).expect("Entry to exist")).next_id = Some(header.id);
        self.blks.insert(
            header.id,
            BlockIndex {
                id: header.id,
                prev_id: Some(active_id),
                next_id: None,
            },
        );
        self.active = Some(header.id);
    }

    pub fn add_block(&mut self, block: &Block) {
        if block.header.prev_id == self.active {
            self.connect_block(block.header);
        } else {
            self.orphans.push(block.header);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_new() {}
}
