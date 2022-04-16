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
// Author(s): A. Altonen
use crate::{
    error::P2pError,
    sync::{
        mock_consensus::{BlockHeader, BlockId},
        queue::{ImportQueue, ImportQueueState, QueuedData},
    },
};
use std::collections::HashMap;

// TODO: rename 'add_block()' to `register_block()`
// TODO: use LRU cache for the import queue

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PeerIndexState {
    /// Block has been accepted to peer's block index
    Accepted,

    /// Ancestor missing, block has been queued
    Queued,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InnerPeerIndex {
    pub id: BlockId,
    pub prev_id: Option<BlockId>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PeerIndex {
    index: HashMap<BlockId, InnerPeerIndex>,
    headers: HashMap<BlockId, BlockHeader>,
    queue: ImportQueue<BlockHeader>,
}

impl Default for PeerIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerIndex {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            headers: HashMap::new(),
            queue: ImportQueue::new(),
        }
    }

    fn import_queued_blocks(&mut self, queued: &QueuedData<BlockHeader>) {
        for header in queued.iter() {
            self.index.insert(
                header.id,
                InnerPeerIndex {
                    id: header.id,
                    prev_id: header.prev_id,
                },
            );
            self.headers.insert(header.id, *header);
        }
    }

    pub fn queue(&self) -> &ImportQueue<BlockHeader> {
        &self.queue
    }

    pub fn contains(&self, header: &BlockHeader) -> bool {
        self.headers.contains_key(&header.id)
    }

    /// Initialize the block index from headers
    pub fn initialize(&mut self, headers: &[BlockHeader]) {
        (self.index, self.headers) = headers
            .iter()
            .map(|header| {
                (
                    (
                        header.id,
                        InnerPeerIndex {
                            id: header.id,
                            prev_id: header.prev_id,
                        },
                    ),
                    (header.id, *header),
                )
            })
            .unzip();

        self.index
            .iter()
            .filter_map(|(id, _)| {
                self.headers.get(id).and_then(|value| self.queue.drain_with_id(&value.id))
            })
            .collect::<Vec<QueuedData<BlockHeader>>>()
            .iter()
            .for_each(|headers| self.import_queued_blocks(headers));
    }

    pub fn add_block(&mut self, header: BlockHeader) -> Result<PeerIndexState, P2pError> {
        // return early if the block doesn't have an ancestor
        let prev_id = header.prev_id.ok_or(P2pError::InvalidData)?;

        // the ancestor of this block is known to us, add the block to the index
        if self.index.contains_key(&prev_id) {
            self.index.insert(
                header.id,
                InnerPeerIndex {
                    id: header.id,
                    prev_id: Some(prev_id),
                },
            );

            // check if the import queue contained blocks that depended
            // on this block and if so, import them to the block index
            if let Some(headers) = self.queue.drain_with_id(&header.id) {
                self.import_queued_blocks(&headers);
                return Ok(PeerIndexState::Accepted);
            }

            return Ok(PeerIndexState::Accepted);
        }

        // block's ancestor is not known by this peer's block index
        match self.queue.try_queue(&header)? {
            ImportQueueState::Queued => Ok(PeerIndexState::Queued),
            ImportQueueState::Resolved => self
                .queue
                .drain_with_id(&header.id)
                .ok_or(P2pError::InvalidData)
                .map(|headers| {
                    self.import_queued_blocks(&headers);
                    PeerIndexState::Accepted
                }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn get_genesis() -> BlockHeader {
        BlockHeader {
            id: 1337u64,
            prev_id: Some(0u64),
        }
    }

    fn verify_state(
        peer: &mut PeerIndex,
        own_id: BlockId,
        parent_id: BlockId,
        assumed_size: usize,
    ) {
        let block_res = peer.index.get(&own_id).unwrap();
        assert_eq!(peer.index.len(), assumed_size);
        assert_eq!(block_res.id, own_id);
        assert_eq!(block_res.prev_id, Some(parent_id));
    }

    fn add_block(peer: &mut PeerIndex, parent_id: BlockId, assumed_size: usize) -> BlockId {
        let block = BlockHeader::new(Some(parent_id));
        assert_eq!(peer.add_block(block), Ok(PeerIndexState::Accepted));
        verify_state(peer, block.id, parent_id, assumed_size);

        block.id
    }

    // receive blocks announcements from the peer, state is updated without queuing
    #[test]
    fn peer_add_blocks_to_self() {
        let genesis = get_genesis();
        let mut peer = PeerIndex::new();
        peer.initialize(&[genesis]);

        assert_eq!(peer.index.len(), 1);
        assert_eq!(peer.index.get(&genesis.id).unwrap().id, genesis.id);

        // add two blocks that both have genesis as the parent
        let block1_id = add_block(&mut peer, genesis.id, 2);
        let block2_id = add_block(&mut peer, genesis.id, 3);

        // add two more blocks for block1
        let block3_id = add_block(&mut peer, block1_id, 4);
        let block4_id = add_block(&mut peer, block1_id, 5);

        // add one more block for block4
        let block5 = add_block(&mut peer, block4_id, 6);
    }

    // receive block announcements from other peers but as they update the chain
    // the peer is tracking, they are accepted without queuing
    #[test]
    fn peer_accept_block_announcement() {
        let genesis = get_genesis();
        let mut peer = PeerIndex::new();
        peer.initialize(&[genesis]);

        assert_eq!(peer.index.len(), 1);
        assert_eq!(peer.index.get(&genesis.id).unwrap().id, genesis.id);

        // add two blocks that both have genesis as the parent
        let block1_id = add_block(&mut peer, genesis.id, 2);
        let block2_id = add_block(&mut peer, genesis.id, 3);

        // add two more blocks for block1
        let block3_id = add_block(&mut peer, block1_id, 4);
        let block4_id = add_block(&mut peer, block1_id, 5);

        // add one more block for block4
        let block5 = add_block(&mut peer, block4_id, 6);
    }

    // first two blocks are added on top of genesis block,
    // then add the missing block to the chain
    #[test]
    fn block_missing_then_peer_self_announces() {
        let genesis = get_genesis();
        let mut peer = PeerIndex::new();
        peer.initialize(&[genesis]);

        // add two blocks that both have genesis as the parent
        let block1_id = add_block(&mut peer, genesis.id, 2);
        let block2_id = add_block(&mut peer, block1_id, 3);

        assert_eq!(peer.queue.num_chains(), 0);
        assert_eq!(peer.queue.num_queued(), 0);

        // create block that depends on block2 but don't announce it yet
        let block3 = BlockHeader {
            id: 13371338u64,
            prev_id: Some(block2_id),
        };

        // add two blocks that depend on the missing block and verify that they are queued
        let block4 = BlockHeader::new(Some(block3.id));
        assert_eq!(peer.add_block(block4), Ok(PeerIndexState::Queued));

        let block5 = BlockHeader::new(Some(block4.id));
        assert_eq!(peer.add_block(block5), Ok(PeerIndexState::Queued));

        assert_eq!(peer.index.len(), 3);
        assert_eq!(peer.queue.num_chains(), 1);
        assert_eq!(peer.queue.num_queued(), 2);

        // then add the missing block and verify that the queued blocks are added to the block index
        assert_eq!(peer.add_block(block3), Ok(PeerIndexState::Accepted));
        assert_eq!(peer.index.len(), 6);
        assert_eq!(peer.queue.num_chains(), 0);
        assert_eq!(peer.queue.num_queued(), 0);
        assert!(peer.index.contains_key(&block3.id));
        assert!(peer.index.contains_key(&block4.id));
        assert!(peer.index.contains_key(&block5.id));
    }

    // block missing and remote peers announce blocks that depend on the missing block
    // verify that the remote blocks are queued and then they announce block that is missing
    // verify that all blocks are added to the block index
    #[test]
    fn block_missing_then_remote_announces() {
        let genesis = get_genesis();
        let mut peer = PeerIndex::new();
        peer.initialize(&[genesis]);

        // add two blocks that both have genesis as the parent
        let block1_id = add_block(&mut peer, genesis.id, 2);
        let block2_id = add_block(&mut peer, block1_id, 3);

        assert_eq!(peer.queue.num_chains(), 0);
        assert_eq!(peer.queue.num_queued(), 0);

        // create block that depends on block2 but don't announce it yet
        let block3 = BlockHeader {
            id: 13371338u64,
            prev_id: Some(block2_id),
        };

        // add two blocks that depend on the missing block and verify that they are queued
        let block4 = BlockHeader::new(Some(block3.id));
        assert_eq!(peer.add_block(block4), Ok(PeerIndexState::Queued));

        let block5 = BlockHeader::new(Some(block4.id));
        assert_eq!(peer.add_block(block5), Ok(PeerIndexState::Queued));

        assert_eq!(peer.index.len(), 3);
        assert_eq!(peer.queue.num_chains(), 1);
        assert_eq!(peer.queue.num_queued(), 2);

        // then add the missing block and verify that the queued blocks are added to the block index
        assert_eq!(peer.add_block(block3), Ok(PeerIndexState::Accepted));
        assert_eq!(peer.index.len(), 6);
        assert_eq!(peer.queue.num_chains(), 0);
        assert_eq!(peer.queue.num_queued(), 0);
        assert!(peer.index.contains_key(&block3.id));
        assert!(peer.index.contains_key(&block4.id));
        assert!(peer.index.contains_key(&block5.id));
    }

    #[test]
    fn init_from_headers_then_add_blocks_one_chain() {
        let mut peer = PeerIndex::new();

        let block1 = BlockHeader::with_id(1, Some(1337u64));
        let block2 = BlockHeader::with_id(2, Some(1337u64));
        let block1_1 = BlockHeader::with_id(11, Some(block1.id));
        let block2_1 = BlockHeader::with_id(21, Some(block2.id));
        let block1_1_1 = BlockHeader::with_id(111, Some(block1_1.id));

        // blocks may come in any order
        assert_eq!(peer.add_block(block1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block1_1_1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block2_1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block1_1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block2), Ok(PeerIndexState::Queued));

        assert_eq!(peer.queue.num_chains(), 1);
        assert_eq!(peer.queue.num_queued(), 5);

        let missing = BlockHeader::with_id(1337u64, Some(1336u64));
        let other_chain1 = BlockHeader::with_id(4444u64, Some(1337u64));
        let other_chain2 = BlockHeader::with_id(5555u64, Some(4444u64));
        let other_chain3 = BlockHeader::with_id(6666u64, Some(5555u64));

        peer.initialize(&[missing, other_chain1, other_chain2, other_chain3]);

        assert_eq!(peer.queue.num_chains(), 0);
        assert_eq!(peer.queue.num_queued(), 0);
        assert_eq!(peer.index.len(), 9);
    }

    #[test]
    fn init_from_headers_then_add_blocks_two_chains() {
        let mut peer = PeerIndex::new();

        // first chain
        let block1 = BlockHeader::with_id(1, Some(1337u64));
        let block2 = BlockHeader::with_id(2, Some(1337u64));
        let block1_1 = BlockHeader::with_id(11, Some(block1.id));
        let block2_1 = BlockHeader::with_id(21, Some(block2.id));
        let block1_1_1 = BlockHeader::with_id(111, Some(block1_1.id));

        assert_eq!(peer.add_block(block1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block2), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block2_1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block1_1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block1_1_1), Ok(PeerIndexState::Queued));

        assert_eq!(peer.queue.num_chains(), 1);
        assert_eq!(peer.queue.num_queued(), 5);

        // second chain
        let block3 = BlockHeader::with_id(3, Some(1336u64));
        let block4 = BlockHeader::with_id(4, Some(1336u64));
        let block3_1 = BlockHeader::with_id(31, Some(block3.id));
        let block3_1_1 = BlockHeader::with_id(311, Some(block3_1.id));

        assert_eq!(peer.add_block(block3), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block4), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block3_1), Ok(PeerIndexState::Queued));
        assert_eq!(peer.add_block(block3_1_1), Ok(PeerIndexState::Queued));

        assert_eq!(peer.queue.num_chains(), 2);
        assert_eq!(peer.queue.num_queued(), 9);

        let missing_1 = BlockHeader::with_id(1337u64, Some(111111u64));
        let missing_2 = BlockHeader::with_id(1336u64, Some(111111u64));

        peer.initialize(&[missing_1, missing_2]);
        assert_eq!(peer.queue.num_chains(), 0);
        assert_eq!(peer.queue.num_queued(), 0);
        assert_eq!(peer.index.len(), 11);
    }
}
