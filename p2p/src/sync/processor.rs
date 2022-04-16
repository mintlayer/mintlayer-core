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
#![allow(unused)]
#![cfg(not(loom))]

use crate::{
    error::P2pError,
    net::NetworkService,
    sync::{
        mock_consensus::{Block, BlockHeader, BlockId},
        queue::{self, ImportQueue, ImportQueueState, QueuedData},
    },
};
use logging::log;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProcessorState {
    MoreWork,
    Done,
}

pub enum ProcessorEvent {
    NewBlocks { blocks: Arc<Block> },
}

impl From<(bool, bool)> for ProcessorState {
    fn from(input: (bool, bool)) -> ProcessorState {
        if input.0 && input.1 {
            ProcessorState::Done
        } else {
            ProcessorState::MoreWork
        }
    }
}

// impl queue::Orderable for Arc<Block> {
//     type Id = BlockId;

//     fn get_id(&self) -> &Self::Id {
//         &self.header.id
//     }

//     fn get_prev_id(&self) -> &Option<Self::Id> {
//         &self.header.prev_id
//     }
// }

#[derive(Debug, PartialEq, Eq)]
pub struct BlockRequest<T>
where
    T: NetworkService,
{
    /// PeerId of the node who is working on this request
    pub peer_id: T::PeerId,

    /// Set of headers denoting the blocks local node is requesting
    pub headers: Vec<BlockHeader>,
}

pub struct BlockProcessor<T>
where
    T: NetworkService,
{
    /// Import queue to reorder out-of-order blocks
    queue: queue::ImportQueue<Arc<Block>>,

    /// Set of peers that are currently busy, used for scheduling
    busy: HashSet<T::PeerId>,

    /// Set of block requests that are currently under execution
    active: HashMap<BlockHeader, (T::PeerId, HashSet<T::PeerId>)>,

    /// Set of blocks that still need to be downloaded
    work: HashMap<BlockHeader, HashSet<T::PeerId>>,
}

impl<T> Default for BlockProcessor<T>
where
    T: NetworkService,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> BlockProcessor<T>
where
    T: NetworkService,
{
    /// Create new block processor object
    ///
    /// Internally this object contains a block import queue that is
    /// used during syncing to organize the incoming blocks until they
    /// can be moved to chainstate
    pub fn new() -> Self {
        Self {
            queue: queue::ImportQueue::new(),
            busy: HashSet::new(),
            active: HashMap::new(),
            work: HashMap::new(),
        }
    }

    /// Register peer to the block processor
    ///
    /// When a peer is registered, its headers are compared against the internal
    /// task list the processor holds and that task list is updated to either contain
    /// this `PeerId` for the headers that are shared among multiple remote peers,
    /// or a new entry is created just for this peer.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the peer
    /// `headers` - Set of blocks, denoted by their headers, that must be downloaded
    pub fn register_peer(&mut self, peer_id: T::PeerId, headers: &[BlockHeader]) -> ProcessorState {
        log::debug!(
            "register peer {:?} to block processor, headers: {:#?}",
            peer_id,
            headers
        );

        headers.iter().for_each(|header| {
            if !self.queue.contains_key(&header.id) {
                match self.active.get_mut(header) {
                    Some((_, entry)) => entry.insert(peer_id),
                    None => self.work.entry(*header).or_insert_with(HashSet::new).insert(peer_id),
                };
            }
        });

        // syncing is done if both the work and active queues are empty
        ProcessorState::from((self.work.is_empty(), true))
    }

    /// Unregister peer from the block processor
    ///
    /// If a connection is lost during syncing or the peer provided invalid data
    /// that requires closing the connection, the peer must be explicitly unregistered
    /// from the block processor. This is to prevent selecting that peer for future block
    /// requests.
    ///
    /// Remove all references to `peer_id` from `self.active` and `self.work`. If the peer
    /// is the only provider for those blocks, then the blocks are not dowloaded at all.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the peer
    pub fn unregister_peer(&mut self, peer_id: &T::PeerId) {
        log::debug!("unregister peer {:?} from block processor", peer_id);

        self.work
            .iter_mut()
            .filter_map(|(header, peers)| {
                peers.remove(peer_id);
                peers.is_empty().then(|| *header)
            })
            .collect::<Vec<_>>()
            .iter()
            .for_each(|entry| {
                self.work.remove(entry);
            });

        self.active
            .iter_mut()
            .filter_map(|(header, (_, peers))| {
                peers.remove(peer_id);
                peers.is_empty().then(|| *header)
            })
            .collect::<Vec<_>>()
            .iter()
            .for_each(|entry| {
                self.active.remove(entry);
            });
    }

    /// Get block request from the block processor
    ///
    /// The undownloaded blocks are split into block requests which are sent to remote
    /// peers which have reported to have them.
    ///
    /// The general idea of the peer selection algorithm is to prioritize speed of download
    /// over everything else but to also load balance the requests such that no peer has to
    /// upload overwhelming amount of the data compared to other available peers.
    ///
    /// Currently the algorithm doesn't keep any statistics about nodes, how well they are
    /// responding to our requests or how much each nodes has uploaded but just randomly
    /// selects a node from the list. This is inefficient both in terms of increased signaling
    /// costs but also in random DB access patterns which result in inefficient reads but
    /// all of this will be fixed in the future.
    ///
    /// There is a lot to improve in terms of efficiency but this'll do for now.
    pub fn get_block_request(&mut self) -> Vec<BlockRequest<T>> {
        log::debug!(
            "get block request, work len {}, active len {}",
            self.work.len(),
            self.active.len()
        );

        self.work
            .iter()
            .filter_map(|(header, peers)| {
                peers.iter().find(|peer| !self.busy.contains(peer)).map(|peer| {
                    log::trace!("request {:?} from peer {:?}", header, peer);

                    self.busy.insert(*peer);
                    self.active.insert(*header, (*peer, peers.clone()));
                    (*peer, *header)
                })
            })
            .collect::<Vec<(_, _)>>()
            .iter()
            .map(|(peer, header)| {
                self.work.remove(header);
                BlockRequest {
                    peer_id: *peer,
                    headers: vec![*header],
                }
            })
            .collect::<Vec<_>>()
    }

    /// Register block response to the block processor
    ///
    /// After request has been sent to the remote node and they have answered with a set of blocks,
    /// the response is parsed and blocks are moved to the import queue and entries are removed from
    /// the active queue as they are getting resolved. The implementation doesn't assume that `blocks`
    /// only contains entries that are in `self.active` but also checks the entries of `self.work` as
    /// not to redownload already downloaded blocks.
    ///
    /// If this response removed the last active entry and there is no more work to be done, `ProcessorState::Done`
    /// is returned to indicate that local peer is up to date with the network and it can add the blocks
    /// from the import queue to the local block index.
    ///
    /// If there are still more blocks to be downloaded, `ProcessorState::MoreWork` is returned which indicates
    /// to the caller that is should call `self.get_work()` again.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the peer
    /// `blocks` - Set of blocks received from the remote peer
    pub fn register_block_response(
        &mut self,
        peer_id: &T::PeerId,
        blocks: Vec<Arc<Block>>,
    ) -> ProcessorState {
        for block in blocks {
            self.register_block(peer_id, block);
        }

        // syncing is done if both the work and active queues are empty
        ProcessorState::from((self.work.is_empty(), self.active.is_empty()))
    }

    /// Register a single block to the block processor
    ///
    /// This method is used during syncing if a block is received from a floodsub topic and the node
    /// is not yet done with syncing and thus cannot give the received blocks directly to chainstate.
    ///
    /// As this is also called by `BlockProcessor::register_block_response()`, the method checks if
    /// the received block completes either an active or an unscheduled block requests and if so,
    /// marks that request as resolved.
    ///
    /// The block is then added to the import queue from which it can be fetched when the node has is
    /// fully up to date with the network.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the peer
    /// `blocks` - Block received from the remote peer
    pub fn register_block(&mut self, peer_id: &T::PeerId, block: Arc<Block>) -> ProcessorState {
        // TODO: implement request completion statistics for benchmarking peer performance
        let _ = self.work.remove(&block.header);
        let _ = self.active.remove(&block.header);

        self.busy.remove(peer_id);
        self.queue.queue(block);

        // syncing is done if both the work and active queues are empty
        ProcessorState::from((self.work.is_empty(), self.active.is_empty()))
    }

    /// Get all non-orphan data that has accrued during block downloading
    pub fn drain(&mut self) -> Vec<queue::QueuedData<Arc<Block>>> {
        self.queue.drain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;
    use itertools::*;

    // Register peer who doesn't have any unknown blocks or only knows
    // of blocks that have already been downloaded/are being downloaded
    #[test]
    fn register_peer_no_work() {
        let mut processor = BlockProcessor::<MockService>::new();
        let peer1 = test_utils::get_random_mock_id();
        assert_eq!(processor.register_peer(peer1, &[]), ProcessorState::Done);
        assert!(processor.work.is_empty());

        // add some blocks to the import queue to act as already downloaded blocks
        processor.queue.queue(Arc::new(Block::with_id(101, Some(100))));
        processor.queue.queue(Arc::new(Block::with_id(102, Some(100))));
        processor.queue.queue(Arc::new(Block::with_id(103, Some(101))));
        processor.queue.queue(Arc::new(Block::with_id(104, Some(102))));
        processor.queue.queue(Arc::new(Block::with_id(105, Some(101))));

        // verify that as the blocks have already been downloaded,
        // they are not registered as new work
        assert_eq!(
            processor.register_peer(
                peer1,
                &[
                    BlockHeader::with_id(102, Some(100)),
                    BlockHeader::with_id(103, Some(101)),
                    BlockHeader::with_id(104, Some(102)),
                ]
            ),
            ProcessorState::Done
        );
        assert!(processor.work.is_empty());

        let (peer2, peer3, peer4) = (
            test_utils::get_random_mock_id(),
            test_utils::get_random_mock_id(),
            test_utils::get_random_mock_id(),
        );

        // add some ongoing block downloads
        processor.active.insert(
            BlockHeader::with_id(222, Some(220)),
            (peer2, HashSet::from([peer3, peer4])),
        );
        processor.active.insert(
            BlockHeader::with_id(223, Some(222)),
            (peer3, HashSet::from([peer2, peer4])),
        );
        processor.active.insert(
            BlockHeader::with_id(224, Some(223)),
            (peer4, HashSet::from([peer2, peer3])),
        );

        assert_eq!(
            processor.register_peer(
                peer1,
                &[
                    BlockHeader::with_id(102, Some(100)),
                    BlockHeader::with_id(103, Some(101)),
                    BlockHeader::with_id(104, Some(102)),
                ]
            ),
            ProcessorState::Done
        );
        assert!(processor.work.is_empty());
    }

    #[test]
    fn register_peer_some_work() {
        let mut processor = BlockProcessor::<MockService>::new();
        let peer1 = test_utils::get_mock_id_with(111);

        assert_eq!(
            processor.register_peer(
                peer1,
                &[
                    BlockHeader::with_id(51, Some(50)),
                    BlockHeader::with_id(52, Some(51)),
                    BlockHeader::with_id(53, Some(51)),
                ]
            ),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.work,
            HashMap::from([
                (BlockHeader::with_id(51, Some(50)), HashSet::from([peer1])),
                (BlockHeader::with_id(52, Some(51)), HashSet::from([peer1])),
                (BlockHeader::with_id(53, Some(51)), HashSet::from([peer1])),
            ])
        );

        // add some blocks to the import queue to act as already downloaded blocks
        processor.queue.queue(Arc::new(Block::with_id(101, Some(100))));
        processor.queue.queue(Arc::new(Block::with_id(102, Some(100))));

        // verify that as the blocks have already been downloaded,
        // they are not registered as new work
        assert_eq!(
            processor.register_peer(
                peer1,
                &[
                    BlockHeader::with_id(101, Some(100)),
                    BlockHeader::with_id(102, Some(101)),
                    BlockHeader::with_id(71, Some(70)),
                ]
            ),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.work,
            HashMap::from([
                (BlockHeader::with_id(51, Some(50)), HashSet::from([peer1])),
                (BlockHeader::with_id(52, Some(51)), HashSet::from([peer1])),
                (BlockHeader::with_id(53, Some(51)), HashSet::from([peer1])),
                (BlockHeader::with_id(71, Some(70)), HashSet::from([peer1])),
            ])
        );

        let (peer2, peer3, peer4) = (
            test_utils::get_mock_id_with(112),
            test_utils::get_mock_id_with(113),
            test_utils::get_mock_id_with(114),
        );

        // add some ongoing block downloads
        processor.active.insert(
            BlockHeader::with_id(222, Some(220)),
            (peer2, HashSet::from([peer3, peer4])),
        );
        processor.active.insert(
            BlockHeader::with_id(223, Some(222)),
            (peer3, HashSet::from([peer2, peer4])),
        );
        processor.active.insert(
            BlockHeader::with_id(224, Some(223)),
            (peer4, HashSet::from([peer2, peer3])),
        );

        assert_eq!(
            processor.register_peer(
                peer1,
                &[
                    BlockHeader::with_id(222, Some(220)),
                    BlockHeader::with_id(223, Some(222)),
                    // new work
                    BlockHeader::with_id(171, Some(170)),
                    BlockHeader::with_id(172, Some(171)),
                ]
            ),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.work,
            HashMap::from([
                (BlockHeader::with_id(51, Some(50)), HashSet::from([peer1])),
                (BlockHeader::with_id(52, Some(51)), HashSet::from([peer1])),
                (BlockHeader::with_id(53, Some(51)), HashSet::from([peer1])),
                (BlockHeader::with_id(71, Some(70)), HashSet::from([peer1])),
                (BlockHeader::with_id(171, Some(170)), HashSet::from([peer1])),
                (BlockHeader::with_id(172, Some(171)), HashSet::from([peer1])),
            ])
        );
        assert_eq!(
            processor.active,
            HashMap::from([
                (
                    BlockHeader::with_id(222, Some(220)),
                    (peer2, HashSet::from([peer1, peer3, peer4])),
                ),
                (
                    BlockHeader::with_id(223, Some(222)),
                    (peer3, HashSet::from([peer1, peer2, peer4])),
                ),
                (
                    BlockHeader::with_id(224, Some(223)),
                    (peer4, HashSet::from([peer2, peer3])),
                ),
            ])
        );
    }

    #[test]
    fn get_block_request() {
        let mut processor = BlockProcessor::<MockService>::new();

        let (peer1, peer2) = (
            test_utils::get_mock_id_with(111),
            test_utils::get_mock_id_with(112),
        );

        assert_eq!(processor.get_block_request(), vec![]);

        assert_eq!(
            processor.register_peer(
                peer1,
                &[
                    BlockHeader::with_id(100, Some(1)),
                    BlockHeader::with_id(101, Some(100)),
                    BlockHeader::with_id(102, Some(101)),
                    BlockHeader::with_id(103, Some(102)),
                ]
            ),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.register_peer(
                peer2,
                &[
                    BlockHeader::with_id(100, Some(1)),
                    BlockHeader::with_id(201, Some(100)),
                    BlockHeader::with_id(202, Some(201)),
                    BlockHeader::with_id(203, Some(202)),
                ]
            ),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.work,
            HashMap::from([
                (
                    BlockHeader::with_id(100, Some(1)),
                    HashSet::from([peer1, peer2])
                ),
                (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
                (BlockHeader::with_id(102, Some(101)), HashSet::from([peer1])),
                (BlockHeader::with_id(103, Some(102)), HashSet::from([peer1])),
                (BlockHeader::with_id(201, Some(100)), HashSet::from([peer2])),
                (BlockHeader::with_id(202, Some(201)), HashSet::from([peer2])),
                (BlockHeader::with_id(203, Some(202)), HashSet::from([peer2])),
            ])
        );

        assert_eq!(processor.get_block_request().len(), 2);
        processor.busy.drain();
        assert_eq!(processor.get_block_request().len(), 2);
        processor.busy.drain();
        assert_eq!(processor.get_block_request().len(), 2);
        processor.busy.drain();
        assert_eq!(processor.get_block_request().len(), 1);
    }

    #[test]
    fn register_block_response() {
        let mut processor = BlockProcessor::<MockService>::new();

        let (peer1, peer2) = (
            test_utils::get_mock_id_with(111),
            test_utils::get_mock_id_with(112),
        );

        processor.work = HashMap::from([
            (
                BlockHeader::with_id(100, Some(1)),
                HashSet::from([peer1, peer2]),
            ),
            (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
            (BlockHeader::with_id(103, Some(102)), HashSet::from([peer1])),
            (BlockHeader::with_id(201, Some(100)), HashSet::from([peer2])),
            (BlockHeader::with_id(202, Some(201)), HashSet::from([peer2])),
        ]);

        let mut handle_block_response = |state| {
            let work = processor.get_block_request();

            for task in work {
                assert_eq!(
                    processor.register_block_response(
                        &task.peer_id,
                        vec![Arc::new(
                            Block::with_id(task.headers[0].id, task.headers[0].prev_id,)
                        )],
                    ),
                    state,
                );
            }
        };

        handle_block_response(ProcessorState::MoreWork);
        handle_block_response(ProcessorState::MoreWork);
        handle_block_response(ProcessorState::Done);

        assert!(processor.active.is_empty());
        assert!(processor.work.is_empty());
        assert_eq!(processor.queue.num_chains(), 2);
    }

    #[test]
    fn unregister_peer() {
        let mut processor = BlockProcessor::<MockService>::new();

        let (peer1, peer2, peer3) = (
            test_utils::get_mock_id_with(111),
            test_utils::get_mock_id_with(112),
            test_utils::get_mock_id_with(113),
        );

        processor.work = HashMap::from([
            (
                BlockHeader::with_id(100, Some(1)),
                HashSet::from([peer1, peer2]),
            ),
            (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
            (BlockHeader::with_id(103, Some(102)), HashSet::from([peer3])),
            (BlockHeader::with_id(201, Some(100)), HashSet::from([peer2])),
            (BlockHeader::with_id(202, Some(201)), HashSet::from([peer2])),
            (BlockHeader::with_id(206, Some(207)), HashSet::from([peer3])),
        ]);

        // remove peer 123 from `processor.work`
        processor.unregister_peer(&peer2);
        assert_eq!(
            processor.work,
            HashMap::from([
                (BlockHeader::with_id(100, Some(1)), HashSet::from([peer1])),
                (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
                (BlockHeader::with_id(103, Some(102)), HashSet::from([peer3])),
                (BlockHeader::with_id(206, Some(207)), HashSet::from([peer3])),
            ])
        );

        // create active block request process and then remove peer 123
        assert!(!processor.get_block_request().is_empty());
        assert_eq!(processor.active.len(), 2);

        // remove peer 123 from both `processor.active` and `processor.work`
        processor.unregister_peer(&peer1);

        if processor.work
            == HashMap::from([(BlockHeader::with_id(103, Some(102)), HashSet::from([peer3]))])
        {
            assert_eq!(
                processor.active,
                HashMap::from([(
                    BlockHeader::with_id(206, Some(207)),
                    (peer3, HashSet::from([peer3])),
                )])
            );
        } else {
            assert_eq!(
                processor.work,
                HashMap::from([(BlockHeader::with_id(206, Some(207)), HashSet::from([peer3]))])
            );
            assert_eq!(
                processor.active,
                HashMap::from([(
                    BlockHeader::with_id(103, Some(102)),
                    (peer3, HashSet::from([peer3])),
                )])
            );
        }
    }

    #[test]
    fn drain() {
        let mut processor = BlockProcessor::<MockService>::new();

        let (peer1, peer2) = (
            test_utils::get_mock_id_with(111),
            test_utils::get_mock_id_with(112),
        );

        processor.work = HashMap::from([
            (
                BlockHeader::with_id(100, Some(1)),
                HashSet::from([peer1, peer2]),
            ),
            (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
            (BlockHeader::with_id(103, Some(102)), HashSet::from([peer1])),
            (BlockHeader::with_id(201, Some(100)), HashSet::from([peer2])),
            (BlockHeader::with_id(202, Some(201)), HashSet::from([peer2])),
        ]);

        let mut handle_block_response = |state| {
            let work = processor.get_block_request();

            for task in work {
                assert_eq!(
                    processor.register_block_response(
                        &task.peer_id,
                        vec![Arc::new(
                            Block::with_id(task.headers[0].id, task.headers[0].prev_id,)
                        )],
                    ),
                    state,
                );
            }
        };

        handle_block_response(ProcessorState::MoreWork);
        handle_block_response(ProcessorState::MoreWork);
        handle_block_response(ProcessorState::Done);

        assert!(processor.active.is_empty());
        assert!(processor.work.is_empty());
        assert_eq!(processor.queue.num_chains(), 2);

        let chains = processor
            .drain()
            .iter()
            .flat_map(|x| x.to_vec())
            .sorted()
            .collect::<Vec<Arc<Block>>>();

        assert_eq!(
            chains,
            [
                Arc::new(Block::with_id(100, Some(1))),
                Arc::new(Block::with_id(101, Some(100))),
                Arc::new(Block::with_id(103, Some(102))),
                Arc::new(Block::with_id(201, Some(100))),
                Arc::new(Block::with_id(202, Some(201))),
            ]
        );
    }

    // sync up to date with a remote node while adding blocks from the floodsub to the queue
    // when syncing is completed, verify that all blocks are in order can be imported to chainstate
    #[test]
    fn block_response_and_new_blocks() {
        let mut processor = BlockProcessor::<MockService>::new();

        let (peer1, peer2, peer3) = (
            test_utils::get_mock_id_with(111),
            test_utils::get_mock_id_with(112),
            test_utils::get_mock_id_with(113),
        );

        processor.work = HashMap::from([
            (
                BlockHeader::with_id(100, Some(1)),
                HashSet::from([peer1, peer2]),
            ),
            (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
            (BlockHeader::with_id(103, Some(102)), HashSet::from([peer1])),
            (BlockHeader::with_id(201, Some(100)), HashSet::from([peer2])),
            (BlockHeader::with_id(202, Some(201)), HashSet::from([peer2])),
        ]);

        let handle_block_response = |processor: &mut BlockProcessor<MockService>, state| {
            let work = processor.get_block_request();

            for task in work {
                assert_eq!(
                    processor.register_block_response(
                        &task.peer_id,
                        vec![Arc::new(
                            Block::with_id(task.headers[0].id, task.headers[0].prev_id,)
                        )],
                    ),
                    state,
                );
            }
        };

        // download some old blocks
        handle_block_response(&mut processor, ProcessorState::MoreWork);

        // add a new block from the floodsub,
        //
        // one that add to the longer chain (100) and one that add new block on top of 103
        assert_eq!(
            processor.register_block(&peer1, Arc::new(Block::with_id(203, Some(202)))),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.register_block(&peer3, Arc::new(Block::with_id(104, Some(103)))),
            ProcessorState::MoreWork
        );

        // download some old blocks
        handle_block_response(&mut processor, ProcessorState::MoreWork);

        // add a new block from the floodsub
        //
        // add two more blocks on top of the longest chain (100) and a new branch starting from 102
        assert_eq!(
            processor.register_block(&peer1, Arc::new(Block::with_id(204, Some(203)))),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.register_block(&peer2, Arc::new(Block::with_id(205, Some(104)))),
            ProcessorState::MoreWork
        );
        assert_eq!(
            processor.register_block(&peer3, Arc::new(Block::with_id(111, Some(102)))),
            ProcessorState::MoreWork
        );

        handle_block_response(&mut processor, ProcessorState::Done);

        assert!(processor.active.is_empty());
        assert!(processor.work.is_empty());
        assert_eq!(processor.queue.num_chains(), 2);

        let mut entries = processor
            .drain()
            .iter()
            .map(|queued| {
                queued
                    .iter()
                    .map(|entry| (entry.header.id, entry.header.prev_id))
                    .collect::<Vec<(BlockId, Option<BlockId>)>>()
            })
            .collect::<Vec<Vec<(BlockId, Option<BlockId>)>>>();

        if entries[0].len() != 4 {
            entries.swap(0, 1);
        }

        entries[0].sort_by(|a, b| {
            let res = a.1.cmp(&b.1);
            if res == std::cmp::Ordering::Equal {
                return a.0.cmp(&b.0);
            }
            res
        });

        assert_eq!(
            entries[0],
            vec![(103, Some(102)), (111, Some(102)), (104, Some(103)), (205, Some(104))]
        );

        entries[1].sort_by(|a, b| {
            let res = a.0.cmp(&b.0);
            if res == std::cmp::Ordering::Equal {
                return a.1.cmp(&b.1);
            }
            res
        });

        assert_eq!(
            entries[1],
            vec![
                (100, Some(1)),
                (101, Some(100)),
                (201, Some(100)),
                (202, Some(201)),
                (203, Some(202)),
                (204, Some(203)),
            ]
        );
    }

    // first receive two blocks from floodsub before any peer state has been initialized,
    // then downloads missing blocks from the peer that just connected.
    // verify that both the downloaded blocks and the blocks that were received from the
    // floodsub are all expoted in order
    #[test]
    fn first_floodsub_then_syncing() {
        let mut processor = BlockProcessor::<MockService>::new();

        let (peer1, peer2, peer3) = (
            test_utils::get_mock_id_with(111),
            test_utils::get_mock_id_with(112),
            test_utils::get_mock_id_with(113),
        );

        // add two blocks to the import queue before initializing the work state
        // add a new block from the floodsub,
        assert_eq!(
            processor.register_block(&peer1, Arc::new(Block::with_id(203, Some(202)))),
            ProcessorState::Done
        );
        assert_eq!(
            processor.register_block(&peer3, Arc::new(Block::with_id(204, Some(203)))),
            ProcessorState::Done
        );

        processor.work = HashMap::from([
            (
                BlockHeader::with_id(100, Some(1)),
                HashSet::from([peer1, peer2]),
            ),
            (BlockHeader::with_id(101, Some(100)), HashSet::from([peer1])),
            (BlockHeader::with_id(103, Some(102)), HashSet::from([peer1])),
            (BlockHeader::with_id(201, Some(100)), HashSet::from([peer2])),
            (BlockHeader::with_id(202, Some(201)), HashSet::from([peer2])),
        ]);

        let handle_block_response = |processor: &mut BlockProcessor<MockService>, state| {
            let work = processor.get_block_request();

            for task in work {
                assert_eq!(
                    processor.register_block_response(
                        &task.peer_id,
                        vec![Arc::new(
                            Block::with_id(task.headers[0].id, task.headers[0].prev_id,)
                        )],
                    ),
                    state,
                );
            }
        };

        // download some old blocks
        handle_block_response(&mut processor, ProcessorState::MoreWork);

        // add a new block from the floodsub that depends on the previously recived blocks
        assert_eq!(
            processor.register_block(&peer1, Arc::new(Block::with_id(205, Some(204)))),
            ProcessorState::MoreWork
        );

        // download some old blocks
        handle_block_response(&mut processor, ProcessorState::MoreWork);

        // add a new block from the floodsub that depends on the previously recived blocks
        assert_eq!(
            processor.register_block(&peer3, Arc::new(Block::with_id(111, Some(102)))),
            ProcessorState::MoreWork
        );

        handle_block_response(&mut processor, ProcessorState::Done);

        assert!(processor.active.is_empty());
        assert!(processor.work.is_empty());
        assert_eq!(processor.queue.num_chains(), 2);

        let mut entries = processor
            .drain()
            .iter()
            .map(|queued| {
                queued
                    .iter()
                    .map(|entry| (entry.header.id, entry.header.prev_id))
                    .collect::<Vec<(_, Option<_>)>>()
            })
            .collect::<Vec<Vec<(_, Option<_>)>>>();

        if entries[0].len() != 2 {
            entries.swap(0, 1);
        }

        entries[0].sort_by(|a, b| {
            let res = a.1.cmp(&b.1);
            if res == std::cmp::Ordering::Equal {
                return a.0.cmp(&b.0);
            }
            res
        });

        assert_eq!(entries[0], vec![(103, Some(102)), (111, Some(102))]);

        entries[1].sort_by(|a, b| {
            let res = a.0.cmp(&b.0);
            if res == std::cmp::Ordering::Equal {
                return a.1.cmp(&b.1);
            }
            res
        });

        assert_eq!(
            entries[1],
            vec![
                (100, Some(1)),
                (101, Some(100)),
                (201, Some(100)),
                (202, Some(201)),
                (203, Some(202)),
                (204, Some(203)),
                (205, Some(204)),
            ]
        );
    }
}
