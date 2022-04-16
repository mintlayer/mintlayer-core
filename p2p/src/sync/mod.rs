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
#![cfg(not(loom))]
#![allow(unused)]

use crate::{
    error::{self, FatalError, P2pError},
    event,
    message::{MessageType, SyncingMessage},
    net::{self, FloodsubService, NetworkService},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};

pub mod index;
pub mod mock_consensus;
pub mod peer;
pub mod queue;

// Define which errors are fatal for the sync manager as the error is bubbled
// up to the main event loop which then decides how to act on errors.
// Peer not existing is not a fatal error for SyncManager but it is fatal error
// for the function that tries to update peer state.
//
// This is just a convenience method to have access to nicer error handling
impl<T> FatalError for error::Result<T> {
    fn into_fatal(self) -> core::result::Result<(), P2pError> {
        if let Err(err) = self {
            log::error!("call failed: {:#?}", err);

            if err == P2pError::ChannelClosed {
                return Err(err);
            }
        }

        Ok(())
    }
}

impl queue::Orderable for Arc<mock_consensus::Block> {
    type Id = mock_consensus::BlockId;

    fn get_id(&self) -> &Self::Id {
        &self.header.id
    }

    fn get_prev_id(&self) -> &Option<Self::Id> {
        &self.header.prev_id
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProcessorState {
    MoreWork,
    Done,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Local node's state is uninitialized
    Uninitialized,

    /// Downloading blocks from remote node(s)
    DownloadingBlocks,

    /// Local block index is fully synced
    Idle,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlockRequest<T>
where
    T: NetworkService,
{
    /// PeerId of the node who is working on this request
    pub peer_id: T::PeerId,

    /// Set of headers denoting the blocks local node is requesting
    pub headers: Vec<mock_consensus::BlockHeader>,
}

/// Sync manager is responsible for syncing the local blockchain to the chain with most trust
/// and keeping up with updates to different branches of the blockchain.
///
/// It keeps track of the state of each individual peer and holds an intermediary block index
/// which represents the local block index of every peer it's connected to.
///
/// Currently its only mode of operation is greedy so it will download all changes from every
/// peer it's connected to and actively keep track of the peer's state.
pub struct SyncManager<T>
where
    T: NetworkService,
{
    /// Syncing state of the local node
    state: SyncState,

    /// TX channel for sending subsystem-related queries
    p2p_handle: event::P2pEventHandle,

    /// RX channel for receiving syncing-related control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// RX channel for receiving syncing events from peers
    rx_peer: mpsc::Receiver<event::PeerSyncEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, peer::PeerContext<T>>,

    /// TX handle for sending blocks to the floodsub
    tx_floodsub: mpsc::Sender<event::BlockFloodEvent>,

    /// RX handle for receiving blocks from the floodsub
    rx_floodsub: mpsc::Receiver<event::SyncFloodEvent<T>>,

    /// Import queue to reorder out-of-order blocks
    queue: queue::ImportQueue<Arc<mock_consensus::Block>>,

    // TODO: merge this with `peers`
    /// Set of peers that are currently busy, used for scheduling
    busy: HashSet<T::PeerId>,

    /// Set of block requests that are currently under execution
    active: HashMap<mock_consensus::BlockHeader, (T::PeerId, HashSet<T::PeerId>)>,

    /// Set of blocks that still need to be downloaded
    work: HashMap<mock_consensus::BlockHeader, HashSet<T::PeerId>>,
    // TODO: keep track of our current best block so we can drain the queue periodically
}

impl<T> SyncManager<T>
where
    T: NetworkService,
{
    pub fn new(
        tx_floodsub: mpsc::Sender<event::BlockFloodEvent>,
        rx_floodsub: mpsc::Receiver<event::SyncFloodEvent<T>>,
        tx_p2p: mpsc::Sender<event::P2pEvent>,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
        rx_peer: mpsc::Receiver<event::PeerSyncEvent<T>>,
    ) -> Self {
        Self {
            state: SyncState::Idle,
            tx_floodsub,
            rx_floodsub,
            p2p_handle: event::P2pEventHandle::new(tx_p2p),
            rx_sync,
            rx_peer,
            peers: Default::default(),
            queue: queue::ImportQueue::new(),
            busy: HashSet::new(),
            active: HashMap::new(),
            work: HashMap::new(),
        }
    }

    /// Register peer to the sync manager
    ///
    /// After the remote peer has successfully finished handshaking with local node,
    /// it is reported by [SwarmManager] to [SyncManager] so that it can try and establish
    /// the sync state with the remote peer. This is done by creating an "uninitialized"
    /// entry for the peer and sending a `GetHeaders` request with local node's current
    /// locator object. The remote peer is activated for block requests only after it
    /// has responded to local node's query about its current best headers.
    ///
    /// TODO: if remote doesn't respond within some time limit, remove it from the peer set?
    /// TODO: what if the peer already exists, how would we even get a re-registration?
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote remote peer
    /// `tx` - Channel for sending direct messages to the remote peer
    pub async fn register_peer(
        &mut self,
        peer_id: T::PeerId,
        tx: mpsc::Sender<event::PeerEvent<T>>,
    ) -> error::Result<()> {
        if self.peers.contains_key(&peer_id) {
            log::error!("peer {:?} already known by sync manager", peer_id);
            return Err(P2pError::PeerExists);
        }

        // TODO: rewrite this into something nicer
        let locator = self.p2p_handle.get_locator().await?;
        let mut peer = peer::PeerContext::new(peer_id, tx);

        peer.get_headers(locator).await?;
        self.peers.insert(peer_id, peer);

        Ok(())
    }

    /// Initialize the peer state
    ///
    /// After remote node has received local node's header request, it responds
    /// to it with a set of headers from its best chain that it is tracking.
    ///
    /// These headers are used to initialize the peer index and to add a participant
    /// to any active block request entry that the remote node might complete.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote remote peer
    /// `headers` - Headers of the remote peer's best chain
    pub async fn initialize_peer(
        &mut self,
        peer_id: T::PeerId,
        headers: &[mock_consensus::BlockHeader],
    ) -> error::Result<()> {
        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;

        log::debug!(
            "initialize peer {:?} state, headers: {:#?}",
            peer_id,
            headers
        );

        // perform ancestry search on the headers and find out which blocks must be downloaded
        //
        // if the search yields unique headers, schedule them for downloading and return them
        // if not, return the best header currently known by the local node the response received
        // from the remote indicates they are following the same chain and are up to date with us
        let headers = match self.p2p_handle.get_uniq_headers(headers.to_vec()).await? {
            Some(uniq) => {
                // for each header, check if it's already in the active queue (it's being downloaded)
                // and if so, add `peer` to that list in case the download fails and it has to be retried.
                //
                // otherwise create new work entry or modify an existing entry with the peer's ID
                uniq.iter().for_each(|header| {
                    if !self.queue.contains_key(&header.id) {
                        match self.active.get_mut(header) {
                            Some((_, entry)) => entry.insert(peer_id),
                            None => self
                                .work
                                .entry(*header)
                                .or_insert_with(HashSet::new)
                                .insert(peer_id),
                        };
                    }
                });

                uniq
            }
            // TODO: should syncing now this info without querying it from the chainstate?
            None => [self.p2p_handle.get_best_block_header().await?].to_vec(),
        };

        peer.initialize_index(&headers);
        Ok(())
    }

    /// Unregister peer from the sync manager
    ///
    /// The connection may have been lost or the peer provided invalid information that
    /// warrants closing the connection all together. Remove all references to the peer,
    /// remove it from all work-related data structures and reschedule any blocks that
    /// were being downloaded from the removed peer and download them from other peers
    /// if there are any providers. If not, just delete the entries.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote peer
    pub async fn unregister_peer(&mut self, peer_id: T::PeerId) -> error::Result<()> {
        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;

        log::debug!("unregister peer {:?}", peer_id);

        self.work
            .iter_mut()
            .filter_map(|(header, peers)| {
                peers.remove(&peer_id);
                peers.is_empty().then(|| *header)
            })
            .collect::<Vec<_>>()
            .iter()
            .for_each(|entry| {
                println!("remove work {:?}", entry);
                self.work.remove(entry);
            });

        // if peer is the only provider of the block, the request is deleted
        // if there are multiple providers and peer is the active provider, the request is rescheduled
        // if there are multiple providers and some other peer is active provider, nothing is done
        let (remove, reschedule): (Vec<_>, Vec<_>) = self
            .active
            .iter_mut()
            .map(|(header, (active, peers))| {
                peers.remove(&peer_id);
                if peers.is_empty() {
                    (Some(header.clone()), None)
                } else if active == &peer_id {
                    (None, Some(header.clone()))
                } else {
                    (None, None)
                }
            })
            .unzip();

        remove.iter().for_each(|header| {
            header.map(|header| self.active.remove(&header));
        });

        reschedule.iter().for_each(|header| {
            header.map(|header| {
                let (_, peers) = self.active.remove(&header).expect("entry to exist");
                self.work.insert(header, peers);
            });
        });

        self.peers.remove(&peer_id);
        Ok(())
    }

    /// Register block to the sync manager
    ///
    /// This function is called when a block is received from the floodsub.
    /// It checks if the state of [SyncManager] is [SyncState::Idle] which means that
    /// to the best of the node's knowledge it is up to date with the network and the block
    /// can be directly imported into the local node's block index.
    ///
    /// If the state is anything else, the block is queued and when its ancestors have
    /// been received, the block is drained from the queue along its ancestors into the
    /// local node's block index.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote peer
    /// `block` - Block that was received
    pub async fn process_block(
        &mut self,
        peer_id: T::PeerId,
        block: Arc<mock_consensus::Block>,
    ) -> error::Result<()> {
        log::trace!(
            "received a block from peer {:?}, block id {:#?}",
            peer_id,
            block.header.id
        );

        match self.state {
            SyncState::Idle => self.p2p_handle.new_block((*block).clone()).await,
            _ => self.process_sync_block(peer_id, block),
        }
    }

    /// Process block when the node is still syncing
    ///
    /// When a node is syncing, incoming blocks are not sent to the block index
    /// but instead stored inside the import queue from which they are periodically
    /// drained to the block index as their depenencies are being resolved.
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote peer
    /// `block` - Block that was received
    fn process_sync_block(
        &mut self,
        peer_id: T::PeerId,
        block: Arc<mock_consensus::Block>,
    ) -> error::Result<()> {
        log::trace!(
            "node syncing, process incoming block from peer {:?}",
            peer_id
        );

        // TODO: implement request completion statistics for benchmarking peer performance
        // TODO: check for example if the node sent the block that we were expecting
        //       and update its reputation accordingly
        // TODO: it must be known here whether the block came as a block response
        //       or as a random block from the floodsub
        self.work.remove(&block.header);
        self.active.remove(&block.header);
        self.busy.remove(&peer_id);
        self.queue.queue(block);

        Ok(())
    }

    /// Process incoming block response
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote peer
    /// `block` - Block that was received
    pub async fn process_block_response(
        &mut self,
        peer_id: T::PeerId,
        blocks: Vec<Arc<mock_consensus::Block>>,
    ) -> error::Result<()> {
        log::trace!(
            "node syncing, process incoming block response from peer {:?}, {} blocks",
            peer_id,
            blocks.len(),
        );

        blocks.into_iter().for_each(|block| {
            self.process_sync_block(peer_id, block);
        });

        Ok(())
    }

    /// Process incoming header request from remote peer
    ///
    /// TODO: is any of this information interesting enough to store somewhere
    /// for tracking purposes?
    ///
    /// # Arguments
    /// `peer_id` - Unique ID of the remote peer
    /// `locator` - Set of headers used for performing the ancestry search
    pub async fn process_header_request(
        &mut self,
        peer_id: T::PeerId,
        locator: Vec<mock_consensus::BlockHeader>,
    ) -> error::Result<()> {
        log::trace!(
            "received a header request from peer {:?}, locator {:#?}",
            peer_id,
            locator
        );

        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;
        let headers = self.p2p_handle.get_headers(locator).await?;

        peer.send_headers(headers).await
    }

    /// Process incoming block request from remote peer
    pub async fn process_block_request(
        &mut self,
        peer_id: T::PeerId,
        headers: &[mock_consensus::BlockHeader],
    ) -> error::Result<()> {
        log::trace!(
            "received a block request from peer {:?}, header counter {}",
            peer_id,
            headers.len(),
        );

        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;
        let blocks = self.p2p_handle.get_blocks(headers.to_vec()).await?;
        peer.send_blocks(blocks).await
    }

    /// Advance the state of syncing
    ///
    /// The combination of the states of `self.work`, `self.active` and `self.queue` define what
    /// the current state of syncing is.
    pub async fn advance_state(&mut self) -> error::Result<()> {
        if !self.work.is_empty() {
            log::debug!(
                "try to schedule block requests, work len {}, active len {}",
                self.work.len(),
                self.active.len()
            );

            // TODO: download more than one block from node using one request
            let requests = self
                .work
                .iter()
                .filter_map(|(header, peers)| {
                    peers.iter().find(|peer_id| !self.busy.contains(peer_id)).map(|peer_id| {
                        log::trace!("request {:?} from peer {:?}", header, peer_id);

                        self.busy.insert(*peer_id);
                        // TODO: don't insert to active yet!
                        self.active.insert(*header, (*peer_id, peers.clone()));
                        (*peer_id, *header)
                    })
                })
                .collect::<Vec<(_, _)>>();

            for (peer_id, header) in requests {
                let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;
                self.work.remove(&header);
                peer.get_blocks(vec![header]).await?;
            }

            self.state = SyncState::DownloadingBlocks;
            return Ok(());
        }

        // work is empty, check if active has any work
        // TODO: implement partial draining
        // TODO: implement block request expirations
        if !self.active.is_empty() {
            self.state = SyncState::DownloadingBlocks;
            return Ok(());
        }

        // try to drain the queue if there are any blocks
        if !self.queue.is_empty() {
            for chain in self.queue.drain().iter() {
                for block in chain.iter() {
                    self.p2p_handle.new_block((**block).clone()).await?;
                }
            }

            self.state = SyncState::Idle;
            return Ok(());
        }

        // TODO: this may not be correct
        Ok(())
    }

    /// Run [SyncManager] event loop
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting sync manager event loop");

        loop {
            tokio::select! {
                res = self.rx_floodsub.recv().fuse() => {
                    let event::SyncFloodEvent::Block { peer_id, block } = res.ok_or(P2pError::ChannelClosed)?;
                    self.process_block(peer_id, Arc::new(block)).await.into_fatal()?;
                },
                event = self.rx_sync.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    event::SyncControlEvent::Connected { peer_id, tx } => {
                        self.register_peer(peer_id, tx).await.into_fatal()?;
                    }
                    event::SyncControlEvent::Disconnected { peer_id } => {
                        self.unregister_peer(peer_id).await.into_fatal()?;
                    }
                },
                event = self.rx_peer.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    event::PeerSyncEvent::Headers { peer_id, headers } => {
                        self.initialize_peer(peer_id, &headers).await.into_fatal()?;
                    }
                    event::PeerSyncEvent::GetHeaders { peer_id, locator } => {
                        self.process_header_request(peer_id, locator).await.into_fatal()?;
                    }
                    event::PeerSyncEvent::Blocks { peer_id, blocks } => {
                        self.process_block_response(peer_id, blocks).await.into_fatal()?;
                    }
                    event::PeerSyncEvent::GetBlocks { peer_id, headers } => {
                        self.process_block_request(peer_id, &headers).await.into_fatal()?;
                    }
                }
            }

            // advance the state of the manager after each event has been handled
            self.advance_state().await.into_fatal()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        message::{self, MessageType, SyncingMessage},
        net::{mock::MockService, FloodsubService},
    };
    use common::chain::config;
    use itertools::*;
    use std::net::SocketAddr;

    macro_rules! get_message {
        ($expression:expr, $($pattern:pat_param)|+, $ret:expr) => {
            match $expression {
                $($pattern)|+ => $ret,
                _ => panic!("invalid message received")
            }
        }
    }

    async fn make_sync_manager<T>(
        addr: T::Address,
    ) -> (
        SyncManager<T>,
        mpsc::Sender<event::SyncControlEvent<T>>,
        mpsc::Sender<event::PeerSyncEvent<T>>,
        mpsc::Receiver<event::P2pEvent>,
    )
    where
        T: NetworkService,
    {
        let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
        let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(16);
        let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);
        let (tx_sf, rx_sf) = tokio::sync::mpsc::channel(16);
        let (tx_fs, rx_fs) = tokio::sync::mpsc::channel(16);

        (
            SyncManager::<T>::new(tx_sf, rx_fs, tx_p2p, rx_sync, rx_peer),
            tx_sync,
            tx_peer,
            rx_p2p,
        )
    }

    // handle peer connection event
    #[tokio::test]
    async fn test_peer_connected() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let (tx, rx) = mpsc::channel(1);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        tokio::spawn(async move {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(mock_consensus::Consensus::with_height(4).get_locator());
                }
            );
        });

        assert_eq!(mgr.register_peer(peer_id, tx).await, Ok(()));
        assert_eq!(mgr.peers.len(), 1);
        assert_eq!(
            mgr.peers.iter().next().unwrap().1.state(),
            &peer::PeerSyncState::UploadingHeaders,
        );
    }

    // handle peer disconnection event
    #[tokio::test]
    async fn test_peer_disconnected() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let (tx, rx) = mpsc::channel(16);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        tokio::spawn(async move {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(mock_consensus::Consensus::with_height(4).get_locator());
                }
            );
        });

        assert_eq!(mgr.register_peer(peer_id, tx).await, Ok(()));
        assert_eq!(mgr.peers.len(), 1);
        assert_eq!(
            mgr.peers.iter().next().unwrap().1.state(),
            &peer::PeerSyncState::UploadingHeaders,
        );

        // no peer with this id exist, nothing happens
        assert_eq!(
            mgr.unregister_peer(addr).await,
            Err(P2pError::PeerDoesntExist)
        );
        assert_eq!(mgr.peers.len(), 1);

        assert_eq!(mgr.unregister_peer(peer_id).await, Ok(()));
        assert!(mgr.peers.is_empty());
    }

    // unregister peer with unscheduled block requests where it's the only provider
    #[tokio::test]
    async fn unregister_peer_unscheduled_work_only_provider() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let (tx, rx) = mpsc::channel(16);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        tokio::spawn(async move {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(mock_consensus::Consensus::with_height(4).get_locator());
                }
            );

            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    response.send(Some(headers));
                }
            )
        });

        assert_eq!(mgr.register_peer(peer_id, tx).await, Ok(()));
        assert_eq!(mgr.peers.len(), 1);
        assert_eq!(
            mgr.peers.iter().next().unwrap().1.state(),
            &peer::PeerSyncState::UploadingHeaders,
        );
        assert!(mgr.work.is_empty());

        // register work for the peer and verify the work is unscheduled
        assert_eq!(
            mgr.initialize_peer(
                peer_id,
                &[
                    mock_consensus::BlockHeader::with_id(102, Some(100)),
                    mock_consensus::BlockHeader::with_id(103, Some(101)),
                    mock_consensus::BlockHeader::with_id(104, Some(102)),
                ]
            )
            .await,
            Ok(())
        );
        assert_eq!(mgr.work.len(), 3);
        assert!(mgr.active.is_empty());

        // unregister peer and verify that all work has been removed
        assert_eq!(mgr.unregister_peer(peer_id).await, Ok(()));
        assert!(mgr.work.is_empty());
        assert!(mgr.active.is_empty());
    }

    // unregister peer with active block request
    #[tokio::test]
    async fn unregister_peer_active_work_only_provider() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let (tx, rx) = mpsc::channel(16);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        tokio::spawn(async move {
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(mock_consensus::Consensus::with_height(4).get_locator());
                }
            );

            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    response.send(Some(headers));
                }
            )
        });

        assert_eq!(mgr.register_peer(peer_id, tx).await, Ok(()));
        assert_eq!(mgr.peers.len(), 1);
        assert_eq!(
            mgr.peers.iter().next().unwrap().1.state(),
            &peer::PeerSyncState::UploadingHeaders,
        );
        assert!(mgr.work.is_empty());

        // register work for the peer and verify the work is unscheduled
        assert_eq!(
            mgr.initialize_peer(
                peer_id,
                &[
                    mock_consensus::BlockHeader::with_id(102, Some(100)),
                    mock_consensus::BlockHeader::with_id(103, Some(101)),
                    mock_consensus::BlockHeader::with_id(104, Some(102)),
                ]
            )
            .await,
            Ok(())
        );
        assert_eq!(mgr.work.len(), 3);
        assert!(mgr.active.is_empty());

        // schedule work for the peer
        mgr.advance_state().await;
        assert_eq!(mgr.work.len(), 2);
        assert_eq!(mgr.active.len(), 1);

        // unregister peer and verify that all work has been removed
        assert_eq!(mgr.unregister_peer(peer_id).await, Ok(()));
        assert!(mgr.work.is_empty());
        assert!(mgr.active.is_empty());
    }

    // register 3 peers which all are individual providers for some blocks
    // and for some blocks they are all providers
    // then unregister one peer with an active block request and verify
    // that while the peer is removed, the work it was doing is assigned
    // (or rather rescheduled) to someone else
    #[tokio::test]
    async fn unregister_peer_active_work_one_of_providers() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;

        let (tx, rx) = mpsc::channel(16);
        let peer_id1 = test_utils::get_random_mock_id();
        let peer_id2 = test_utils::get_random_mock_id();
        let peer_id3 = test_utils::get_random_mock_id();

        let handle = tokio::spawn(async move {
            let cons = mock_consensus::Consensus::with_height(8);

            for i in 0..6 {
                match rx_p2p.recv().await.unwrap() {
                    event::P2pEvent::GetLocator { response } => {
                        response.send(cons.get_locator());
                    }
                    event::P2pEvent::GetUniqHeaders { headers, response } => {
                        response.send(Some(headers));
                    }
                    _ => panic!("invalid message"),
                }
            }

            cons
        });

        // first register 2 peers
        assert_eq!(mgr.register_peer(peer_id1, tx.clone()).await, Ok(()));
        assert_eq!(mgr.register_peer(peer_id2, tx.clone()).await, Ok(()));
        assert_eq!(mgr.peers.len(), 2);
        for (id, peer) in mgr.peers.iter() {
            assert_eq!(peer.state(), &peer::PeerSyncState::UploadingHeaders);
        }
        assert!(mgr.work.is_empty());

        // register work for the both of them where some of the headers
        // are shared and some are unique
        assert_eq!(
            mgr.initialize_peer(
                peer_id1,
                &[
                    mock_consensus::BlockHeader::with_id(102, Some(100)),
                    mock_consensus::BlockHeader::with_id(103, Some(101)),
                    mock_consensus::BlockHeader::with_id(105, Some(104)),
                ]
            )
            .await,
            Ok(())
        );
        assert_eq!(
            mgr.initialize_peer(
                peer_id2,
                &[
                    mock_consensus::BlockHeader::with_id(102, Some(100)),
                    mock_consensus::BlockHeader::with_id(103, Some(101)),
                ]
            )
            .await,
            Ok(())
        );
        assert_eq!(mgr.work.len(), 3);
        assert!(mgr.active.is_empty());

        // verify providers
        assert_eq!(
            mgr.work.get(&mock_consensus::BlockHeader::with_id(102, Some(100))).unwrap(),
            &HashSet::from([peer_id1, peer_id2])
        );
        assert_eq!(
            mgr.work.get(&mock_consensus::BlockHeader::with_id(103, Some(101))).unwrap(),
            &HashSet::from([peer_id1, peer_id2])
        );
        assert_eq!(
            mgr.work.get(&mock_consensus::BlockHeader::with_id(105, Some(104))).unwrap(),
            &HashSet::from([peer_id1])
        );

        // schedule work for the peer
        mgr.advance_state().await;
        assert_eq!(mgr.work.len(), 1);
        assert_eq!(mgr.active.len(), 2);

        // register the third and verify that as it also was provider
        // for both of the scheduled blocks, the active entries are
        // modified accordingly
        assert_eq!(mgr.register_peer(peer_id3, tx).await, Ok(()));
        assert_eq!(mgr.peers.len(), 3);
        assert_eq!(
            mgr.peers.get(&peer_id3).unwrap().state(),
            &peer::PeerSyncState::UploadingHeaders
        );
        assert_eq!(
            mgr.initialize_peer(
                peer_id3,
                &[
                    mock_consensus::BlockHeader::with_id(102, Some(100)),
                    mock_consensus::BlockHeader::with_id(103, Some(101)),
                    mock_consensus::BlockHeader::with_id(999, Some(888)),
                ]
            )
            .await,
            Ok(())
        );

        let headers = vec![
            mock_consensus::BlockHeader::with_id(102, Some(100)),
            mock_consensus::BlockHeader::with_id(103, Some(101)),
            mock_consensus::BlockHeader::with_id(105, Some(104)),
            mock_consensus::BlockHeader::with_id(999, Some(888)),
        ];

        // verify providers and that if a new provider is added while a block request is already in
        // progress, the new provider is added to the list of providers in case the request fails
        for header in &headers {
            let peers = if let Some(info) = mgr.work.get(&header) {
                info
            } else if let Some((_, info)) = mgr.active.get(&header) {
                info
            } else {
                panic!("invalid etry");
            };

            let expected = if header == &headers[0] || header == &headers[1] {
                HashSet::from([peer_id1, peer_id2, peer_id3])
            } else if header == &headers[2] {
                HashSet::from([peer_id1])
            } else {
                HashSet::from([peer_id3])
            };

            assert_eq!(&expected, peers);
        }

        // unregister peer2 and verify that as its work also had other providers,
        // the work has been reassigned to peers 1 and 3
        assert_eq!(mgr.unregister_peer(peer_id2).await, Ok(()));

        assert_eq!(mgr.active.len(), 1);
        assert_eq!(mgr.work.len(), 3);

        for header in &headers {
            let peers = if let Some(info) = mgr.work.get(&header) {
                info
            } else if let Some((_, info)) = mgr.active.get(&header) {
                info
            } else {
                panic!("invalid etry");
            };

            let expected = if header == &headers[0] || header == &headers[1] {
                HashSet::from([peer_id1, peer_id3])
            } else if header == &headers[2] {
                HashSet::from([peer_id1])
            } else {
                HashSet::from([peer_id3])
            };

            assert_eq!(&expected, peers);
        }
    }
}
