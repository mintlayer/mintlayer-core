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
    error::{self, P2pError},
    event,
    net::{self, FloodsubService, NetworkService},
};
use common::chain::ChainConfig;
use futures::FutureExt;
use logging::log;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};

pub mod blkidx;
pub mod mock_consensus;
pub mod peer;

/// State of the peer
#[derive(Debug, PartialEq, Eq)]
pub enum SyncState {
    /// No activity with the peer
    Idle,

    // Downloading headers
    DownloadingHeaders,

    /// Downloading blocks
    DownloadingBlocks,
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
    /// Chain config
    config: Arc<ChainConfig>,

    /// Syncing state of the local node
    state: SyncState,

    /// Handle for sending/receiving connectivity events
    handle: T::FloodsubHandle,

    /// TX channel for sending subsystem-related queries
    p2p_handle: event::P2pEventHandle,

    /// RX channel for receiving syncing-related control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// RX channel for receiving syncing events from peers
    rx_peer: mpsc::Receiver<event::PeerSyncEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, peer::PeerSyncState<T>>,
}

impl<T> SyncManager<T>
where
    T: NetworkService,
    T::FloodsubHandle: FloodsubService<T>,
{
    pub fn new(
        config: Arc<ChainConfig>,
        handle: T::FloodsubHandle,
        tx_p2p: mpsc::Sender<event::P2pEvent>,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
        rx_peer: mpsc::Receiver<event::PeerSyncEvent<T>>,
    ) -> Self {
        Self {
            config,
            state: SyncState::Idle,
            handle,
            p2p_handle: event::P2pEventHandle::new(tx_p2p),
            rx_sync,
            rx_peer,
            peers: Default::default(),
        }
    }

    /// Handle floodsub event
    pub fn on_floodsub_event(&mut self, event: net::FloodsubEvent<T>) -> error::Result<()> {
        let net::FloodsubEvent::MessageReceived {
            peer_id: _,
            topic,
            message,
        } = event;

        match topic {
            net::FloodsubTopic::Transactions => {
                log::debug!("received new transaction: {:#?}", message);
            }
            net::FloodsubTopic::Blocks => {
                log::debug!("received new block: {:#?}", message);
            }
        }

        Ok(())
    }

    /// Handle control-related sync event from P2P/SwarmManager
    pub async fn on_sync_event(&mut self, event: event::SyncControlEvent<T>) -> error::Result<()> {
        match event {
            event::SyncControlEvent::Connected { peer_id, tx } => {
                log::debug!("create new entry for peer {:?}", peer_id);

                if let Entry::Vacant(e) = self.peers.entry(peer_id) {
                    e.insert(peer::PeerSyncState::new(peer_id, tx.clone()))
                        .get_headers(self.p2p_handle.get_locator().await?)
                        .await?;
                } else {
                    log::error!("peer {:?} already known by sync manager", peer_id);
                }
            }
            event::SyncControlEvent::Disconnected { peer_id } => {
                self.peers
                    .remove(&peer_id)
                    .ok_or_else(|| P2pError::Unknown("Peer does not exist".to_string()))
                    .map(|_| log::debug!("remove peer {:?}", peer_id))
                    .map_err(|_| log::error!("peer {:?} not known by sync manager", peer_id));
            }
        }

        Ok(())
    }

    /// Handle syncing-related event received from a remote peer
    pub async fn on_peer_event(&mut self, event: event::PeerSyncEvent<T>) -> error::Result<()> {
        match event {
            event::PeerSyncEvent::GetHeaders { peer_id, locator } => {
                let headers = self.p2p_handle.get_headers(locator).await?;
                let peer = self.peers.get_mut(&peer_id.expect("PeerID to be valid"));

                match peer {
                    Some(peer) => peer.send_headers(headers).await?,
                    None => log::error!("peer {:?} not known by sync manager", peer_id),
                }
            }
            event::PeerSyncEvent::Headers { peer_id, headers } => {
                let blkidx = blkidx::PeerBlockIndex::from_headers(&headers);
                let uniq_headers = self.p2p_handle.get_uniq_headers(headers).await?;
                let peer = self.peers.get_mut(&peer_id.expect("PeerID to be valid"));

                match peer {
                    Some(peer) => {
                        peer.add_blkidx(blkidx);
                        peer.get_blocks(uniq_headers).await?;
                    }
                    None => {
                        log::error!("peer {:?} not known by sync manager", peer_id)
                    }
                }
            }
            event::PeerSyncEvent::Blocks { peer_id, blocks } => {
                for block in blocks {
                    self.p2p_handle.new_block(block).await?;
                }
            }
            event::PeerSyncEvent::GetBlocks { peer_id, headers } => {
                let blocks = self.p2p_handle.get_blocks(headers).await?;
                let peer = self.peers.get_mut(&peer_id.expect("PeerID to be valid"));

                match peer {
                    Some(peer) => peer.send_blocks(blocks).await?,
                    None => log::error!("peer {:?} not known by sync manager", peer_id),
                }
            }
        }

        Ok(())
    }

    /// Run SyncManager event loop
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting sync manager event loop");

        loop {
            tokio::select! {
                res = self.handle.poll_next() => {
                    self.on_floodsub_event(res?)?;
                }
                res = self.rx_sync.recv().fuse() => {
                    self.on_sync_event(res.ok_or(P2pError::ChannelClosed)?).await?;
                }
                res = self.rx_peer.recv().fuse() => {
                    self.on_peer_event(res.ok_or(P2pError::ChannelClosed)?).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{mock::MockService, FloodsubService};
    use common::chain::config;
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
        T::FloodsubHandle: FloodsubService<T>,
    {
        let config = Arc::new(config::create_mainnet());
        let (_, flood) = T::start(addr, &[], &[]).await.unwrap();
        let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
        let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(16);
        let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);

        (
            SyncManager::<T>::new(Arc::clone(&config), flood, tx_p2p, rx_sync, rx_peer),
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

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected { peer_id, tx }).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);
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

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected { peer_id, tx }).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // no peer with this id exist, nothing happens
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Disconnected { peer_id: addr }).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Disconnected { peer_id }).await,
            Ok(())
        );
        assert!(mgr.peers.is_empty());
    }
}
