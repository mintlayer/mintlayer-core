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
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, oneshot};

pub mod blkidx;
pub mod mock_consensus;

/// State of the peer
#[derive(Debug, PartialEq, Eq)]
enum SyncState {
    /// No activity with the peer
    Idle,

    // Downloading headers
    DownloadingHeaders,

    /// Downloading blocks
    DownloadingBlocks,
}

struct PeerSyncState<T>
where
    T: NetworkService,
{
    /// Unique peer ID
    peer_id: T::PeerId,

    // State of the peer
    state: SyncState,

    /// TX channel for sending syncing messages to remote peer
    tx: mpsc::Sender<event::PeerEvent<T>>,

    /// Peer block index
    blkidx: Option<blkidx::PeerBlockIndex>,
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
    peers: HashMap<T::PeerId, PeerSyncState<T>>,
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
    fn on_floodsub_event(&mut self, event: net::FloodsubEvent<T>) -> error::Result<()> {
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
    async fn on_sync_event(&mut self, event: event::SyncControlEvent<T>) -> error::Result<()> {
        match event {
            event::SyncControlEvent::Connected { peer_id, tx } => {
                log::debug!("create new entry for peer {:?}", peer_id);

                if let std::collections::hash_map::Entry::Vacant(e) = self.peers.entry(peer_id) {
                    e.insert(PeerSyncState {
                        peer_id,
                        state: SyncState::DownloadingHeaders,
                        tx: tx.clone(),
                        blkidx: None,
                    });

                    tx.send(event::PeerEvent::Syncing(
                        event::PeerSyncEvent::GetHeaders {
                            peer_id: None,
                            locator: self.p2p_handle.get_locator().await?,
                        },
                    ))
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
    async fn on_peer_event(&mut self, event: event::PeerSyncEvent<T>) -> error::Result<()> {
        match event {
            event::PeerSyncEvent::GetHeaders { peer_id, locator } => {
                let headers = self.p2p_handle.get_headers(locator).await?;
                let peer = self.peers.get_mut(&peer_id.expect("PeerID to be valid"));

                match peer {
                    Some(peer) => {
                        peer.tx
                            .send(event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
                                peer_id: None,
                                headers,
                            }))
                            .await?;
                    }
                    None => {
                        log::error!("peer {:?} not known by sync manager", peer_id)
                    }
                }
            }
            event::PeerSyncEvent::Headers { peer_id, headers } => {
                let blkidx = blkidx::PeerBlockIndex::from_headers(&headers);
                let uniq_headers = self.p2p_handle.get_uniq_headers(headers).await?;
                let peer = self.peers.get_mut(&peer_id.expect("PeerID to be valid"));

                match peer {
                    Some(peer) => {
                        (*peer).blkidx = Some(blkidx);
                        if !uniq_headers.is_empty() {
                            peer.tx
                                .send(event::PeerEvent::Syncing(event::PeerSyncEvent::GetBlocks {
                                    peer_id: None,
                                    headers: uniq_headers,
                                }))
                                .await?;
                        }
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
            _ => println!("unknown event"),
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

    // verify that if local and remote nodes are in sync (they have the same mainchain)
    // no blocks are exchanged after getheaders messages have been exchanged
    #[tokio::test]
    async fn local_and_remote_in_sync() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
        let mut remote_cons = mock_consensus::Consensus::with_height(8);

        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        let mut local_cons = remote_cons.clone();
        let handle = tokio::spawn(async move {
            // verify that the first message that the consensus receives is the locator request
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(local_cons.get_locator());
                }
            );

            // verify that after getheaders has been sent (internally) and remote peer has responded
            // to it with their (possibly) new headers, getuniqheaders request is received and as local
            // and remote node are in sync, `get_uniq_headers()` returns an empty vector
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert!(uniq.is_empty());
                    response.send(uniq);
                }
            );

            // verify that after local node has sent its header request, the remote node sends its own headers
            // request, process is appropriately. In practice these could come in either order
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetHeaders { locator, response },
                {
                    let headers = local_cons.get_headers(&locator);
                    let all_headers = local_cons.as_vec();

                    // verify that only the two most recent block headers are sent to remote node
                    assert_eq!((headers[0], headers[1]), (all_headers[1], all_headers[0]));

                    response.send(headers);
                }
            );
        });

        // add peer to the hashmap of known peers and send getheaders request to them
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected {
                peer_id,
                tx: peer_tx
            })
            .await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // verify that when the connection has been established,
        // the remote peer will receive getheaders request
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
                peer_id: _,
                locator
            }),
            {
                let headers = remote_cons.get_headers(&locator);
                let all_headers = remote_cons.as_vec();

                // verify that only the two most recent block headers are sent to local node
                assert_eq!((headers[0], headers[1]), (all_headers[1], all_headers[0]),);

                assert_eq!(
                    mgr.on_peer_event(event::PeerSyncEvent::Headers {
                        peer_id: Some(peer_id),
                        headers,
                    })
                    .await,
                    Ok(())
                );
            }
        );

        // now remote peer sends getheaders request to local sync node and it should
        // get the same response
        let locator = remote_cons.get_locator();

        assert_eq!(
            mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
                peer_id: Some(peer_id),
                locator,
            })
            .await,
            Ok(())
        );

        // after the possibly new headers have been received from remote, verify that they
        // aren't actually unique and that remote node doesn't have to download any new
        // blocks from the local node
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
                peer_id: _,
                headers
            }),
            {
                assert!(remote_cons.get_uniq_headers(&headers).is_empty());
            }
        );
    }

    // local and remote nodes are in the same chain but remote is ahead 7 blocks
    //
    // this the remote node is synced first and as it's ahead of local node,
    // no blocks are downloaded whereas loca node downloads the 7 new blocks from remote
    #[tokio::test]
    async fn remote_ahead_by_7_blocks() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
        let mut remote_cons = mock_consensus::Consensus::with_height(8);
        let mut local_cons = remote_cons.clone();
        let mut new_block_hdrs = vec![];

        // add 7 more blocks to remote's chain
        for _ in 0..7 {
            let cur_id = remote_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            new_block_hdrs.push(block.header);
            remote_cons.accept_block(block);
        }

        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        let handle = tokio::spawn(async move {
            // verify that the first message that the consensus receives is the locator request
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(local_cons.get_locator());
                }
            );

            // verify that as the remote is ahead of local by 7 blocks, extracting the unique
            // headers from the header response results in 7 new headers and that the headers
            // belong to the 7 new blocks that were added to the remote chain
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert_eq!(uniq.len(), 7);
                    assert_eq!(uniq, new_block_hdrs);
                    response.send(uniq);
                }
            );
        });

        // add peer to the hashmap of known peers and send getheaders request to them
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected {
                peer_id,
                tx: peer_tx
            })
            .await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // verify that when the connection has been established,
        // the remote peer will receive getheaders request
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
                peer_id: _,
                locator
            }),
            {
                assert_eq!(
                    mgr.on_peer_event(event::PeerSyncEvent::Headers {
                        peer_id: Some(peer_id),
                        headers: remote_cons.get_headers(&locator),
                    })
                    .await,
                    Ok(())
                );
            }
        );
    }

    // local and remote nodes are in the same chain but local is ahead of remote by 12 blocks
    #[tokio::test]
    async fn local_ahead_by_12_blocks() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
        let mut remote_cons = mock_consensus::Consensus::with_height(8);
        let mut local_cons = remote_cons.clone();
        let mut new_block_hdrs = vec![];

        // add 12 more blocks to local's chain
        for _ in 0..12 {
            let cur_id = local_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            new_block_hdrs.push(block.header);
            local_cons.accept_block(block);
        }

        let (peer_tx, mut peer_rx) = mpsc::channel(1);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        let handle = tokio::spawn(async move {
            // verify that the first message that the consensus receives is the locator request
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(local_cons.get_locator());
                }
            );

            // as local is ahead of remote, getuniqheaders returns an empty vector
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert!(uniq.is_empty());
                    response.send(uniq);
                }
            );

            // verify that as the local node is ahead of remote by 12 blocks,
            // the header response contains at least 12 headers
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetHeaders { locator, response },
                {
                    let headers = local_cons.get_headers(&locator);
                    assert!(headers.len() >= 12);
                    response.send(headers);
                }
            );
        });

        // add peer to the hashmap of known peers and send getheaders request to them
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected {
                peer_id,
                tx: peer_tx
            })
            .await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // verify that when the connection has been established,
        // the remote peer will receive getheaders request
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
                peer_id: _,
                locator
            }),
            {
                assert_eq!(
                    mgr.on_peer_event(event::PeerSyncEvent::Headers {
                        peer_id: Some(peer_id),
                        headers: remote_cons.get_headers(&locator),
                    })
                    .await,
                    Ok(())
                );
            }
        );

        let locator = remote_cons.get_locator();
        assert_eq!(
            mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
                peer_id: Some(peer_id),
                locator,
            })
            .await,
            Ok(())
        );

        // verify that after extracting the uniq headers from the response,
        // remote is left with 12 new block headers
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
                peer_id: _,
                headers
            }),
            {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 12);
                assert_eq!(uniq, new_block_hdrs);
            }
        );
    }

    // local and remote nodes are in different chains and remote has longer chain
    #[tokio::test]
    async fn remote_local_diff_chains_remote_higher() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
        let mut remote_cons = mock_consensus::Consensus::with_height(8);
        let mut local_cons = remote_cons.clone();
        let mut new_remote_block_hdrs = vec![];
        let mut new_local_block_hdrs = vec![];

        // add 8 more blocks to remote's chain
        for _ in 0..8 {
            let cur_id = remote_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            new_remote_block_hdrs.push(block.header);
            remote_cons.accept_block(block);
        }

        // add 5 more blocks to local's chain
        for _ in 0..5 {
            let cur_id = local_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            new_local_block_hdrs.push(block.header);
            local_cons.accept_block(block);
        }

        let (peer_tx, mut peer_rx) = mpsc::channel(3);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        let handle = tokio::spawn(async move {
            // verify that the first message that the consensus receives is the locator request
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(local_cons.get_locator());
                }
            );

            // as remote is a different branch that has 8 new blocks since the common ancestor
            // `get_uniq_headers()` will return those headers from the entire response
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert_eq!(uniq.len(), 8);
                    assert_eq!(uniq, new_remote_block_hdrs);
                    response.send(uniq);
                }
            );

            // as the local node is in a different branch than remote that has 5 blocks
            // since the common ancestors, the response contains at least 5 headers
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetHeaders { locator, response },
                {
                    let headers = local_cons.get_headers(&locator);
                    assert!(headers.len() >= 5);
                    response.send(headers);
                }
            );
        });

        // add peer to the hashmap of known peers and send getheaders request to them
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected {
                peer_id,
                tx: peer_tx
            })
            .await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // verify that when the connection has been established,
        // the remote peer will receive getheaders request
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
                peer_id: _,
                locator
            }),
            {
                assert_eq!(
                    mgr.on_peer_event(event::PeerSyncEvent::Headers {
                        peer_id: Some(peer_id),
                        headers: remote_cons.get_headers(&locator),
                    })
                    .await,
                    Ok(())
                );
            }
        );

        let locator = remote_cons.get_locator();
        assert_eq!(
            mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
                peer_id: Some(peer_id),
                locator,
            })
            .await,
            Ok(())
        );

        let _ = peer_rx.recv().await.unwrap();

        // verify that after extracting the uniq headers from the response,
        // remote is left with 12 new block headers
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
                peer_id: _,
                headers
            }),
            {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 5);
                assert_eq!(uniq, new_local_block_hdrs);
            }
        );
    }

    // remote and local are in different branches and local has longer chain
    #[tokio::test]
    async fn remote_local_diff_chains_local_higher() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, _, mut rx_p2p) = make_sync_manager::<MockService>(addr).await;
        let mut remote_cons = mock_consensus::Consensus::with_height(8);
        let mut local_cons = remote_cons.clone();
        let mut new_remote_block_hdrs = vec![];
        let mut new_local_block_hdrs = vec![];

        // add 8 more blocks to remote's chain
        for _ in 0..3 {
            let cur_id = remote_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            new_remote_block_hdrs.push(block.header);
            remote_cons.accept_block(block);
        }

        // add 5 more blocks to local's chain
        for _ in 0..16 {
            let cur_id = local_cons.mainchain.blkid;
            let block = mock_consensus::Block::new(Some(cur_id));
            new_local_block_hdrs.push(block.header);
            local_cons.accept_block(block);
        }

        let (peer_tx, mut peer_rx) = mpsc::channel(2);
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        let handle = tokio::spawn(async move {
            // verify that the first message that the consensus receives is the locator request
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetLocator { response },
                {
                    response.send(local_cons.get_locator());
                }
            );

            // as remote is a different branch that has 8 new blocks since the common ancestor
            // `get_uniq_headers()` will return those headers from the entire response
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetUniqHeaders { headers, response },
                {
                    let uniq = local_cons.get_uniq_headers(&headers);
                    assert_eq!(uniq.len(), 3);
                    assert_eq!(uniq, new_remote_block_hdrs);
                    response.send(uniq);
                }
            );

            // as the local node is in a different branch than remote that has 5 blocks
            // since the common ancestors, the response contains at least 5 headers
            get_message!(
                rx_p2p.recv().await.unwrap(),
                event::P2pEvent::GetHeaders { locator, response },
                {
                    let headers = local_cons.get_headers(&locator);
                    assert!(headers.len() >= 16);
                    response.send(headers);
                }
            );
        });

        // add peer to the hashmap of known peers and send getheaders request to them
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected {
                peer_id,
                tx: peer_tx
            })
            .await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // verify that when the connection has been established,
        // the remote peer will receive getheaders request
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::GetHeaders {
                peer_id: _,
                locator
            }),
            {
                assert_eq!(
                    mgr.on_peer_event(event::PeerSyncEvent::Headers {
                        peer_id: Some(peer_id),
                        headers: remote_cons.get_headers(&locator),
                    })
                    .await,
                    Ok(())
                );
            }
        );

        let locator = remote_cons.get_locator();
        assert_eq!(
            mgr.on_peer_event(event::PeerSyncEvent::GetHeaders {
                peer_id: Some(peer_id),
                locator,
            })
            .await,
            Ok(())
        );

        let _ = peer_rx.recv().await.unwrap();

        // verify that after extracting the uniq headers from the response,
        // remote is left with 12 new block headers
        get_message!(
            peer_rx.recv().await.unwrap(),
            event::PeerEvent::Syncing(event::PeerSyncEvent::Headers {
                peer_id: _,
                headers
            }),
            {
                let uniq = remote_cons.get_uniq_headers(&headers);
                assert_eq!(uniq.len(), 16);
                assert_eq!(uniq, new_local_block_hdrs);
            }
        );
    }
}
