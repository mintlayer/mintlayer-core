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

use crate::{
    error::{self, FatalError, P2pError, ProtocolError},
    event,
    message::{Message, MessageType, SyncingMessage, SyncingRequest, SyncingResponse},
    net::{self, NetworkService, SyncingService},
};
use common::{
    chain::{
        block::{Block, BlockHeader},
        config::ChainConfig,
    },
    primitives::Idable,
};
use consensus::{consensus_interface, BlockError, BlockSource, ConsensusError::ProcessBlockError};
use futures::FutureExt;
use logging::log;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};
use tokio::sync::mpsc;

// TODO: add wrapper api for the request api
// TODO: update peer state after each call

pub mod mock_consensus;
pub mod peer;

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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// Local node's state is uninitialized
    Uninitialized,

    /// Downloading blocks from remote node(s)
    DownloadingBlocks,

    /// Local block index is fully synced
    Idle,
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
    handle: T::SyncingHandle,

    /// RX channel for receiving syncing-related control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, peer::PeerContext<T>>,

    /// Subsystem handle to Consensus
    consensus: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
}

impl<T> SyncManager<T>
where
    T: NetworkService,
    T::SyncingHandle: SyncingService<T>,
{
    pub fn new(
        config: Arc<ChainConfig>,
        handle: T::SyncingHandle,
        consensus: subsystem::Handle<Box<dyn consensus_interface::ConsensusInterface>>,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
    ) -> Self {
        Self {
            config,
            handle,
            rx_sync,
            consensus,
            peers: Default::default(),
            state: SyncState::Uninitialized,
        }
    }

    pub fn state(&self) -> &SyncState {
        &self.state
    }

    pub fn handle_mut(&mut self) -> &mut T::SyncingHandle {
        &mut self.handle
    }

    pub async fn register_peer(&mut self, peer_id: T::PeerId) -> error::Result<()> {
        log::info!("register peer {:?} to sync manager", peer_id);

        match self.peers.entry(peer_id) {
            Entry::Occupied(_) => Err(P2pError::PeerExists),
            Entry::Vacant(entry) => {
                let locator = self.consensus.call(move |this| this.get_locator()).await?.unwrap();
                // let locator = self.p2p_handle.get_locator().await?;
                entry.insert(peer::PeerContext::new(peer_id));
                // TODO: save request somewhere with a timer
                let _ = self
                    .handle
                    .send_request(
                        peer_id,
                        Message {
                            magic: *self.config.magic_bytes(),
                            msg: MessageType::Syncing(SyncingMessage::Request(
                                SyncingRequest::GetHeaders { locator },
                            )),
                        },
                    )
                    .await?;
                Ok(())
            }
        }
    }

    pub async fn unregister_peer(&mut self, peer_id: T::PeerId) -> error::Result<()> {
        log::info!("unregister peer {:?}", peer_id);

        self.peers.remove(&peer_id);
        Ok(())
    }

    pub async fn process_header_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        locator: Vec<BlockHeader>,
    ) -> error::Result<()> {
        log::trace!(
            "received a header request from peer {:?}, locator {:#?}",
            peer_id,
            locator
        );

        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;
        // let headers = self.p2p_handle.get_headers(locator).await?;
        let headers = self.consensus.call(move |this| this.get_headers(locator)).await?.unwrap();

        self.handle
            .send_response(
                request_id,
                Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
                        headers,
                    })),
                },
            )
            .await
    }

    async fn process_block_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        headers: Vec<BlockHeader>,
    ) -> error::Result<()> {
        log::trace!(
            "received a block request from peer {:?}, header counter {}",
            peer_id,
            headers.len(),
        );

        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;
        // let blocks = self.p2p_handle.get_blocks(headers.to_vec()).await?;
        debug_assert!(headers.len() == 1);
        let blocks = vec![self
            .consensus
            .call(move |this| this.get_block(headers[0].get_id()))
            .await?
            .unwrap()
            .unwrap()];

        self.handle
            .send_response(
                request_id,
                Message {
                    magic: *self.config.magic_bytes(),
                    msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Blocks {
                        blocks,
                    })),
                },
            )
            .await
    }

    async fn process_header_response(
        &mut self,
        peer_id: T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> error::Result<()> {
        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;

        log::debug!(
            "initialize peer {:?} state, headers: {:#?}",
            peer_id,
            headers
        );

        // TODO: check error, ban peer
        let headers =
            self.consensus.call(move |this| this.get_uniq_headers(headers)).await?.unwrap();

        if !headers.is_empty() {
            if let Some(next_block) = peer.register_headers(&headers) {
                let _ = self
                    .handle
                    .send_request(
                        peer_id,
                        Message {
                            magic: *self.config.magic_bytes(),
                            msg: MessageType::Syncing(SyncingMessage::Request(
                                SyncingRequest::GetBlocks {
                                    headers: vec![next_block.clone()],
                                },
                            )),
                        },
                    )
                    .await;
                peer.set_state(peer::PeerSyncState::UploadingBlocks(next_block));
            }
        } else {
            peer.set_state(peer::PeerSyncState::Idle);
        }

        Ok(())
    }

    async fn process_block_response(
        &mut self,
        peer_id: T::PeerId,
        blocks: Vec<Block>,
    ) -> error::Result<()> {
        log::trace!("received {} blocks from peer {:?}", blocks.len(), peer_id,);
        debug_assert!(blocks.len() == 1);

        let peer_id__ = {
            let mut iretid = None;
            for (i, (id, _)) in self.peers.iter().enumerate() {
                if id == &peer_id {
                    iretid = Some(i);
                }
            }

            iretid
        };

        let peer = self.peers.get_mut(&peer_id).ok_or(P2pError::PeerDoesntExist)?;

        // TODO: check error, ban peer
        let block = blocks[0].clone();
        match self
            .consensus
            .call_mut(move |this| {
                this.process_block(block, BlockSource::Peer(peer_id__.unwrap() as u32))
            })
            .await?
        {
            Ok(_) => {}
            Err(ProcessBlockError(BlockError::BlockAlreadyExists(id))) => {
                log::warn!("block {:?} already exists", id)
            }
            Err(e) => return Err(P2pError::Unknown("consesus error".to_string())),
        }

        match peer.register_block_response((blocks[0]).header()) {
            Ok(Some(next_block)) => {
                let _ = self
                    .handle
                    .send_request(
                        peer_id,
                        Message {
                            magic: *self.config.magic_bytes(),
                            msg: MessageType::Syncing(SyncingMessage::Request(
                                SyncingRequest::GetBlocks {
                                    headers: vec![next_block.clone()],
                                },
                            )),
                        },
                    )
                    .await?;
                peer.set_state(peer::PeerSyncState::UploadingBlocks(next_block));
                Ok(())
            }
            Ok(None) => {
                // last block from peer, ask if peer knows of any new headers
                // let locator = self.p2p_handle.get_locator().await?;
                let locator = self.consensus.call(move |this| this.get_locator()).await?.unwrap();
                let _ = self
                    .handle
                    .send_request(
                        peer_id,
                        Message {
                            magic: *self.config.magic_bytes(),
                            msg: MessageType::Syncing(SyncingMessage::Request(
                                SyncingRequest::GetHeaders { locator },
                            )),
                        },
                    )
                    .await?;
                peer.set_state(peer::PeerSyncState::UploadingHeaders);
                Ok(())
            }
            Err(e) => {
                // TODO: ban peer
                log::error!("peer sent invalid or unexpected data, close connection");
                Ok(())
            }
        }
    }

    // if all peers are idling, then it means we're idling -> fully synced
    pub fn check_state(&mut self) -> error::Result<()> {
        for peer in self.peers.values() {
            match peer.state() {
                peer::PeerSyncState::UploadingBlocks(_) => {
                    self.state = SyncState::DownloadingBlocks;
                    return Ok(());
                }
                peer::PeerSyncState::UploadingHeaders => {
                    self.state = SyncState::Uninitialized;
                    return Ok(());
                }
                _ => {}
            }
        }

        self.state = SyncState::Idle;
        Ok(())
    }

    /// Handle incoming block/header request/response
    pub async fn on_syncing_event(&mut self, event: net::SyncingMessage<T>) -> error::Result<()> {
        match event {
            net::SyncingMessage::Request {
                peer_id,
                request_id,
                request:
                    Message {
                        msg: MessageType::Syncing(SyncingMessage::Request(message)),
                        ..
                    },
            } => match message {
                SyncingRequest::GetHeaders { locator } => {
                    self.process_header_request(peer_id, request_id, locator).await
                }
                SyncingRequest::GetBlocks { headers } => {
                    self.process_block_request(peer_id, request_id, headers).await
                }
            },
            net::SyncingMessage::Response {
                peer_id,
                request_id: _,
                response:
                    Message {
                        msg: MessageType::Syncing(SyncingMessage::Response(message)),
                        ..
                    },
            } => match message {
                SyncingResponse::Headers { headers } => {
                    self.process_header_response(peer_id, headers).await
                }
                SyncingResponse::Blocks { blocks } => {
                    self.process_block_response(peer_id, blocks).await
                }
            },
            net::SyncingMessage::Request { peer_id, .. }
            | net::SyncingMessage::Response { peer_id, .. } => {
                log::error!("received an invalid message from peer {:?}", peer_id);
                // TODO: disconnect peer and ban it
                // TODO: send `Misbehaved` event to SwarmManager
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    /// Handle control-related sync event from P2P/SwarmManager
    async fn on_sync_event(&mut self, event: event::SyncControlEvent<T>) -> error::Result<()> {
        match event {
            event::SyncControlEvent::Connected(peer_id) => self.register_peer(peer_id).await,
            event::SyncControlEvent::Disconnected(peer_id) => self.unregister_peer(peer_id).await,
        }
    }

    /// Run SyncManager event loop
    pub async fn run(&mut self) -> error::Result<()> {
        log::info!("starting sync manager event loop");

        loop {
            tokio::select! {
                res = self.handle.poll_next() => {
                    self.on_syncing_event(res?).await.into_fatal()?;
                }
                res = self.rx_sync.recv().fuse() => {
                    self.on_sync_event(res.ok_or(P2pError::ChannelClosed)?).await.into_fatal()?;
                }
            }

            self.check_state().into_fatal()?;
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::net::{
//         libp2p::Libp2pService, mock::MockService, ConnectivityEvent, ConnectivityService,
//         SyncingService,
//     };
//     use common::chain::config;
//     use libp2p::{multiaddr::Protocol, PeerId};
//     use std::net::SocketAddr;

//     macro_rules! get_message {
//         ($expression:expr, $($pattern:pat_param)|+, $ret:expr) => {
//             match $expression {
//                 $($pattern)|+ => $ret,
//                 _ => panic!("invalid message received")
//             }
//         }
//     }
//     async fn make_sync_manager<T>(
//         addr: T::Address,
//     ) -> (
//         SyncManager<T>,
//         T::ConnectivityHandle,
//         mpsc::Sender<event::SyncControlEvent<T>>,
// <<<<<<< HEAD
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         mpsc::Sender<event::PeerSyncEvent<T>>,
// =======
//         mpsc::Receiver<event::P2pEvent>,
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)
//     )
//     where
//         T: NetworkService,
//         T::ConnectivityHandle: ConnectivityService<T>,
//         T::SyncingHandle: SyncingService<T>,
//     {
//         let (conn, _, sync) = T::start(
//             addr,
//             &[],
//             &[],
//             Arc::new(config::create_mainnet()),
//             std::time::Duration::from_secs(10),
//         )
//         .await
//         .unwrap();

// <<<<<<< HEAD
//         // let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
//         // let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
//         let (tx_peer, rx_peer) = tokio::sync::mpsc::channel(16);
// =======
//         let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
//         let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);
//         let config = common::chain::config::create_mainnet();
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)

// <<<<<<< HEAD
//         let mut manager = subsystem::Manager::new("mintlayer");
//         manager.install_signal_handlers();

//         // Consensus subsystem
//         // let cons = manager.add_subsystem(
//         //     "consensus",
//         //     consensus::make_consensus(
//         //         config::create_mainnet(),
//         //         blockchain_storage::Store::new_empty().unwrap(),
//         //     )
//         //     .unwrap(),
//         // );

//         // let cons = subsystem::Handle<ConsensusInterface>;

//         todo!();
//         // (
//         //     SyncManager::<T>::new(sync, cons, rx_p2p, rx_sync),
//         //     conn,
//         //     tx_sync,
//         // )
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         (SyncManager::<T>::new(sync, rx_sync), conn, tx_sync, tx_peer)
// =======
//         (
//             SyncManager::<T>::new(Arc::new(config), sync, rx_sync, tx_p2p),
//             conn,
//             tx_sync,
//             rx_p2p,
//         )
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)
//     }
//     // handle peer connection event
//     #[tokio::test]
//     async fn test_peer_connected() {
// <<<<<<< HEAD
//         let addr: SocketAddr = test_utils::make_address("[::1]:");
//         let (mut mgr, _, mut tx_sync) = make_sync_manager::<MockService>(addr).await;
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         let addr: SocketAddr = test_utils::make_address("[::1]:");
//         let (mut mgr, _, mut tx_sync, mut tx_peer) = make_sync_manager::<MockService>(addr).await;
// =======
//         let (mut mgr, _, _, mut rx_p2p) =
//             make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)

//         tokio::spawn(async move {
//             get_message!(
//                 rx_p2p.recv().await.unwrap(),
//                 event::P2pEvent::GetLocator { response },
//                 {
//                     response.send(mock_consensus::Consensus::with_height(4).get_locator());
//                 }
//             );
//         });

//         assert_eq!(
// <<<<<<< HEAD
//             mgr.on_sync_event(event::SyncControlEvent::Connected(peer_id)).await,
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//             mgr.on_sync_event(event::SyncControlEvent::Connected { peer_id }).await,
// =======
//             mgr.on_sync_event(event::SyncControlEvent::Connected {
//                 peer_id: PeerId::random()
//             })
//             .await,
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)
//             Ok(())
//         );
//         assert_eq!(mgr.peers.len(), 1);
//     }

//     // handle peer disconnection event
//     #[tokio::test]
//     async fn test_peer_disconnected() {
// <<<<<<< HEAD
//         let addr: SocketAddr = test_utils::make_address("[::1]:");
//         let (mut mgr, _, mut tx_sync) = make_sync_manager::<MockService>(addr).await;
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         let addr: SocketAddr = test_utils::make_address("[::1]:");
//         let (mut mgr, _, mut tx_sync, mut tx_peer) = make_sync_manager::<MockService>(addr).await;
// =======
//         let (mut mgr, _, _, mut rx_p2p) =
//             make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)

//         // send Connected event to SyncManager
//         let peer_id = PeerId::random();

//         tokio::spawn(async move {
//             get_message!(
//                 rx_p2p.recv().await.unwrap(),
//                 event::P2pEvent::GetLocator { response },
//                 {
//                     response.send(mock_consensus::Consensus::with_height(4).get_locator());
//                 }
//             );
//         });

//         assert_eq!(
//             mgr.on_sync_event(event::SyncControlEvent::Connected(peer_id)).await,
//             Ok(())
//         );
//         assert_eq!(mgr.peers.len(), 1);

//         // no peer with this id exist, nothing happens
//         assert_eq!(
// <<<<<<< HEAD
//             mgr.on_sync_event(event::SyncControlEvent::Disconnected(addr)).await,
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//             mgr.on_sync_event(event::SyncControlEvent::Disconnected { peer_id: addr }).await,
// =======
//             mgr.on_sync_event(event::SyncControlEvent::Disconnected {
//                 peer_id: PeerId::random()
//             })
//             .await,
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)
//             Ok(())
//         );
//         assert_eq!(mgr.peers.len(), 1);

//         assert_eq!(
//             mgr.on_sync_event(event::SyncControlEvent::Disconnected(peer_id)).await,
//             Ok(())
//         );
//         assert!(mgr.peers.is_empty());
//     }

//     // #[tokio::test]
//     // async fn test_request_response() {
//     //     let (mut mgr1, mut conn1, _, _) =
//     //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
//     //     let (mut mgr2, mut conn2, _, _) =
//     //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

//     //     let (conn1_res, conn2_res) =
//     //         tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
//     //     let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
//     //     let conn1_id = match conn2_res {
//     //         ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
//     //         _ => panic!("invalid event received, expected incoming connection"),
//     //     };

// <<<<<<< HEAD
//     //     let req_id = mgr1
//     //         .handle
//     //         .send_request(
//     //             *conn2.peer_id(),
//     //             Message {
//     //                 magic: [1, 2, 3, 4],
//     //                 msg: MessageType::Syncing(SyncingMessage::Request(
//     //                     SyncingRequest::GetHeaders { locator: vec![] },
//     //                 )),
//     //             },
//     //         )
//     //         .await
//     //         .unwrap();
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         let req_id = mgr1
//             .handle
//             .send_request(
//                 *conn2.peer_id(),
//                 Message {
//                     magic: [1, 2, 3, 4],
//                     msg: MessageType::Syncing(SyncingMessage::Request(
//                         SyncingRequest::GetHeaders { locator: vec![] },
//                     )),
//                 },
//             )
//             .await
//             .unwrap();
// =======
//         let req_id = mgr1
//             .handle
//             .send_request(
//                 *conn2.peer_id(),
//                 Message {
//                     magic: [5, 6, 7, 8],
//                     msg: MessageType::Syncing(SyncingMessage::Request(
//                         SyncingRequest::GetHeaders { locator: vec![] },
//                     )),
//                 },
//             )
//             .await
//             .unwrap();
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)

// <<<<<<< HEAD
//     //     if let Ok(net::SyncingMessage::Request {
//     //         peer_id,
//     //         request_id,
//     //         request,
//     //     }) = mgr2.handle.poll_next().await
//     //     {
//     //         assert_eq!(
//     //             request,
//     //             Message {
//     //                 magic: [1, 2, 3, 4],
//     //                 msg: MessageType::Syncing(SyncingMessage::Request(
//     //                     SyncingRequest::GetHeaders { locator: vec![] }
//     //                 ))
//     //             }
//     //         );
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         if let Ok(net::SyncingMessage::Request {
//             peer_id,
//             request_id,
//             request,
//         }) = mgr2.handle.poll_next().await
//         {
//             assert_eq!(
//                 request,
//                 Message {
//                     magic: [1, 2, 3, 4],
//                     msg: MessageType::Syncing(SyncingMessage::Request(
//                         SyncingRequest::GetHeaders { locator: vec![] }
//                     ))
//                 }
//             );
// =======
//         if let Ok(net::SyncingMessage::Request {
//             peer_id,
//             request_id,
//             request,
//         }) = mgr2.handle.poll_next().await
//         {
//             assert_eq!(
//                 request,
//                 Message {
//                     magic: [5, 6, 7, 8],
//                     msg: MessageType::Syncing(SyncingMessage::Request(
//                         SyncingRequest::GetHeaders { locator: vec![] }
//                     ))
//                 }
//             );
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)

//     //         mgr2.handle
//     //             .send_response(
//     //                 request_id,
//     //                 Message {
//     //                     magic: [5, 6, 7, 8],
//     //                     msg: MessageType::Syncing(SyncingMessage::Response(
//     //                         SyncingResponse::Headers { headers: vec![] },
//     //                     )),
//     //                 },
//     //             )
//     //             .await
//     //             .unwrap();
//     //     } else {
//     //         panic!("invalid data received");
//     //     }

//     //     if let Ok(net::SyncingMessage::Response {
//     //         peer_id, response, ..
//     //     }) = mgr1.handle.poll_next().await
//     //     {
//     //         assert_eq!(
//     //             response,
//     //             Message {
//     //                 magic: [5, 6, 7, 8],
//     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//     //                     headers: vec![]
//     //                 },)),
//     //             },
//     //         );
//     //     } else {
//     //         panic!("invalid data received");
//     //     }
//     // }

//     // // peer1 sends to requests to peer2 and peer2 responds to them out of order
//     // #[tokio::test]
//     // async fn test_multiple_requests_and_responses() {
//     //     let (mut mgr1, mut conn1, _, _) =
//     //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
//     //     let (mut mgr2, mut conn2, _, _) =
//     //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

//     //     let (conn1_res, conn2_res) =
//     //         tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
//     //     let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
//     //     let conn1_id = match conn2_res {
//     //         ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
//     //         _ => panic!("invalid event received, expected incoming connection"),
//     //     };

// <<<<<<< HEAD
//     //     let req_id1 = mgr1
//     //         .handle
//     //         .send_request(
//     //             *conn2.peer_id(),
//     //             Message {
//     //                 magic: [1, 2, 3, 4],
//     //                 msg: MessageType::Syncing(SyncingMessage::Request(
//     //                     SyncingRequest::GetHeaders { locator: vec![] },
//     //                 )),
//     //             },
//     //         )
//     //         .await
//     //         .unwrap();
// ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
//         let req_id1 = mgr1
//             .handle
//             .send_request(
//                 *conn2.peer_id(),
//                 Message {
//                     magic: [1, 2, 3, 4],
//                     msg: MessageType::Syncing(SyncingMessage::Request(
//                         SyncingRequest::GetHeaders { locator: vec![] },
//                     )),
//                 },
//             )
//             .await
//             .unwrap();
// =======
//         let req_id1 = mgr1
//             .handle
//             .send_request(
//                 *conn2.peer_id(),
//                 Message {
//                     magic: [5, 6, 7, 8],
//                     msg: MessageType::Syncing(SyncingMessage::Request(
//                         SyncingRequest::GetHeaders { locator: vec![] },
//                     )),
//                 },
//             )
//             .await
//             .unwrap();
// >>>>>>> dad30749 (sync: Add simplified syncing implementation)

//     //     let req_id2 = mgr1
//     //         .handle
//     //         .send_request(
//     //             *conn2.peer_id(),
//     //             Message {
//     //                 magic: [5, 6, 7, 8],
//     //                 msg: MessageType::Syncing(SyncingMessage::Request(
//     //                     SyncingRequest::GetHeaders { locator: vec![] },
//     //                 )),
//     //             },
//     //         )
//     //         .await
//     //         .unwrap();

// <<<<<<< HEAD
// // <<<<<<< HEAD
// //         assert_ne!(req_id1, req_id2);
// //         let mut first_req_id = req_id1;
// // ||||||| parent of aab58647 (p2p: Add P2pInterface)
// //         assert_ne!(req_id1, req_id2);
// // =======
// //     //     assert_ne!(req_id1, req_id2);
// // >>>>>>> aab58647 (p2p: Add P2pInterface)
// ||||||| parent of 59c0418c (sync: Add simplified syncing implementation)
//     //     assert_ne!(req_id1, req_id2);
// =======
// //     //     assert_ne!(req_id1, req_id2);
// >>>>>>> 59c0418c (sync: Add simplified syncing implementation)

// //     //     let (recv_req1_id, request1) = if let Ok(net::SyncingMessage::Request {
// //     //         peer_id: _,
// //     //         request_id,
// //     //         request,
// //     //     }) = mgr2.handle.poll_next().await
// //     //     {
// //     //         (request_id, request)
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     };

// <<<<<<< HEAD
// // <<<<<<< HEAD
// //         let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
// //             peer_id: _,
// //             request_id,
// //             request,
// //         }) = mgr2.handle.poll_next().await
// //         {
// //             (request_id, request)
// //         } else {
// //             panic!("invalid data received");
// //         };
// // ||||||| parent of aab58647 (p2p: Add P2pInterface)
// //         // TODO: force order?
// ||||||| parent of 59c0418c (sync: Add simplified syncing implementation)
//     //     // TODO: force order?
// =======
// // <<<<<<< HEAD
// //     //     // TODO: force order?
// >>>>>>> 59c0418c (sync: Add simplified syncing implementation)

// <<<<<<< HEAD
// //         let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
// //             peer_id: _,
// //             request_id,
// //             request,
// //         }) = mgr2.handle.poll_next().await
// //         {
// //             (request_id, request)
// //         } else {
// //             panic!("invalid data received");
// //         };
// // =======
// //     //     // TODO: force order?
// ||||||| parent of 59c0418c (sync: Add simplified syncing implementation)
//     //     let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
//     //         peer_id: _,
//     //         request_id,
//     //         request,
//     //     }) = mgr2.handle.poll_next().await
//     //     {
//     //         (request_id, request)
//     //     } else {
//     //         panic!("invalid data received");
//     //     };
// =======
// //     //     let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
// //     //         peer_id: _,
// //     //         request_id,
// //     //         request,
// //     //     }) = mgr2.handle.poll_next().await
// //     //     {
// //     //         (request_id, request)
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     };
// // ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
// //         // TODO: force order?
// >>>>>>> 59c0418c (sync: Add simplified syncing implementation)

// <<<<<<< HEAD
// //     //     let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
// //     //         peer_id: _,
// //     //         request_id,
// //     //         request,
// //     //     }) = mgr2.handle.poll_next().await
// //     //     {
// //     //         (request_id, request)
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     };
// // >>>>>>> aab58647 (p2p: Add P2pInterface)
// ||||||| parent of 59c0418c (sync: Add simplified syncing implementation)
//     //     mgr2.handle
//     //         .send_response(
//     //             recv_req2_id,
//     //             Message {
//     //                 magic: [5, 6, 7, 8],
//     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//     //                     headers: vec![],
//     //                 })),
//     //             },
//     //         )
//     //         .await
//     //         .unwrap();
// =======
// //         let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
// //             peer_id: _,
// //             request_id,
// //             request,
// //         }) = mgr2.handle.poll_next().await
// //         {
// //             (request_id, request)
// //         } else {
// //             panic!("invalid data received");
// //         };
// // =======
// //         let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
// //             peer_id: _,
// //             request_id,
// //             request,
// //         }) = mgr2.handle.poll_next().await
// //         {
// //             (request_id, request)
// //         } else {
// //             panic!("invalid data received");
// //         };
// // >>>>>>> dad30749 (sync: Add simplified syncing implementation)
// >>>>>>> 59c0418c (sync: Add simplified syncing implementation)

// //     //     mgr2.handle
// //     //         .send_response(
// //     //             recv_req2_id,
// //     //             Message {
// //     //                 magic: [5, 6, 7, 8],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![],
// //     //                 })),
// //     //             },
// //     //         )
// //     //         .await
// //     //         .unwrap();

// <<<<<<< HEAD
// // <<<<<<< HEAD
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             first_req_id = request_id;
// //             assert!(request_id == req_id2 || request_id == req_id1);
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [5, 6, 7, 8],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// // ||||||| parent of aab58647 (p2p: Add P2pInterface)
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             assert_eq!(request_id, req_id2);
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [5, 6, 7, 8],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// // =======
// //     //     if let Ok(net::SyncingMessage::Response {
// //     //         peer_id,
// //     //         request_id,
// //     //         response,
// //     //     }) = mgr1.handle.poll_next().await
// //     //     {
// //     //         assert_eq!(request_id, req_id2);
// //     //         assert_eq!(
// //     //             response,
// //     //             Message {
// //     //                 magic: [5, 6, 7, 8],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![]
// //     //                 },)),
// //     //             },
// //     //         );
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     }
// // >>>>>>> aab58647 (p2p: Add P2pInterface)
// ||||||| parent of 59c0418c (sync: Add simplified syncing implementation)
//     //     mgr2.handle
//     //         .send_response(
//     //             recv_req1_id,
//     //             Message {
//     //                 magic: [1, 2, 3, 4],
//     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//     //                     headers: vec![],
//     //                 })),
//     //             },
//     //         )
//     //         .await
//     //         .unwrap();
// =======
// // <<<<<<< HEAD
// //     //     if let Ok(net::SyncingMessage::Response {
// //     //         peer_id,
// //     //         request_id,
// //     //         response,
// //     //     }) = mgr1.handle.poll_next().await
// //     //     {
// //     //         assert_eq!(request_id, req_id2);
// //     //         assert_eq!(
// //     //             response,
// //     //             Message {
// //     //                 magic: [5, 6, 7, 8],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![]
// //     //                 },)),
// //     //             },
// //     //         );
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     }
// // ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             assert_eq!(request_id, req_id2);
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [5, 6, 7, 8],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// // =======
// //         let mut next_id = req_id2;
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             // either response can come first as their order is not strictly specified
// //             if request_id == next_id {
// //                 next_id = req_id1;
// //             } else {
// //                 assert_eq!(request_id, req_id1);
// //             }
// >>>>>>> 59c0418c (sync: Add simplified syncing implementation)

// <<<<<<< HEAD
// //     //     mgr2.handle
// //     //         .send_response(
// //     //             recv_req1_id,
// //     //             Message {
// //     //                 magic: [1, 2, 3, 4],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![],
// //     //                 })),
// //     //             },
// //     //         )
// //     //         .await
// //     //         .unwrap();

// // <<<<<<< HEAD
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             if first_req_id == req_id1 {
// //                 assert_eq!(request_id, req_id2);
// //             } else {
// //                 assert_eq!(request_id, req_id1);
// //             }

// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [1, 2, 3, 4],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// //     }
// // ||||||| parent of aab58647 (p2p: Add P2pInterface)
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             assert_eq!(request_id, req_id1);
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [1, 2, 3, 4],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// //     }
// // =======
// //     //     if let Ok(net::SyncingMessage::Response {
// //     //         peer_id,
// //     //         request_id,
// //     //         response,
// //     //     }) = mgr1.handle.poll_next().await
// //     //     {
// //     //         assert_eq!(request_id, req_id1);
// //     //         assert_eq!(
// //     //             response,
// //     //             Message {
// //     //                 magic: [1, 2, 3, 4],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![]
// //     //                 },)),
// //     //             },
// //     //         );
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     }
// //     // }
// // >>>>>>> aab58647 (p2p: Add P2pInterface)
// }
// ||||||| parent of 59c0418c (sync: Add simplified syncing implementation)
//     //     if let Ok(net::SyncingMessage::Response {
//     //         peer_id,
//     //         request_id,
//     //         response,
//     //     }) = mgr1.handle.poll_next().await
//     //     {
//     //         assert_eq!(request_id, req_id1);
//     //         assert_eq!(
//     //             response,
//     //             Message {
//     //                 magic: [1, 2, 3, 4],
//     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//     //                     headers: vec![]
//     //                 },)),
//     //             },
//     //         );
//     //     } else {
//     //         panic!("invalid data received");
//     //     }
//     // }
// }
// =======
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [5, 6, 7, 8],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// // >>>>>>> dad30749 (sync: Add simplified syncing implementation)

// // <<<<<<< HEAD
// //     //     mgr2.handle
// //     //         .send_response(
// //     //             recv_req1_id,
// //     //             Message {
// //     //                 magic: [1, 2, 3, 4],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![],
// //     //                 })),
// //     //             },
// //     //         )
// //     //         .await
// //     //         .unwrap();
// // ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
// //         mgr2.handle
// //             .send_response(
// //                 recv_req1_id,
// //                 Message {
// //                     magic: [1, 2, 3, 4],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![],
// //                     })),
// //                 },
// //             )
// //             .await
// //             .unwrap();
// // =======
// //         mgr2.handle
// //             .send_response(
// //                 recv_req1_id,
// //                 Message {
// //                     magic: [5, 6, 7, 8],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![],
// //                     })),
// //                 },
// //             )
// //             .await
// //             .unwrap();
// // >>>>>>> dad30749 (sync: Add simplified syncing implementation)

// // <<<<<<< HEAD
// //     //     if let Ok(net::SyncingMessage::Response {
// //     //         peer_id,
// //     //         request_id,
// //     //         response,
// //     //     }) = mgr1.handle.poll_next().await
// //     //     {
// //     //         assert_eq!(request_id, req_id1);
// //     //         assert_eq!(
// //     //             response,
// //     //             Message {
// //     //                 magic: [1, 2, 3, 4],
// //     //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //     //                     headers: vec![]
// //     //                 },)),
// //     //             },
// //     //         );
// //     //     } else {
// //     //         panic!("invalid data received");
// //     //     }
// //     // }
// // ||||||| parent of dad30749 (sync: Add simplified syncing implementation)
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             assert_eq!(request_id, req_id1);
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [1, 2, 3, 4],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// //     }
// // =======
// //         if let Ok(net::SyncingMessage::Response {
// //             peer_id,
// //             request_id,
// //             response,
// //         }) = mgr1.handle.poll_next().await
// //         {
// //             assert_eq!(request_id, next_id);
// //             assert_eq!(
// //                 response,
// //                 Message {
// //                     magic: [5, 6, 7, 8],
// //                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
// //                         headers: vec![]
// //                     },)),
// //                 },
// //             );
// //         } else {
// //             panic!("invalid data received");
// //         }
// //     }
// // >>>>>>> dad30749 (sync: Add simplified syncing implementation)
// // }
// >>>>>>> 59c0418c (sync: Add simplified syncing implementation)
