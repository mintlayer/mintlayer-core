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
    error::{self, P2pError, ProtocolError},
    event,
    message::{Message, MessageType, SyncingMessage, SyncingRequest, SyncingResponse},
    net::{self, NetworkService, SyncingService},
};
use common::chain::block::{Block, BlockHeader};
use futures::FutureExt;
use logging::log;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::mpsc;

trait ConsensusInterface {
    fn get_locator(&mut self) -> Result<Vec<BlockHeader>, ()>;
    fn get_uniq_headers(&mut self, locator: Vec<BlockHeader>) -> Result<Vec<BlockHeader>, ()>;
}

/// State of the peer
enum PeerState {
    /// No activity with the peer
    Idle,
}

struct PeerSyncState<T>
where
    T: NetworkService,
{
    /// Unique peer ID
    peer_id: T::PeerId,

    /// State of the peer
    state: PeerState,
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
    /// Handle for sending/receiving connectivity events
    handle: T::SyncingHandle,

    /// RX channel for receiving syncing-related control events
    rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,

    /// Hashmap of connected peers
    peers: HashMap<T::PeerId, PeerSyncState<T>>,
}

impl<T> SyncManager<T>
where
    T: NetworkService,
    T::SyncingHandle: SyncingService<T>,
{
    pub fn new(
        handle: T::SyncingHandle,
        _: subsystem::Handle<consensus::ConsensusInterface>,
        _: mpsc::Receiver<event::SyncEvent>,
        rx_sync: mpsc::Receiver<event::SyncControlEvent<T>>,
    ) -> Self {
        Self {
            handle,
            rx_sync,
            peers: Default::default(),
        }
    }

    async fn process_header_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        locator: Vec<BlockHeader>,
    ) -> error::Result<()> {
        todo!();
    }

    async fn process_block_request(
        &mut self,
        peer_id: T::PeerId,
        request_id: T::RequestId,
        headers: Vec<BlockHeader>,
    ) -> error::Result<()> {
        todo!();
    }

    async fn process_header_response(
        &mut self,
        peer_id: T::PeerId,
        headers: Vec<BlockHeader>,
    ) -> error::Result<()> {
        todo!();
    }

    async fn process_block_response(
        &mut self,
        peer_id: T::PeerId,
        blocks: Vec<Block>,
    ) -> error::Result<()> {
        todo!();
    }

    /// Handle incoming block/header request/response
    async fn on_syncing_event(&mut self, event: net::SyncingMessage<T>) -> error::Result<()> {
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
                Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
            }
        }
    }

    /// Handle control-related sync event from P2P/SwarmManager
    async fn on_sync_event(&mut self, event: event::SyncControlEvent<T>) -> error::Result<()> {
        match event {
            event::SyncControlEvent::Connected(peer_id) => {
                log::debug!("create new entry for peer {:?}", peer_id);

                if let std::collections::hash_map::Entry::Vacant(e) = self.peers.entry(peer_id) {
                    e.insert(PeerSyncState {
                        peer_id,
                        state: PeerState::Idle,
                    });
                } else {
                    log::error!("peer {:?} already known by sync manager", peer_id);
                }
            }
            event::SyncControlEvent::Disconnected(peer_id) => {
                self.peers
                    .remove(&peer_id)
                    .ok_or_else(|| P2pError::Unknown("Peer does not exist".to_string()))
                    .map(|_| log::debug!("remove peer {:?}", peer_id))
                    .map_err(|_| log::error!("peer {:?} not known by sync manager", peer_id));
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
                    self.on_syncing_event(res?).await?;
                }
                res = self.rx_sync.recv().fuse() => {
                    self.on_sync_event(res.ok_or(P2pError::ChannelClosed)?).await?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        libp2p::Libp2pService, mock::MockService, ConnectivityEvent, ConnectivityService,
        SyncingService,
    };
    use common::chain::config;
    use libp2p::{multiaddr::Protocol, PeerId};
    use std::net::SocketAddr;

    async fn make_sync_manager<T>(
        addr: T::Address,
    ) -> (
        SyncManager<T>,
        T::ConnectivityHandle,
        mpsc::Sender<event::SyncControlEvent<T>>,
    )
    where
        T: NetworkService,
        T::ConnectivityHandle: ConnectivityService<T>,
        T::SyncingHandle: SyncingService<T>,
    {
        let (conn, _, sync) = T::start(
            addr,
            &[],
            &[],
            Arc::new(config::create_mainnet()),
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();

        let (tx_sync, rx_sync) = tokio::sync::mpsc::channel(16);
        let (tx_p2p, rx_p2p) = tokio::sync::mpsc::channel(16);

        let mut manager = subsystem::Manager::new("mintlayer");
        manager.install_signal_handlers();

        // Consensus subsystem
        // let cons = manager.add_subsystem(
        //     "consensus",
        //     consensus::make_consensus(
        //         config::create_mainnet(),
        //         blockchain_storage::Store::new_empty().unwrap(),
        //     )
        //     .unwrap(),
        // );

        // let cons = subsystem::Handle<ConsensusInterface>;

        todo!();
        // (
        //     SyncManager::<T>::new(sync, cons, rx_p2p, rx_sync),
        //     conn,
        //     tx_sync,
        // )
    }

    // handle peer connection event
    #[tokio::test]
    async fn test_peer_connected() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, mut tx_sync) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected(peer_id)).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);
    }

    // handle peer disconnection event
    #[tokio::test]
    async fn test_peer_disconnected() {
        let addr: SocketAddr = test_utils::make_address("[::1]:");
        let (mut mgr, _, mut tx_sync) = make_sync_manager::<MockService>(addr).await;

        // send Connected event to SyncManager
        let peer_id: SocketAddr = test_utils::make_address("[::1]:");

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Connected(peer_id)).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        // no peer with this id exist, nothing happens
        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Disconnected(addr)).await,
            Ok(())
        );
        assert_eq!(mgr.peers.len(), 1);

        assert_eq!(
            mgr.on_sync_event(event::SyncControlEvent::Disconnected(peer_id)).await,
            Ok(())
        );
        assert!(mgr.peers.is_empty());
    }

    // #[tokio::test]
    // async fn test_request_response() {
    //     let (mut mgr1, mut conn1, _, _) =
    //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    //     let (mut mgr2, mut conn2, _, _) =
    //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    //     let (conn1_res, conn2_res) =
    //         tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    //     let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    //     let conn1_id = match conn2_res {
    //         ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
    //         _ => panic!("invalid event received, expected incoming connection"),
    //     };

    //     let req_id = mgr1
    //         .handle
    //         .send_request(
    //             *conn2.peer_id(),
    //             Message {
    //                 magic: [1, 2, 3, 4],
    //                 msg: MessageType::Syncing(SyncingMessage::Request(
    //                     SyncingRequest::GetHeaders { locator: vec![] },
    //                 )),
    //             },
    //         )
    //         .await
    //         .unwrap();

    //     if let Ok(net::SyncingMessage::Request {
    //         peer_id,
    //         request_id,
    //         request,
    //     }) = mgr2.handle.poll_next().await
    //     {
    //         assert_eq!(
    //             request,
    //             Message {
    //                 magic: [1, 2, 3, 4],
    //                 msg: MessageType::Syncing(SyncingMessage::Request(
    //                     SyncingRequest::GetHeaders { locator: vec![] }
    //                 ))
    //             }
    //         );

    //         mgr2.handle
    //             .send_response(
    //                 request_id,
    //                 Message {
    //                     magic: [5, 6, 7, 8],
    //                     msg: MessageType::Syncing(SyncingMessage::Response(
    //                         SyncingResponse::Headers { headers: vec![] },
    //                     )),
    //                 },
    //             )
    //             .await
    //             .unwrap();
    //     } else {
    //         panic!("invalid data received");
    //     }

    //     if let Ok(net::SyncingMessage::Response {
    //         peer_id, response, ..
    //     }) = mgr1.handle.poll_next().await
    //     {
    //         assert_eq!(
    //             response,
    //             Message {
    //                 magic: [5, 6, 7, 8],
    //                 msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
    //                     headers: vec![]
    //                 },)),
    //             },
    //         );
    //     } else {
    //         panic!("invalid data received");
    //     }
    // }

    // // peer1 sends to requests to peer2 and peer2 responds to them out of order
    // #[tokio::test]
    // async fn test_multiple_requests_and_responses() {
    //     let (mut mgr1, mut conn1, _, _) =
    //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;
    //     let (mut mgr2, mut conn2, _, _) =
    //         make_sync_manager::<Libp2pService>(test_utils::make_address("/ip6/::1/tcp/")).await;

    //     let (conn1_res, conn2_res) =
    //         tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    //     let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    //     let conn1_id = match conn2_res {
    //         ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
    //         _ => panic!("invalid event received, expected incoming connection"),
    //     };

    //     let req_id1 = mgr1
    //         .handle
    //         .send_request(
    //             *conn2.peer_id(),
    //             Message {
    //                 magic: [1, 2, 3, 4],
    //                 msg: MessageType::Syncing(SyncingMessage::Request(
    //                     SyncingRequest::GetHeaders { locator: vec![] },
    //                 )),
    //             },
    //         )
    //         .await
    //         .unwrap();

    //     let req_id2 = mgr1
    //         .handle
    //         .send_request(
    //             *conn2.peer_id(),
    //             Message {
    //                 magic: [5, 6, 7, 8],
    //                 msg: MessageType::Syncing(SyncingMessage::Request(
    //                     SyncingRequest::GetHeaders { locator: vec![] },
    //                 )),
    //             },
    //         )
    //         .await
    //         .unwrap();

// <<<<<<< HEAD
//         assert_ne!(req_id1, req_id2);
//         let mut first_req_id = req_id1;
// ||||||| parent of aab58647 (p2p: Add P2pInterface)
//         assert_ne!(req_id1, req_id2);
// =======
//     //     assert_ne!(req_id1, req_id2);
// >>>>>>> aab58647 (p2p: Add P2pInterface)

//     //     let (recv_req1_id, request1) = if let Ok(net::SyncingMessage::Request {
//     //         peer_id: _,
//     //         request_id,
//     //         request,
//     //     }) = mgr2.handle.poll_next().await
//     //     {
//     //         (request_id, request)
//     //     } else {
//     //         panic!("invalid data received");
//     //     };

// <<<<<<< HEAD
//         let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
//             peer_id: _,
//             request_id,
//             request,
//         }) = mgr2.handle.poll_next().await
//         {
//             (request_id, request)
//         } else {
//             panic!("invalid data received");
//         };
// ||||||| parent of aab58647 (p2p: Add P2pInterface)
//         // TODO: force order?

//         let (recv_req2_id, request2) = if let Ok(net::SyncingMessage::Request {
//             peer_id: _,
//             request_id,
//             request,
//         }) = mgr2.handle.poll_next().await
//         {
//             (request_id, request)
//         } else {
//             panic!("invalid data received");
//         };
// =======
//     //     // TODO: force order?

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
// >>>>>>> aab58647 (p2p: Add P2pInterface)

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

// <<<<<<< HEAD
//         if let Ok(net::SyncingMessage::Response {
//             peer_id,
//             request_id,
//             response,
//         }) = mgr1.handle.poll_next().await
//         {
//             first_req_id = request_id;
//             assert!(request_id == req_id2 || request_id == req_id1);
//             assert_eq!(
//                 response,
//                 Message {
//                     magic: [5, 6, 7, 8],
//                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//                         headers: vec![]
//                     },)),
//                 },
//             );
//         } else {
//             panic!("invalid data received");
//         }
// ||||||| parent of aab58647 (p2p: Add P2pInterface)
//         if let Ok(net::SyncingMessage::Response {
//             peer_id,
//             request_id,
//             response,
//         }) = mgr1.handle.poll_next().await
//         {
//             assert_eq!(request_id, req_id2);
//             assert_eq!(
//                 response,
//                 Message {
//                     magic: [5, 6, 7, 8],
//                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//                         headers: vec![]
//                     },)),
//                 },
//             );
//         } else {
//             panic!("invalid data received");
//         }
// =======
//     //     if let Ok(net::SyncingMessage::Response {
//     //         peer_id,
//     //         request_id,
//     //         response,
//     //     }) = mgr1.handle.poll_next().await
//     //     {
//     //         assert_eq!(request_id, req_id2);
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
// >>>>>>> aab58647 (p2p: Add P2pInterface)

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

// <<<<<<< HEAD
//         if let Ok(net::SyncingMessage::Response {
//             peer_id,
//             request_id,
//             response,
//         }) = mgr1.handle.poll_next().await
//         {
//             if first_req_id == req_id1 {
//                 assert_eq!(request_id, req_id2);
//             } else {
//                 assert_eq!(request_id, req_id1);
//             }

//             assert_eq!(
//                 response,
//                 Message {
//                     magic: [1, 2, 3, 4],
//                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//                         headers: vec![]
//                     },)),
//                 },
//             );
//         } else {
//             panic!("invalid data received");
//         }
//     }
// ||||||| parent of aab58647 (p2p: Add P2pInterface)
//         if let Ok(net::SyncingMessage::Response {
//             peer_id,
//             request_id,
//             response,
//         }) = mgr1.handle.poll_next().await
//         {
//             assert_eq!(request_id, req_id1);
//             assert_eq!(
//                 response,
//                 Message {
//                     magic: [1, 2, 3, 4],
//                     msg: MessageType::Syncing(SyncingMessage::Response(SyncingResponse::Headers {
//                         headers: vec![]
//                     },)),
//                 },
//             );
//         } else {
//             panic!("invalid data received");
//         }
//     }
// =======
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
// >>>>>>> aab58647 (p2p: Add P2pInterface)
}
