// Copyright (c) 2022 RBB S.r.l
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

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use common::chain::{config::create_mainnet, ChainConfig};
use p2p_test_utils::start_chainstate;

use crate::{
    net::default_backend::{transport::TcpTransportSocket, types::PeerId},
    sync::{Announcement, BlockSyncManager, SyncControlEvent, SyncMessage, SyncingEvent},
    NetworkingService, P2pConfig, P2pError, PeerManagerEvent, Result, SyncingMessagingService,
};

// TODO: FIXME:
/*
   - connect/disconnect peer:
       - connect twice
       - disconnect non-existing?..

   - handle announcement:
       - valid header
       - invalid header (many cases)

   - handle messages:
       - header list request
       - block list request
       - header list response???
       - block response
*/

/// A networking service mock.
///
/// This mock should never be used directly and its only purpose is to be used as a generic
/// parameter in the sync manager tests.
#[derive(Debug)]
struct NetworkingServiceStub {}

#[async_trait]
impl NetworkingService for NetworkingServiceStub {
    type Transport = TcpTransportSocket;
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type PeerId = PeerId;
    type ConnectivityHandle = ();
    type SyncingMessagingHandle = SyncingMessagingHandleMock;

    async fn start(
        _: Self::Transport,
        _: Vec<Self::Address>,
        _: Arc<ChainConfig>,
        _: Arc<P2pConfig>,
    ) -> Result<(Self::ConnectivityHandle, Self::SyncingMessagingHandle)> {
        panic!("Mock service shouldn't be used directly");
    }
}

struct SyncingMessagingHandleMock {
    events_sender: UnboundedSender<SyncingEvent<NetworkingServiceStub>>,
    events_receiver: UnboundedReceiver<SyncingEvent<NetworkingServiceStub>>,
}

#[async_trait]
impl SyncingMessagingService<NetworkingServiceStub> for SyncingMessagingHandleMock {
    fn send_message(&mut self, peer: PeerId, message: SyncMessage) -> Result<()> {
        self.events_sender.send(SyncingEvent::Message { peer, message }).unwrap();
        Ok(())
    }

    fn make_announcement(&mut self, announcement: Announcement) -> Result<()> {
        self.events_sender
            .send(SyncingEvent::Announcement {
                peer: "0".parse().unwrap(),
                announcement,
            })
            .unwrap();
        Ok(())
    }

    async fn poll_next(&mut self) -> Result<SyncingEvent<NetworkingServiceStub>> {
        Ok(self.events_receiver.recv().await.unwrap())
    }
}

/// A wrapper over other ends of the sync manager channels.
///
/// Provides methods for manipulating and observing the sync manager state.
struct SyncManagerHandle {
    peer_event_sender: UnboundedSender<SyncControlEvent<NetworkingServiceStub>>,
    peer_manager_receiver: UnboundedReceiver<PeerManagerEvent<NetworkingServiceStub>>,
    sync_event_sender: UnboundedSender<SyncingEvent<NetworkingServiceStub>>,
    sync_event_receiver: UnboundedReceiver<SyncingEvent<NetworkingServiceStub>>,
    error_receiver: UnboundedReceiver<P2pError>,
}

impl SyncManagerHandle {
    fn connect_peer(&mut self, peer: PeerId) {
        self.peer_event_sender.send(SyncControlEvent::Connected(peer)).unwrap();
    }

    async fn message(&mut self) -> (PeerId, SyncMessage) {
        match self.sync_event_receiver.recv().await.unwrap() {
            SyncingEvent::Message { peer, message } => (peer, message),
            e => panic!("Unexpected event: {e:?}"),
        }
    }
}

/// Starts the sync manager event loop and returns a handle for manipulating and observing the
/// manager state.
async fn start_sync_manager() -> SyncManagerHandle {
    let chain_config = Arc::new(create_mainnet());
    let p2p_config = Arc::new(P2pConfig::default());
    let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
    let (peer_event_sender, peer_event_receiver) = mpsc::unbounded_channel();
    let (peer_manager_sender, peer_manager_receiver) = mpsc::unbounded_channel();

    let (messaging_sender, handle_receiver) = mpsc::unbounded_channel();
    let (handle_sender, messaging_receiver) = mpsc::unbounded_channel();
    let messaging_handle = SyncingMessagingHandleMock {
        events_sender: messaging_sender,
        events_receiver: messaging_receiver,
    };

    let mut sync = BlockSyncManager::new(
        chain_config,
        p2p_config,
        messaging_handle,
        chainstate,
        peer_event_receiver,
        peer_manager_sender,
    );

    let (error_sender, error_receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let e = sync.run().await.unwrap_err();
        error_sender.send(e).unwrap();
    });

    SyncManagerHandle {
        peer_event_sender,
        peer_manager_receiver,
        sync_event_sender: handle_sender,
        sync_event_receiver: handle_receiver,
        error_receiver,
    }
}

#[tokio::test]
async fn connect_peer() {
    let mut handle = start_sync_manager().await;

    let peer = PeerId::new();
    handle.connect_peer(peer);

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
}

// fn make_syncing_messaging_mock<N: NetworkingService>() -> (
//     SyncingMessagingServiceMock<N>,
//     SyncingMessagingServiceMockHandle<N>,
// ) {
//     let (service_sender, handle_receiver) = mpsc::unbounded_channel();
//     let (handle_sender, service_receiver) = mpsc::unbounded_channel();
//
//     let mock = SyncingMessagingServiceMock {
//         events_sender: service_sender,
//         events_receiver: service_receiver,
//     };
//     let handle = SyncingMessagingServiceMockHandle {
//         events_sender: handle_sender,
//         events_receiver: handle_receiver,
//     };
//     (mock, handle)
// }
//
// async fn FIXME<T, N>()
// where
//     T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
//     N: NetworkingService<SyncingMessagingHandle = SyncingMessagingServiceMock<N>> + 'static,
//     // N::ConnectivityHandle: ConnectivityService<N>,
//     N::SyncingMessagingHandle: SyncingMessagingService<N>,
// {
//     let chain_config = Arc::new(create_mainnet());
//     let p2p_config = Arc::new(P2pConfig::default());
//     let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
//     let (peer_event_sender, peer_event_receiver) = mpsc::unbounded_channel();
//     let (peer_manager_sender, peer_manager_receiver) = mpsc::unbounded_channel();
//     let (mock, mock_handle) = make_syncing_messaging_mock::<N>();
//
//     let sync = BlockSyncManager::<N>::new(
//         chain_config,
//         p2p_config,
//         mock,
//         chainstate,
//         peer_event_receiver,
//         peer_manager_sender,
//     );
// }
//
// #[tokio::test]
// async fn FIXME_tcp() {
//     //FIXME::<TestTransportTcp, PeerId, DefaultNetworkingService<TcpTransportSocket>>().await;
//     FIXME::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
//
//     // let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
//     // let (tx_peer_manager, rx_peer_manager) = mpsc::unbounded_channel();
//     //
//     // let chain_config = Arc::new(create_mainnet());
//     // let p2p_config = Arc::new(P2pConfig::default());
//     // // let (conn, sync) = T::start(
//     // //     transport,
//     // //     vec![addr],
//     // //     Arc::clone(&chain_config),
//     // //     Arc::clone(&p2p_config),
//     // // )
//     // // .await
//     // // .unwrap();
//     //
//     // let sync = BlockSyncManager::<T>::new(
//     //     chain_config,
//     //     p2p_config,
//     //     sync,
//     //     chainstate,
//     //     rx_p2p_sync,
//     //     tx_peer_manager,
//     // );
// }

/*
           tokio::select! {
               event = self.messaging_handle.poll_next() => match event? {
                   SyncingEvent::Message { peer, message } => {
                       let res = self.handle_message(peer, message).await;
                       self.handle_result(peer, res).await?;
                   },
                   SyncingEvent::Announcement{ peer, announcement } => {
                       self.handle_announcement(peer, announcement).await?;
                   }
               },
               event = self.peer_event_receiver.recv() => match event.ok_or(P2pError::ChannelClosed)? {
                   SyncControlEvent::Connected(peer_id) => self.register_peer(peer_id).await?,
                   SyncControlEvent::Disconnected(peer_id) => self.unregister_peer(peer_id),
               },
               block_id = new_tip_receiver.recv(), if !self.chainstate_handle.call(|c| c.is_initial_block_download()).await?? => {
                   // This error can only occur when chainstate drops an events subscriber.
                   let block_id = block_id.ok_or(P2pError::ChannelClosed)?;
                   self.handle_new_tip(block_id).await?;
               },
               (peer, block) = async { self.blocks_queue.pop_front().expect("The block queue is empty") }, if !self.blocks_queue.is_empty() => {
                   let res = self.send_block(peer, block).await;
                   self.handle_result(peer, res).await?;
               }
           }
*/
////////////////////////////
/*
mod block_response;
mod connection;
mod header_response;
mod request_response;

use std::sync::Arc;

use tokio::sync::mpsc;

use chainstate::{make_chainstate, ChainstateConfig, DefaultTransactionVerificationStrategy};

use crate::{
    config::{NodeType, P2pConfig},
    event::{PeerManagerEvent, SyncControlEvent},
    net::{default_backend::types::PeerId, ConnectivityService},
    sync::{peer_context::PeerContext, BlockSyncManager},
    NetworkingService, SyncingMessagingService,
};

async fn make_sync_manager<T>(
    transport: T::Transport,
    addr: T::Address,
) -> (
    BlockSyncManager<T>,
    T::ConnectivityHandle,
    mpsc::UnboundedSender<SyncControlEvent<T>>,
    mpsc::UnboundedReceiver<PeerManagerEvent<T>>,
)
where
    T: NetworkingService,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
    T::PeerId: 'static,
{
    let (tx_p2p_sync, rx_p2p_sync) = mpsc::unbounded_channel();
    let (tx_pm, rx_pm) = mpsc::unbounded_channel();
    let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let chainstate_config = ChainstateConfig::new();
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem(
        "chainstate",
        make_chainstate(
            chain_config,
            chainstate_config,
            storage,
            DefaultTransactionVerificationStrategy::new(),
            None,
            Default::default(),
        )
        .unwrap(),
    );
    tokio::spawn(async move { man.main().await });

    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: vec!["/ip6/::1/tcp/3031".to_owned()],
        added_nodes: Vec::new(),
        ban_threshold: 100.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        node_type: NodeType::Full.into(),
        allow_discover_private_ips: Default::default(),
        header_limit: Default::default(),
        max_locator_size: Default::default(),
        requested_blocks_limit: Default::default(),
    });
    let (conn, sync) = T::start(
        transport,
        vec![addr],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    (
        BlockSyncManager::<T>::new(chain_config, p2p_config, sync, handle, rx_p2p_sync, tx_pm),
        conn,
        tx_p2p_sync,
        rx_pm,
    )
}

async fn register_peer<T>(mgr: &mut BlockSyncManager<T>, peer_id: T::PeerId)
where
    T: NetworkingService,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    mgr.peers.insert(peer_id, PeerContext::new());
}

pub trait MakeTestPeerId {
    type PeerId;

    fn new() -> Self::PeerId;
}

impl MakeTestPeerId for PeerId {
    type PeerId = Self;

    fn new() -> Self::PeerId {
        PeerId::new()
    }
}
 */
