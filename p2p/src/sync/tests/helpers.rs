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
    time::Duration,
};

use async_trait::async_trait;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    time,
};

use chainstate::chainstate_interface::ChainstateInterface;
use common::chain::{config::create_mainnet, ChainConfig};
use p2p_test_utils::start_chainstate;

use crate::{
    net::default_backend::{transport::TcpTransportSocket, types::PeerId},
    sync::{Announcement, BlockSyncManager, SyncControlEvent, SyncMessage, SyncingEvent},
    NetworkingService, P2pConfig, P2pError, PeerManagerEvent, Result, SyncingMessagingService,
};

/// A timeout for blocking calls.
const TIMEOUT: Duration = Duration::from_secs(5);

/// A wrapper over other ends of the sync manager channels.
///
/// Provides methods for manipulating and observing the sync manager state.
pub struct SyncManagerHandle {
    peer_event_sender: UnboundedSender<SyncControlEvent<NetworkingServiceStub>>,
    peer_manager_receiver: UnboundedReceiver<PeerManagerEvent<NetworkingServiceStub>>,
    sync_event_sender: UnboundedSender<SyncingEvent<NetworkingServiceStub>>,
    sync_event_receiver: UnboundedReceiver<SyncingEvent<NetworkingServiceStub>>,
    error_receiver: UnboundedReceiver<P2pError>,
}

impl SyncManagerHandle {
    /// Starts the sync manager event loop and returns a handle for manipulating and observing the
    /// manager state.
    pub async fn start() -> Self {
        let chain_config = Arc::new(create_mainnet());
        Self::with_config(chain_config).await
    }

    pub async fn with_config(chain_config: Arc<ChainConfig>) -> Self {
        let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
        Self::with_chainstate_and_config(chain_config, chainstate).await
    }

    pub async fn with_chainstate_and_config(
        chain_config: Arc<ChainConfig>,
        chainstate: subsystem::Handle<Box<dyn ChainstateInterface>>,
    ) -> Self {
        let p2p_config = Arc::new(P2pConfig::default());

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

        Self {
            peer_event_sender,
            peer_manager_receiver,
            sync_event_sender: handle_sender,
            sync_event_receiver: handle_receiver,
            error_receiver,
        }
    }

    /// Sends the `SyncControlEvent::Connected` event without checking outgoing messages.
    pub fn try_connect_peer(&mut self, peer: PeerId) {
        self.peer_event_sender.send(SyncControlEvent::Connected(peer)).unwrap();
    }

    /// Connects a peer and checks that the header list request is sent to that peer.
    pub async fn connect_peer(&mut self, peer: PeerId) {
        self.try_connect_peer(peer);

        let (sent_to, message) = self.message().await;
        assert_eq!(peer, sent_to);
        assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    }

    /// Sends the `SyncControlEvent::Disconnected` event.
    pub fn disconnect_peer(&mut self, peer: PeerId) {
        self.peer_event_sender.send(SyncControlEvent::Disconnected(peer)).unwrap();
    }

    pub fn send_message(&mut self, peer: PeerId, message: SyncMessage) {
        self.sync_event_sender.send(SyncingEvent::Message { peer, message }).unwrap();
    }

    /// Sends an announcement to the sync manager.
    pub fn make_announcement(&mut self, peer: PeerId, announcement: Announcement) {
        self.sync_event_sender
            .send(SyncingEvent::Announcement { peer, announcement })
            .unwrap();
    }

    /// Receives a message from the sync manager.
    pub async fn message(&mut self) -> (PeerId, SyncMessage) {
        match self.event().await {
            SyncingEvent::Message { peer, message } => (peer, message),
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    /// Receives an announcement from the sync manager.
    pub async fn announcement(&mut self) -> (PeerId, Announcement) {
        match self.event().await {
            SyncingEvent::Announcement { peer, announcement } => (peer, announcement),
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    /// Receives an error from the sync manager.
    ///
    /// Only fatal errors can be checked using this function. Non-fatal errors typically result in
    /// increasing the ban score of a peer.
    pub async fn error(&mut self) -> P2pError {
        time::timeout(TIMEOUT, self.error_receiver.recv())
            .await
            .expect("Failed to receive error in time")
            .unwrap()
    }

    /// Receives the `AdjustPeerScore` event from the peer manager.
    pub async fn adjust_peer_score_event(&mut self) -> (PeerId, u32) {
        match self.peer_manager_receiver.recv().await.unwrap() {
            PeerManagerEvent::AdjustPeerScore(peer, score, _) => (peer, score),
            e => panic!("Unexpected peer manager event: {e:?}"),
        }
    }

    async fn event(&mut self) -> SyncingEvent<NetworkingServiceStub> {
        time::timeout(TIMEOUT, self.sync_event_receiver.recv())
            .await
            .expect("Failed to receive event in time")
            .unwrap()
    }
}

/// A networking service stub.
///
/// This type should never be used directly and its only purpose is to be used as a generic
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
        panic!("Stub service shouldn't be used directly");
    }
}

/// A mock implementation of the `SyncingMessagingService` trait.
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
        Ok(time::timeout(TIMEOUT, self.events_receiver.recv())
            .await
            .expect("Failed to receive event in time")
            .unwrap())
    }
}
