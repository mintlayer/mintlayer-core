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
    net::default_backend::transport::TcpTransportSocket,
    sync::{Announcement, BlockSyncManager, SyncControlEvent, SyncMessage, SyncingEvent},
    types::peer_id::PeerId,
    NetworkingService, P2pConfig, P2pError, PeerManagerEvent, Result, SyncingMessagingService,
};

/// A timeout for blocking calls.
const LONG_TIMEOUT: Duration = Duration::from_secs(5);
/// A short timeout for events that shouldn't occur.
const SHORT_TIMEOUT: Duration = Duration::from_millis(500);

/// A wrapper over other ends of the sync manager channels.
///
/// Provides methods for manipulating and observing the sync manager state.
pub struct SyncManagerHandle {
    peer_event_sender: UnboundedSender<SyncControlEvent>,
    peer_manager_receiver: UnboundedReceiver<PeerManagerEvent<NetworkingServiceStub>>,
    sync_event_sender: UnboundedSender<SyncingEvent>,
    sync_event_receiver: UnboundedReceiver<SyncingEvent>,
    error_receiver: UnboundedReceiver<P2pError>,
}

impl SyncManagerHandle {
    /// Starts the sync manager event loop and returns a handle for manipulating and observing the
    /// manager state.
    pub async fn start() -> Self {
        Self::builder().build().await
    }

    pub fn builder() -> SyncManagerHandleBuilder {
        SyncManagerHandleBuilder::new()
    }

    pub async fn start_with_params(
        chain_config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        chainstate: subsystem::Handle<Box<dyn ChainstateInterface>>,
    ) -> Self {
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
            .send(SyncingEvent::Announcement {
                peer,
                announcement: Box::new(announcement),
            })
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
    pub async fn announcement(&mut self) -> Announcement {
        match self.event().await {
            SyncingEvent::Announcement {
                peer: _,
                announcement,
            } => *announcement,
            e => panic!("Unexpected event: {e:?}"),
        }
    }

    /// Receives an error from the sync manager.
    ///
    /// Only fatal errors can be checked using this function. Non-fatal errors typically result in
    /// increasing the ban score of a peer.
    pub async fn error(&mut self) -> P2pError {
        time::timeout(LONG_TIMEOUT, self.error_receiver.recv())
            .await
            .expect("Failed to receive error in time")
            .unwrap()
    }

    /// Panics if the sync manager returns an error.
    pub async fn assert_no_error(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.error_receiver.recv()).await.unwrap_err();
    }

    /// Receives the `AdjustPeerScore` event from the peer manager.
    pub async fn adjust_peer_score_event(&mut self) -> (PeerId, u32) {
        match self.peer_manager_receiver.recv().await.unwrap() {
            PeerManagerEvent::AdjustPeerScore(peer, score, sender) => {
                sender.send(Ok(()));
                (peer, score)
            }
            e => panic!("Unexpected peer manager event: {e:?}"),
        }
    }

    /// Panics if there is an event from the peer manager.
    pub async fn assert_no_peer_manager_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.peer_manager_receiver.recv())
            .await
            .unwrap_err();
    }

    /// Panics if the sync manager sends an event (message or announcement).
    pub async fn assert_no_event(&mut self) {
        time::timeout(SHORT_TIMEOUT, self.sync_event_receiver.recv()).await.unwrap_err();
    }

    async fn event(&mut self) -> SyncingEvent {
        time::timeout(LONG_TIMEOUT, self.sync_event_receiver.recv())
            .await
            .expect("Failed to receive event in time")
            .unwrap()
    }
}

pub struct SyncManagerHandleBuilder {
    chain_config: Arc<ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    chainstate: Option<subsystem::Handle<Box<dyn ChainstateInterface>>>,
}

impl SyncManagerHandleBuilder {
    pub fn new() -> Self {
        Self {
            chain_config: Arc::new(create_mainnet()),
            p2p_config: Arc::new(P2pConfig::default()),
            chainstate: None,
        }
    }

    pub fn with_chain_config(mut self, chain_config: Arc<ChainConfig>) -> Self {
        self.chain_config = chain_config;
        self
    }

    pub fn with_chainstate(
        mut self,
        chainstate: subsystem::Handle<Box<dyn ChainstateInterface>>,
    ) -> Self {
        self.chainstate = Some(chainstate);
        self
    }

    pub fn with_p2p_config(mut self, p2p_config: Arc<P2pConfig>) -> Self {
        self.p2p_config = p2p_config;
        self
    }

    pub async fn build(self) -> SyncManagerHandle {
        let chainstate = match self.chainstate {
            Some(chainstate) => chainstate,
            None => start_chainstate(Arc::clone(&self.chain_config)).await,
        };

        SyncManagerHandle::start_with_params(self.chain_config, self.p2p_config, chainstate).await
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
    events_sender: UnboundedSender<SyncingEvent>,
    events_receiver: UnboundedReceiver<SyncingEvent>,
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
                announcement: Box::new(announcement),
            })
            .unwrap();
        Ok(())
    }

    async fn poll_next(&mut self) -> Result<SyncingEvent> {
        Ok(time::timeout(LONG_TIMEOUT, self.events_receiver.recv())
            .await
            .expect("Failed to receive event in time")
            .unwrap())
    }
}
