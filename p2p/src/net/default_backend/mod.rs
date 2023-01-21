// Copyright (c) 2021-2022 RBB S.r.l
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

pub mod backend;
pub mod constants;
pub mod peer;
pub mod request_manager;
pub mod transport;
pub mod types;

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use logging::log;
use serialization::Encode;

use crate::{
    config,
    error::{P2pError, PublishError},
    message::{self, PeerManagerRequest, PeerManagerResponse, SyncRequest, SyncResponse},
    net::{
        default_backend::{
            constants::ANNOUNCEMENT_MAX_SIZE,
            transport::{TransportListener, TransportSocket},
        },
        types::{ConnectivityEvent, PubSubTopic},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    types::{PeerId, RequestId},
};

use super::types::SyncingEvent;

#[derive(Debug)]
pub struct DefaultNetworkingService<T: TransportSocket>(PhantomData<T>);

#[derive(Debug)]
pub struct ConnectivityHandle<S: NetworkingService, T: TransportSocket> {
    /// The local addresses of a network service provider.
    local_addresses: Vec<S::Address>,

    /// TX channel for sending commands to default_backend backend
    cmd_tx: mpsc::Sender<types::Command<T>>,

    /// RX channel for receiving connectivity events from default_backend backend
    conn_rx: mpsc::Receiver<ConnectivityEvent<T::Address>>,

    _marker: PhantomData<fn() -> S>,
}

pub struct PubSubHandle<S, T>
where
    S: NetworkingService,
    T: TransportSocket,
{
    /// TX channel for sending commands to default_backend backend
    _cmd_tx: mpsc::Sender<types::Command<T>>,

    /// RX channel for receiving pubsub events from default_backend backend
    _pubsub_rx: mpsc::Receiver<types::PubSubEvent<T>>,

    _marker: PhantomData<fn() -> S>,
}

#[derive(Debug)]
pub struct SyncingMessagingHandle<S, T>
where
    S: NetworkingService,
    T: TransportSocket,
{
    /// TX channel for sending commands to default_backend backend
    cmd_tx: mpsc::Sender<types::Command<T>>,

    /// RX channel for receiving syncing events
    sync_rx: mpsc::Receiver<SyncingEvent>,
    _marker: PhantomData<fn() -> S>,
}

#[async_trait]
impl<T: TransportSocket> NetworkingService for DefaultNetworkingService<T> {
    type Transport = T;
    type Address = T::Address;
    type BannableAddress = T::BannableAddress;
    type ConnectivityHandle = ConnectivityHandle<Self, T>;
    type SyncingMessagingHandle = SyncingMessagingHandle<Self, T>;

    async fn start(
        transport: Self::Transport,
        bind_addresses: Vec<Self::Address>,
        chain_config: Arc<common::chain::ChainConfig>,
        p2p_config: Arc<config::P2pConfig>,
    ) -> crate::Result<(Self::ConnectivityHandle, Self::SyncingMessagingHandle)> {
        let (cmd_tx, cmd_rx) = mpsc::channel(16);
        let (conn_tx, conn_rx) = mpsc::channel(16);
        let (sync_tx, sync_rx) = mpsc::channel(16);
        let socket = transport.bind(bind_addresses).await?;
        let local_addresses = socket.local_addresses().expect("to have bind address available");

        tokio::spawn(async move {
            let mut backend = backend::Backend::<T>::new(
                transport,
                socket,
                chain_config,
                p2p_config,
                cmd_rx,
                conn_tx,
                sync_tx,
            );

            if let Err(err) = backend.run().await {
                log::error!("failed to run backend: {err}");
            }
        });

        Ok((
            Self::ConnectivityHandle {
                local_addresses,
                cmd_tx: cmd_tx.clone(),
                conn_rx,
                _marker: Default::default(),
            },
            Self::SyncingMessagingHandle {
                cmd_tx,
                sync_rx,
                _marker: Default::default(),
            },
        ))
    }
}

#[async_trait]
impl<S, T> ConnectivityService<S> for ConnectivityHandle<S, T>
where
    S: NetworkingService<Address = T::Address> + Send,
    T: TransportSocket,
{
    async fn connect(&mut self, address: S::Address) -> crate::Result<()> {
        log::debug!(
            "try to establish outbound connection, address {:?}",
            address
        );

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::Connect {
                address,
                response: tx,
            })
            .await?;

        rx.await?
    }

    async fn disconnect(&mut self, peer_id: PeerId) -> crate::Result<()> {
        log::debug!("close connection with remote, {peer_id}");

        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(types::Command::Disconnect {
                peer_id,
                response: tx,
            })
            .await?;

        rx.await?
    }

    async fn send_request(
        &mut self,
        peer_id: PeerId,
        request: PeerManagerRequest,
    ) -> crate::Result<RequestId> {
        let request_id = RequestId::new();

        self.cmd_tx
            .send(types::Command::SendRequest {
                peer_id,
                request_id,
                message: request.into(),
            })
            .await?;

        Ok(request_id)
    }

    async fn send_response(
        &mut self,
        request_id: RequestId,
        response: PeerManagerResponse,
    ) -> crate::Result<()> {
        self.cmd_tx
            .send(types::Command::SendResponse {
                request_id,
                message: response.into(),
            })
            .await?;
        Ok(())
    }

    async fn local_addresses(&self) -> crate::Result<Vec<S::Address>> {
        Ok(self.local_addresses.clone())
    }

    async fn poll_next(&mut self) -> crate::Result<ConnectivityEvent<S::Address>> {
        self.conn_rx.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

#[async_trait]
impl<S, T> SyncingMessagingService<S> for SyncingMessagingHandle<S, T>
where
    S: NetworkingService + Send,
    T: TransportSocket,
{
    async fn send_request(
        &mut self,
        peer_id: PeerId,
        request: SyncRequest,
    ) -> crate::Result<RequestId> {
        let request_id = RequestId::new();

        self.cmd_tx
            .send(types::Command::SendRequest {
                peer_id,
                request_id,
                message: request.into(),
            })
            .await?;

        Ok(request_id)
    }

    async fn send_response(
        &mut self,
        request_id: RequestId,
        response: SyncResponse,
    ) -> crate::Result<()> {
        self.cmd_tx
            .send(types::Command::SendResponse {
                request_id,
                message: response.into(),
            })
            .await?;
        Ok(())
    }

    async fn make_announcement(
        &mut self,
        announcement: message::Announcement,
    ) -> crate::Result<()> {
        let message = announcement.encode();
        if message.len() > ANNOUNCEMENT_MAX_SIZE {
            return Err(P2pError::PublishError(PublishError::MessageTooLarge(
                message.len(),
                ANNOUNCEMENT_MAX_SIZE,
            )));
        }

        let topic = match &announcement {
            message::Announcement::Block(_) => PubSubTopic::Blocks,
        };

        self.cmd_tx.send(types::Command::AnnounceData { topic, message }).await?;

        Ok(())
    }

    async fn poll_next(&mut self) -> crate::Result<SyncingEvent> {
        self.sync_rx.recv().await.ok_or(P2pError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::{transport::NoiseTcpTransport, *};
    use crate::error::DialError;
    use crate::testing_utils::{TestTransportChannel, TestTransportMaker, TestTransportTcp};
    use crate::{
        net::default_backend::transport::{MpscChannelTransport, TcpTransportSocket},
        testing_utils::TestTransportNoise,
    };
    use common::primitives::semver::SemVer;
    use std::fmt::Debug;

    async fn connect_to_remote<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket + Debug,
    {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let (conn2, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let addr = conn2.local_addresses().await.unwrap();
        assert_eq!(conn1.connect(addr[0].clone()).await, Ok(()));

        if let Ok(ConnectivityEvent::OutboundAccepted {
            address,
            peer_info,
            receiver_address: _,
        }) = conn1.poll_next().await
        {
            assert_eq!(address, conn2.local_addresses().await.unwrap()[0]);
            assert_eq!(&peer_info.network, config.magic_bytes());
            assert_eq!(peer_info.version, SemVer::new(0, 1, 0));
            assert_eq!(peer_info.agent, None);
            assert_eq!(
                peer_info.subscriptions,
                [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect()
            );
        } else {
            panic!("invalid event received");
        }
    }

    #[tokio::test]
    async fn connect_to_remote_tcp() {
        connect_to_remote::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn connect_to_remote_channels() {
        connect_to_remote::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tokio::test]
    async fn connect_to_remote_noise() {
        connect_to_remote::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn accept_incoming<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let (mut conn2, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let bind_address = conn2.local_addresses().await.unwrap();
        let (_res1, res2) = tokio::join!(conn1.connect(bind_address[0].clone()), conn2.poll_next());
        match res2.unwrap() {
            ConnectivityEvent::InboundAccepted {
                address: _,
                peer_info,
                receiver_address: _,
            } => {
                assert_eq!(peer_info.network, *config.magic_bytes());
                assert_eq!(
                    peer_info.version,
                    common::primitives::semver::SemVer::new(0, 1, 0),
                );
                assert_eq!(peer_info.agent, None);
            }
            _ => panic!("invalid event received, expected incoming connection"),
        }
    }

    #[tokio::test]
    async fn accept_incoming_tcp() {
        accept_incoming::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn accept_incoming_channels() {
        accept_incoming::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tokio::test]
    async fn accept_incoming_noise() {
        accept_incoming::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn disconnect<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket,
    {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();
        let (mut conn2, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            config,
            p2p_config,
        )
        .await
        .unwrap();

        let (_res1, res2) = tokio::join!(
            conn1.connect(conn2.local_addresses().await.unwrap()[0].clone()),
            conn2.poll_next()
        );

        match res2.unwrap() {
            ConnectivityEvent::InboundAccepted {
                address: _,
                peer_info,
                receiver_address: _,
            } => {
                assert_eq!(conn2.disconnect(peer_info.peer_id).await, Ok(()));
            }
            _ => panic!("invalid event received, expected incoming connection"),
        }
    }

    #[tokio::test]
    async fn disconnect_tcp() {
        disconnect::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn disconnect_channels() {
        disconnect::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tokio::test]
    async fn disconnect_noise() {
        disconnect::<TestTransportNoise, NoiseTcpTransport>().await;
    }

    async fn self_connect<A, T>()
    where
        A: TestTransportMaker<Transport = T, Address = T::Address>,
        T: TransportSocket + Debug,
    {
        let config = Arc::new(common::chain::config::create_mainnet());
        let p2p_config: Arc<config::P2pConfig> = Arc::new(Default::default());

        let (mut conn1, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        let (conn2, _) = DefaultNetworkingService::<T>::start(
            A::make_transport(),
            vec![A::make_address()],
            Arc::clone(&config),
            Arc::clone(&p2p_config),
        )
        .await
        .unwrap();

        // Try connect to self
        let addr = conn1.local_addresses().await.unwrap();
        assert_eq!(conn1.connect(addr[0].clone()).await, Ok(()));

        // ConnectionError should be reported
        if let Ok(ConnectivityEvent::ConnectionError { address, error }) = conn1.poll_next().await {
            assert_eq!(address, conn1.local_addresses().await.unwrap()[0]);
            assert_eq!(error, P2pError::DialError(DialError::AttemptToDialSelf));
        } else {
            panic!("invalid event received");
        }

        // Two ConnectionClosed will be also reported
        if let Ok(ConnectivityEvent::ConnectionClosed { peer_id: _ }) = conn1.poll_next().await {
        } else {
            panic!("invalid event received");
        }
        if let Ok(ConnectivityEvent::ConnectionClosed { peer_id: _ }) = conn1.poll_next().await {
        } else {
            panic!("invalid event received");
        }

        // Check that we can still connect normally after
        let addr = conn2.local_addresses().await.unwrap();
        assert_eq!(conn1.connect(addr[0].clone()).await, Ok(()));
        if let Ok(ConnectivityEvent::OutboundAccepted {
            address,
            peer_info,
            receiver_address: _,
        }) = conn1.poll_next().await
        {
            assert_eq!(address, conn2.local_addresses().await.unwrap()[0]);
            assert_eq!(&peer_info.network, config.magic_bytes());
            assert_eq!(peer_info.version, SemVer::new(0, 1, 0));
            assert_eq!(peer_info.agent, None);
            assert_eq!(
                peer_info.subscriptions,
                [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect()
            );
        } else {
            panic!("invalid event received");
        }
    }

    #[tokio::test]
    async fn self_connect_tcp() {
        self_connect::<TestTransportTcp, TcpTransportSocket>().await;
    }

    #[tokio::test]
    async fn self_connect_channels() {
        self_connect::<TestTransportChannel, MpscChannelTransport>().await;
    }

    #[tokio::test]
    async fn self_connect_noise() {
        self_connect::<TestTransportNoise, NoiseTcpTransport>().await;
    }
}
