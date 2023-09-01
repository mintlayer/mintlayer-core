// Copyright (c) 2021-2023 RBB S.r.l
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

use super::{transport::NoiseTcpTransport, *};
use crate::{
    config::NodeType,
    error::DialError,
    net::default_backend::transport::{MpscChannelTransport, TcpTransportSocket},
    protocol::SupportedProtocolVersion,
    testing_utils::{
        test_p2p_config, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp,
    },
};
use std::fmt::Debug;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

async fn connect_to_remote_impl<A, T>(
    remote_protocol_version: ProtocolVersion,
    expected_common_protocol_version: ProtocolVersion,
) where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut local_srv, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (remote_srv, _, _, _) = DefaultNetworkingService::<T>::start_with_version(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
        remote_protocol_version,
    )
    .await
    .unwrap();

    let addr = remote_srv.local_addresses();
    local_srv.connect(addr[0], None).unwrap();

    if let Ok(ConnectivityEvent::OutboundAccepted {
        address,
        peer_info,
        receiver_address: _,
    }) = local_srv.poll_next().await
    {
        assert_eq!(address, remote_srv.local_addresses()[0]);
        let protocol_version: ProtocolVersion = peer_info.protocol_version.into();
        assert_eq!(protocol_version, expected_common_protocol_version);
        assert_eq!(peer_info.network, *config.magic_bytes());
        assert_eq!(peer_info.software_version, *config.software_version());
        assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        assert_eq!(peer_info.common_services, NodeType::Full.into());
    } else {
        panic!("invalid event received");
    }
}

async fn connect_to_remote<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    connect_to_remote_impl::<A, T>(
        SupportedProtocolVersion::V1.into(),
        SupportedProtocolVersion::V1.into(),
    )
    .await;

    // Note: V2 is not finalized yet, so it should not be selected.
    connect_to_remote_impl::<A, T>(
        SupportedProtocolVersion::V2.into(),
        SupportedProtocolVersion::V1.into(),
    )
    .await;
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

async fn accept_incoming_impl<A, T>(
    remote_protocol_version: ProtocolVersion,
    expected_common_protocol_version: ProtocolVersion,
) where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut local_srv, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut remote_srv, _, _, _) = DefaultNetworkingService::<T>::start_with_version(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
        remote_protocol_version,
    )
    .await
    .unwrap();

    let bind_address = local_srv.local_addresses();
    remote_srv.connect(bind_address[0], None).unwrap();
    let res = local_srv.poll_next().await;
    match res.unwrap() {
        ConnectivityEvent::InboundAccepted {
            address: _,
            peer_info,
            receiver_address: _,
        } => {
            let protocol_version: ProtocolVersion = peer_info.protocol_version.into();
            assert_eq!(protocol_version, expected_common_protocol_version);
            assert_eq!(peer_info.network, *config.magic_bytes());
            assert_eq!(peer_info.software_version, *config.software_version());
            assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        }
        _ => panic!("invalid event received, expected incoming connection"),
    }
}

async fn accept_incoming<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    accept_incoming_impl::<A, T>(
        SupportedProtocolVersion::V1.into(),
        SupportedProtocolVersion::V1.into(),
    )
    .await;

    // Note: V2 is not finalized yet, so it should not be selected.
    accept_incoming_impl::<A, T>(
        SupportedProtocolVersion::V2.into(),
        SupportedProtocolVersion::V1.into(),
    )
    .await;
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
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn1, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn2, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        config,
        p2p_config,
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    conn1.connect(conn2.local_addresses()[0], None).unwrap();
    let res2 = conn2.poll_next().await;

    match res2.unwrap() {
        ConnectivityEvent::InboundAccepted {
            address: _,
            peer_info,
            receiver_address: _,
        } => {
            conn2.disconnect(peer_info.peer_id).unwrap();
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
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn1, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (conn2, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    // Try connect to self
    let addr = conn1.local_addresses();
    conn1.connect(addr[0], None).unwrap();

    // ConnectionError should be reported
    if let Ok(ConnectivityEvent::ConnectionError { address, error }) = conn1.poll_next().await {
        assert_eq!(address, conn1.local_addresses()[0]);
        assert_eq!(error, P2pError::DialError(DialError::AttemptToDialSelf));
    } else {
        panic!("invalid event received");
    }

    // Check that we can still connect normally after
    let addr = conn2.local_addresses();
    conn1.connect(addr[0], None).unwrap();
    if let Ok(ConnectivityEvent::OutboundAccepted {
        address,
        peer_info,
        receiver_address: _,
    }) = conn1.poll_next().await
    {
        assert_eq!(address, conn2.local_addresses()[0]);
        assert_eq!(peer_info.protocol_version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(peer_info.network, *config.magic_bytes());
        assert_eq!(peer_info.software_version, *config.software_version());
        assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        assert_eq!(peer_info.common_services, NodeType::Full.into());
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

async fn invalid_outbound_peer_connect<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    let time_getter = TimeGetter::default();
    let transport = A::make_transport();
    let mut listener = transport.bind(vec![A::make_address()]).await.unwrap();
    let addr = listener.local_addresses().unwrap();
    tokio::spawn(async move {
        let (mut socket, _address) = listener.accept().await.unwrap();
        let _ = socket.write_all(b"invalid message").await;
    });

    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn, _, _, _) = DefaultNetworkingService::<T>::start(
        A::make_transport(),
        vec![],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    // Try to connect to some broken peer
    conn.connect(addr[0], None).unwrap();
    // `ConnectionError` should be reported
    let event = timeout(Duration::from_secs(60), conn.poll_next()).await.unwrap().unwrap();

    match event {
        ConnectivityEvent::ConnectionError { address, error: _ } => {
            assert_eq!(address, addr[0]);
        }
        event => panic!("invalid event received: {event:?}"),
    }
}

#[tokio::test]
async fn invalid_outbound_peer_connect_tcp() {
    invalid_outbound_peer_connect::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn invalid_outbound_peer_connect_channels() {
    invalid_outbound_peer_connect::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn invalid_outbound_peer_connect_noise() {
    invalid_outbound_peer_connect::<TestTransportNoise, NoiseTcpTransport>().await;
}

// This test checks common protocol version selection when the nodes are explicitly told
// which version numbers to announce to each other. It doest't use CURRENT_PROTOCOL_VERSION
// in any way and therefore doesn't check which version will be selected in a real-world
// scenario (this is checked by connect_to_remote/accept_incoming tests above).
async fn general_protocol_version_selection_impl<A, T>(
    protocol_version1: ProtocolVersion,
    protocol_version2: ProtocolVersion,
    expected_common_protocol_version: ProtocolVersion,
) where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut srv1, _, _, _) = DefaultNetworkingService::<T>::start_with_version(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
        protocol_version1,
    )
    .await
    .unwrap();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut srv2, _, _, _) = DefaultNetworkingService::<T>::start_with_version(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
        protocol_version2,
    )
    .await
    .unwrap();

    let addr = srv2.local_addresses();
    srv1.connect(addr[0], None).unwrap();

    let res1 = srv1.poll_next().await;
    match res1.unwrap() {
        ConnectivityEvent::OutboundAccepted {
            address,
            peer_info,
            receiver_address: _,
        } => {
            assert_eq!(address, srv2.local_addresses()[0]);
            let protocol_version: ProtocolVersion = peer_info.protocol_version.into();
            assert_eq!(protocol_version, expected_common_protocol_version);
            assert_eq!(peer_info.network, *config.magic_bytes());
            assert_eq!(peer_info.software_version, *config.software_version());
            assert_eq!(peer_info.user_agent, p2p_config.user_agent);
            assert_eq!(peer_info.common_services, NodeType::Full.into());
        }
        _ => panic!("invalid event received, expected outgoing connection"),
    }

    let res2 = srv2.poll_next().await;
    match res2.unwrap() {
        ConnectivityEvent::InboundAccepted {
            address: _,
            peer_info,
            receiver_address: _,
        } => {
            let protocol_version: ProtocolVersion = peer_info.protocol_version.into();
            assert_eq!(protocol_version, expected_common_protocol_version);
            assert_eq!(peer_info.network, *config.magic_bytes());
            assert_eq!(peer_info.software_version, *config.software_version());
            assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        }
        _ => panic!("invalid event received, expected incoming connection"),
    }
}

async fn general_protocol_version_selection<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    general_protocol_version_selection_impl::<A, T>(
        SupportedProtocolVersion::V1.into(),
        SupportedProtocolVersion::V2.into(),
        SupportedProtocolVersion::V1.into(),
    )
    .await;
    general_protocol_version_selection_impl::<A, T>(
        SupportedProtocolVersion::V2.into(),
        SupportedProtocolVersion::V1.into(),
        SupportedProtocolVersion::V1.into(),
    )
    .await;
    general_protocol_version_selection_impl::<A, T>(
        SupportedProtocolVersion::V2.into(),
        SupportedProtocolVersion::V2.into(),
        SupportedProtocolVersion::V2.into(),
    )
    .await;
}

#[tokio::test]
async fn general_protocol_version_selection_tcp() {
    general_protocol_version_selection::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tokio::test]
async fn general_protocol_version_selection_channels() {
    general_protocol_version_selection::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tokio::test]
async fn general_protocol_version_selection_noise() {
    general_protocol_version_selection::<TestTransportNoise, NoiseTcpTransport>().await;
}
