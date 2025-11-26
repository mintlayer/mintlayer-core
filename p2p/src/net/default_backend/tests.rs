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

use std::{fmt::Debug, sync::Arc};

use enum_iterator::all;
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
};

use chainstate::ban_score::BanScore;
use common::time_getter::TimeGetter;
use logging::log;
use networking::{
    test_helpers::{
        TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
    },
    transport::{
        MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket, TransportListener,
        TransportSocket,
    },
};
use p2p_test_utils::run_with_timeout;
use test_utils::assert_matches_return_val;
use utils::atomics::SeqCstAtomicBool;

use crate::{
    config::NodeType,
    error::{DialError, P2pError},
    net::{
        default_backend::default_networking_service::get_preferred_protocol_version_for_tests,
        types::ConnectivityEvent, ConnectivityService, NetworkingService,
    },
    protocol::{ProtocolVersion, SupportedProtocolVersion},
    test_helpers::test_p2p_config,
};

use super::DefaultNetworkingService;

// The current "preferred" version.
const CURRENT_PROTOCOL_VERSION: ProtocolVersion =
    get_preferred_protocol_version_for_tests().into_raw_version();
// The next version after the current one.
const NEXT_PROTOCOL_VERSION: ProtocolVersion =
    ProtocolVersion::new(CURRENT_PROTOCOL_VERSION.inner() + 1);

async fn connect_to_remote_impl<A, T>(
    remote_protocol_version: ProtocolVersion,
    expected_common_protocol_version: ProtocolVersion,
) where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut local_srv, _, _, _) = DefaultNetworkingService::<T>::start(
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
        peer_address,
        bind_address: _,
        peer_info,
        node_address_as_seen_by_peer: _,
    }) = local_srv.poll_next().await
    {
        assert_eq!(peer_address, remote_srv.local_addresses()[0]);
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
    connect_to_remote_impl::<A, T>(CURRENT_PROTOCOL_VERSION, CURRENT_PROTOCOL_VERSION).await;

    connect_to_remote_impl::<A, T>(NEXT_PROTOCOL_VERSION, CURRENT_PROTOCOL_VERSION).await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_to_remote_tcp() {
    run_with_timeout(connect_to_remote::<TestTransportTcp, TcpTransportSocket>()).await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_to_remote_channels() {
    run_with_timeout(connect_to_remote::<
        TestTransportChannel,
        MpscChannelTransport,
    >())
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_to_remote_noise() {
    run_with_timeout(connect_to_remote::<TestTransportNoise, NoiseTcpTransport>()).await;
}

async fn accept_incoming_impl<A, T>(
    remote_protocol_version: ProtocolVersion,
    expected_common_protocol_version: ProtocolVersion,
) where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut local_srv, _, _, _) = DefaultNetworkingService::<T>::start(
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
            peer_address: _,
            bind_address: _,
            peer_info,
            node_address_as_seen_by_peer: _,
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
    accept_incoming_impl::<A, T>(CURRENT_PROTOCOL_VERSION, CURRENT_PROTOCOL_VERSION).await;

    accept_incoming_impl::<A, T>(NEXT_PROTOCOL_VERSION, CURRENT_PROTOCOL_VERSION).await;
}

#[tracing::instrument]
#[tokio::test]
async fn accept_incoming_tcp() {
    run_with_timeout(accept_incoming::<TestTransportTcp, TcpTransportSocket>()).await;
}

#[tracing::instrument]
#[tokio::test]
async fn accept_incoming_channels() {
    run_with_timeout(accept_incoming::<TestTransportChannel, MpscChannelTransport>()).await;
}

#[tracing::instrument]
#[tokio::test]
async fn accept_incoming_noise() {
    run_with_timeout(accept_incoming::<TestTransportNoise, NoiseTcpTransport>()).await;
}

async fn disconnect<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn1, _, _, _) = DefaultNetworkingService::<T>::start(
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
            peer_address: _,
            bind_address: _,
            peer_info,
            node_address_as_seen_by_peer: _,
        } => {
            conn2.disconnect(peer_info.peer_id, None).unwrap();
        }
        _ => panic!("invalid event received, expected incoming connection"),
    }
}

#[tracing::instrument]
#[tokio::test]
async fn disconnect_tcp() {
    run_with_timeout(disconnect::<TestTransportTcp, TcpTransportSocket>()).await;
}

#[tracing::instrument]
#[tokio::test]
async fn disconnect_channels() {
    run_with_timeout(disconnect::<TestTransportChannel, MpscChannelTransport>()).await;
}

#[tracing::instrument]
#[tokio::test]
async fn disconnect_noise() {
    run_with_timeout(disconnect::<TestTransportNoise, NoiseTcpTransport>()).await;
}

async fn self_connect<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket + Debug,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn1, _, _, _) = DefaultNetworkingService::<T>::start(
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
    let addr = conn1.local_addresses()[0];
    // Repeat this several times (5 seems to be enough to reproduce the race condition described
    // below *almost* on every test run).
    for _ in 0..5 {
        conn1.connect(addr, None).unwrap();

        // ConnectionError should be reported
        let poll_result = conn1.poll_next().await;
        if let Ok(ConnectivityEvent::ConnectionError {
            peer_address,
            error,
        }) = poll_result
        {
            assert_eq!(peer_address, addr);
            assert_eq!(error, P2pError::DialError(DialError::AttemptToDialSelf));
        } else {
            panic!("Invalid event received: {poll_result:?}");
        }
    }

    // Check that we can still connect normally after
    let addr = conn2.local_addresses()[0];
    conn1.connect(addr, None).unwrap();
    let poll_result = conn1.poll_next().await;
    if let Ok(ConnectivityEvent::OutboundAccepted {
        peer_address,
        bind_address: _,
        peer_info,
        node_address_as_seen_by_peer: _,
    }) = poll_result
    {
        assert_eq!(peer_address, addr);
        assert_eq!(
            peer_info.protocol_version,
            get_preferred_protocol_version_for_tests()
        );
        assert_eq!(peer_info.network, *config.magic_bytes());
        assert_eq!(peer_info.software_version, *config.software_version());
        assert_eq!(peer_info.user_agent, p2p_config.user_agent);
        assert_eq!(peer_info.common_services, NodeType::Full.into());
    } else {
        panic!("Invalid event received: {poll_result:?}");
    }
}

// Note: it's important for the "self_connect" tests to be multi-threaded to be able to detect
// all possible problems of the implementation (specifically, we had a race condition between
// sending a `PeerEvent` to backend and sending `HelloAck` to the peer, which could break
// self-connection detection but which couldn't be caught by the single-threaded version of
// these tests).
#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_connect_tcp() {
    run_with_timeout(self_connect::<TestTransportTcp, TcpTransportSocket>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_connect_channels() {
    run_with_timeout(self_connect::<TestTransportChannel, MpscChannelTransport>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn self_connect_noise() {
    run_with_timeout(self_connect::<TestTransportNoise, NoiseTcpTransport>()).await;
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
    let _peer_socket_join_handle = logging::spawn_in_current_span(async move {
        let (mut peer_socket, _address) = listener.accept().await.unwrap();
        let _ = peer_socket.write_all(b"invalid message").await;
        // Return the socket to make sure it lives to the end of the test.
        // This is mainly needed in the case of MpscChannelTransport, where a connection
        // is just a pair of tokio::io::DuplexStream's, one of which is held inside
        // the socket. Once the socket is dropped, any attempts to write to the stream
        // on the other side will fail immediately. I.e. the handshake will likely fail
        // when the node tries to send Hello, so it won't even see the "invalid message",
        // which it's supposed to receive instead of HelloAck.
        peer_socket
    });

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn, _, _, _) = DefaultNetworkingService::<T>::start(
        true,
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
    conn.connect(addr[0].into(), None).unwrap();

    let event = conn.poll_next().await.unwrap();
    let (peer_address, error) = assert_matches_return_val!(
        event,
        ConnectivityEvent::MisbehavedOnHandshake {
            peer_address,
            error,
        },
        (peer_address, error)
    );
    assert_eq!(peer_address, addr[0].into());
    assert_eq!(error.ban_score(), 100);

    let event = conn.poll_next().await.unwrap();
    let peer_address = assert_matches_return_val!(
        event,
        ConnectivityEvent::ConnectionError {
            peer_address,
            error: _,
        },
        peer_address
    );
    assert_eq!(peer_address, addr[0].into());
}

#[tracing::instrument]
#[tokio::test]
async fn invalid_outbound_peer_connect_tcp() {
    run_with_timeout(invalid_outbound_peer_connect::<
        TestTransportTcp,
        TcpTransportSocket,
    >())
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn invalid_outbound_peer_connect_channels() {
    run_with_timeout(invalid_outbound_peer_connect::<
        TestTransportChannel,
        MpscChannelTransport,
    >())
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn invalid_outbound_peer_connect_noise() {
    run_with_timeout(invalid_outbound_peer_connect::<
        TestTransportNoise,
        NoiseTcpTransport,
    >())
    .await;
}

// This test checks common protocol version selection when the nodes are explicitly told
// which version numbers to announce to each other. It doest't use PREFERRED_PROTOCOL_VERSION
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
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut srv1, _, _, _) = DefaultNetworkingService::<T>::start_with_version(
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
        true,
        A::make_transport(),
        vec![A::make_address().into()],
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
            peer_address,
            bind_address: _,
            peer_info,
            node_address_as_seen_by_peer: _,
        } => {
            assert_eq!(peer_address, srv2.local_addresses()[0]);
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
            peer_address: _,
            bind_address: _,
            peer_info,
            node_address_as_seen_by_peer: _,
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
        CURRENT_PROTOCOL_VERSION,
        NEXT_PROTOCOL_VERSION,
        CURRENT_PROTOCOL_VERSION,
    )
    .await;
    general_protocol_version_selection_impl::<A, T>(
        NEXT_PROTOCOL_VERSION,
        CURRENT_PROTOCOL_VERSION,
        CURRENT_PROTOCOL_VERSION,
    )
    .await;

    let next_version_supported = all::<SupportedProtocolVersion>()
        .any(|ver| ver.into_raw_version() == NEXT_PROTOCOL_VERSION);
    // This part won't work if NEXT_PROTOCOL_VERSION is not inside SupportedProtocolVersion.
    if next_version_supported {
        log::debug!("NEXT_PROTOCOL_VERSION is supported; performing an additional check");
        general_protocol_version_selection_impl::<A, T>(
            NEXT_PROTOCOL_VERSION,
            NEXT_PROTOCOL_VERSION,
            NEXT_PROTOCOL_VERSION,
        )
        .await;
    }
}

#[tracing::instrument]
#[tokio::test]
async fn general_protocol_version_selection_tcp() {
    run_with_timeout(general_protocol_version_selection::<
        TestTransportTcp,
        TcpTransportSocket,
    >())
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn general_protocol_version_selection_channels() {
    run_with_timeout(general_protocol_version_selection::<
        TestTransportChannel,
        MpscChannelTransport,
    >())
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn general_protocol_version_selection_noise() {
    run_with_timeout(general_protocol_version_selection::<
        TestTransportNoise,
        NoiseTcpTransport,
    >())
    .await;
}
