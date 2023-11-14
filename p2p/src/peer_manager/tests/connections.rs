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
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use p2p_test_utils::P2pBasicTestTimeGetter;
use p2p_types::{ip_or_socket_address::IpOrSocketAddress, socket_address::SocketAddress};

use crate::{
    config::P2pConfig,
    net::types::{services::Service, PeerRole},
    peer_manager::{
        tests::{get_connected_peers, run_peer_manager},
        MaxInboundConnections,
    },
    testing_utils::{
        connect_and_accept_services, connect_services, get_connectivity_event,
        peerdb_inmemory_store, test_p2p_config, TestTransportChannel, TestTransportMaker,
        TestTransportNoise, TestTransportTcp, TEST_PROTOCOL_VERSION,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
};
use common::{
    chain::config, primitives::user_agent::mintlayer_core_user_agent, time_getter::TimeGetter,
};
use utils::atomics::SeqCstAtomicBool;

use crate::{
    error::{DialError, P2pError, ProtocolError},
    net::{
        self,
        default_backend::{
            transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            DefaultNetworkingService,
        },
        types::PeerInfo,
        ConnectivityService, NetworkingService,
    },
    peer_manager::{self, tests::make_peer_manager},
    PeerManagerEvent,
};

// try to connect to an address that no one listening on and verify it fails
async fn test_peer_manager_connect<T: NetworkingService>(
    transport: T::Transport,
    bind_addr: SocketAddress,
    remote_addr: SocketAddress,
) where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let (mut peer_manager, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(transport, bind_addr, config).await;

    peer_manager.try_connect(remote_addr, None).unwrap();

    assert!(matches!(
        peer_manager.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionError {
            address: _,
            error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut)
        })
    ));
}

#[tracing::instrument]
#[tokio::test]
async fn test_peer_manager_connect_tcp() {
    let transport = TestTransportTcp::make_transport();
    let bind_addr = TestTransportTcp::make_address();
    let remote_addr: SocketAddress = "[::1]:1".parse().unwrap();

    test_peer_manager_connect::<DefaultNetworkingService<TcpTransportSocket>>(
        transport,
        bind_addr,
        remote_addr,
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn test_peer_manager_connect_tcp_noise() {
    let transport = TestTransportNoise::make_transport();
    let bind_addr = TestTransportTcp::make_address();
    let remote_addr: SocketAddress = "[::1]:1".parse().unwrap();

    test_peer_manager_connect::<DefaultNetworkingService<NoiseTcpTransport>>(
        transport,
        bind_addr,
        remote_addr,
    )
    .await;
}

// verify that the auto-connect functionality works if the number of active connections
// is below the desired threshold and there are idle peers in the peerdb
async fn test_auto_connect<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    let addr = pm2.peer_connectivity_handle.local_addresses()[0];

    logging::spawn_in_current_span(async move {
        loop {
            assert!(pm2.peer_connectivity_handle.poll_next().await.is_ok());
        }
    });

    // "discover" the other networking service
    pm1.peerdb.peer_discovered(addr);
    pm1.heartbeat(false);

    assert_eq!(pm1.pending_outbound_connects.len(), 1);
    assert!(std::matches!(
        pm1.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::OutboundAccepted { .. })
    ));
}

#[tracing::instrument]
#[tokio::test]
async fn test_auto_connect_tcp() {
    test_auto_connect::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn test_auto_connect_channels() {
    test_auto_connect::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>()
        .await;
}

#[tracing::instrument]
#[tokio::test]
async fn test_auto_connect_noise() {
    test_auto_connect::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn connect_outbound_same_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_outbound_same_network_tcp() {
    connect_outbound_same_network::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_outbound_same_network_channels() {
    connect_outbound_same_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_outbound_same_network_noise() {
    connect_outbound_same_network::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn connect_outbound_different_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    let (_address, peer_info, _) = connect_services::<T>(
        &mut pm2.peer_connectivity_handle,
        &mut pm1.peer_connectivity_handle,
    )
    .await;
    assert_ne!(peer_info.network, *config.magic_bytes());
}

#[tracing::instrument]
#[tokio::test]
async fn connect_outbound_different_network_tcp() {
    connect_outbound_different_network::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_outbound_different_network_channels() {
    connect_outbound_different_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_outbound_different_network_noise() {
    connect_outbound_different_network::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

async fn connect_inbound_same_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    pm2.try_accept_connection(address, PeerRole::Inbound, peer_info, None).unwrap();
}

#[tracing::instrument]
#[tokio::test]
async fn connect_inbound_same_network_tcp() {
    connect_inbound_same_network::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>(
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_inbound_same_network_channel() {
    connect_inbound_same_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_inbound_same_network_noise() {
    connect_inbound_same_network::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn connect_inbound_different_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let (mut pm1, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr1,
        Arc::new(config::create_mainnet()),
    )
    .await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    assert_eq!(
        pm2.try_accept_connection(address, PeerRole::Inbound, peer_info, None),
        Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork(
            [1, 2, 3, 4],
            *config::create_mainnet().magic_bytes(),
        )))
    );
}

#[tracing::instrument]
#[tokio::test]
async fn connect_inbound_different_network_tcp() {
    connect_inbound_different_network::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_inbound_different_network_channels() {
    connect_inbound_different_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connect_inbound_different_network_noise() {
    connect_inbound_different_network::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

async fn remote_closes_connection<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let (mut pm1, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr1,
        Arc::new(config::create_mainnet()),
    )
    .await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::create_mainnet()),
    )
    .await;

    let (_address, peer_info, _) = connect_and_accept_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    assert_eq!(
        pm2.peer_connectivity_handle.disconnect(peer_info.peer_id),
        Ok(())
    );
    assert!(std::matches!(
        pm1.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tracing::instrument]
#[tokio::test]
async fn remote_closes_connection_tcp() {
    remote_closes_connection::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>()
        .await;
}

#[tracing::instrument]
#[tokio::test]
async fn remote_closes_connection_channels() {
    remote_closes_connection::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn remote_closes_connection_noise() {
    remote_closes_connection::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>()
        .await;
}

async fn inbound_connection_too_many_peers<A, T>(peers: Vec<(SocketAddress, PeerInfo)>)
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr2, Arc::clone(&config)).await;

    for peer in peers.into_iter() {
        pm1.try_accept_connection(peer.0, PeerRole::Inbound, peer.1, None).unwrap();
    }
    assert_eq!(pm1.inbound_peer_count(), *MaxInboundConnections::default());

    let (_address, peer_info, _) = connect_and_accept_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    logging::spawn_in_current_span(async move { pm1.run().await });

    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    if let Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id }) = event {
        assert_eq!(peer_id, peer_info.peer_id);
    } else {
        panic!("invalid event received");
    }
}

#[tracing::instrument]
#[tokio::test]
async fn inbound_connection_too_many_peers_tcp() {
    let config = Arc::new(config::create_mainnet());
    let peers = (0..*MaxInboundConnections::default())
        .map(|index| {
            (
                format!("127.0.0.1:{}", index + 10000).parse().expect("valid address"),
                PeerInfo {
                    peer_id: PeerId::new(),
                    protocol_version: TEST_PROTOCOL_VERSION,
                    network: *config.magic_bytes(),
                    software_version: *config.software_version(),
                    user_agent: mintlayer_core_user_agent(),
                    common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
                },
            )
        })
        .collect::<Vec<_>>();

    inbound_connection_too_many_peers::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >(peers)
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn inbound_connection_too_many_peers_channels() {
    let config = Arc::new(config::create_mainnet());
    let peers = (0..*MaxInboundConnections::default())
        .map(|index| {
            (
                format!("127.0.0.1:{}", index + 10000).parse().expect("valid address"),
                PeerInfo {
                    peer_id: PeerId::new(),
                    protocol_version: TEST_PROTOCOL_VERSION,
                    network: *config.magic_bytes(),
                    software_version: *config.software_version(),
                    user_agent: mintlayer_core_user_agent(),
                    common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
                },
            )
        })
        .collect::<Vec<_>>();

    inbound_connection_too_many_peers::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >(peers)
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn inbound_connection_too_many_peers_noise() {
    let config = Arc::new(config::create_mainnet());
    let peers = (0..*MaxInboundConnections::default())
        .map(|index| {
            (
                format!("127.0.0.1:{}", index + 10000).parse().expect("valid address"),
                PeerInfo {
                    peer_id: PeerId::new(),
                    protocol_version: TEST_PROTOCOL_VERSION,
                    network: *config.magic_bytes(),
                    software_version: *config.software_version(),
                    user_agent: mintlayer_core_user_agent(),
                    common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
                },
            )
        })
        .collect::<Vec<_>>();

    inbound_connection_too_many_peers::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >(peers)
    .await;
}

async fn connection_timeout<T>(transport: T::Transport, addr1: SocketAddress, addr2: SocketAddress)
where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn, _, _, _) = T::start(
        transport,
        vec![addr1],
        Arc::clone(&config),
        p2p_config,
        time_getter,
        shutdown,
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    // This will fail immediately because it is trying to connect to the closed port
    conn.connect(addr2, None).expect("dial to succeed");

    match timeout(Duration::from_secs(1), conn.poll_next()).await {
        Ok(res) => assert!(std::matches!(
            res,
            Ok(net::types::ConnectivityEvent::ConnectionError {
                address: _,
                error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
            })
        )),
        Err(_err) => panic!("did not receive `ConnectionError` in time"),
    }
}

#[tracing::instrument]
#[tokio::test]
async fn connection_timeout_tcp() {
    connection_timeout::<DefaultNetworkingService<TcpTransportSocket>>(
        TestTransportTcp::make_transport(),
        TestTransportTcp::make_address(),
        TestTransportTcp::make_address(),
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connection_timeout_channels() {
    connection_timeout::<DefaultNetworkingService<MpscChannelTransport>>(
        TestTransportChannel::make_transport(),
        TestTransportChannel::make_address(),
        TestTransportChannel::make_address(),
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connection_timeout_noise() {
    connection_timeout::<DefaultNetworkingService<NoiseTcpTransport>>(
        TestTransportNoise::make_transport(),
        TestTransportNoise::make_address(),
        TestTransportNoise::make_address(),
    )
    .await;
}

// try to establish a new connection through RPC and verify that it is notified of the timeout
async fn connection_timeout_rpc_notified<T>(
    transport: T::Transport,
    addr1: SocketAddress,
    addr2: SocketAddress,
) where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(P2pConfig {
        outbound_connection_timeout: Duration::from_secs(1).into(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
        protocol_config: Default::default(),
    });
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (conn, _, _, _) = T::start(
        transport,
        vec![addr1],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();
    let (peer_mgr_event_sender, peer_mgr_event_receiver) = tokio::sync::mpsc::unbounded_channel();

    let peer_manager = peer_manager::PeerManager::<T, _>::new(
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        conn,
        peer_mgr_event_receiver,
        time_getter,
        peerdb_inmemory_store(),
    )
    .unwrap();

    logging::spawn_in_current_span(async move {
        peer_manager.run().await.unwrap();
    });

    let (response_sender, response_receiver) = oneshot_nofail::channel();
    peer_mgr_event_sender
        .send(PeerManagerEvent::Connect(
            addr2.to_string().parse().unwrap(),
            response_sender,
        ))
        .unwrap();

    match timeout(Duration::from_secs(60), response_receiver).await.unwrap() {
        Ok(Err(P2pError::DialError(DialError::ConnectionRefusedOrTimedOut))) => {}
        event => panic!("unexpected event: {event:?}"),
    }
}

// Address is reserved for "TEST-NET-2" documentation and examples. See: https://en.wikipedia.org/wiki/Reserved_IP_addresses
const GUARANTEED_TIMEOUT_ADDRESS: &str = "198.51.100.2:1";

#[tracing::instrument]
#[tokio::test]
async fn connection_timeout_rpc_notified_tcp() {
    connection_timeout_rpc_notified::<DefaultNetworkingService<TcpTransportSocket>>(
        TestTransportTcp::make_transport(),
        TestTransportTcp::make_address(),
        GUARANTEED_TIMEOUT_ADDRESS.parse().unwrap(),
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connection_timeout_rpc_notified_channels() {
    connection_timeout_rpc_notified::<DefaultNetworkingService<MpscChannelTransport>>(
        TestTransportChannel::make_transport(),
        TestTransportChannel::make_address(),
        GUARANTEED_TIMEOUT_ADDRESS.parse().unwrap(),
    )
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connection_timeout_rpc_notified_noise() {
    connection_timeout_rpc_notified::<DefaultNetworkingService<NoiseTcpTransport>>(
        TestTransportNoise::make_transport(),
        TestTransportNoise::make_address(),
        GUARANTEED_TIMEOUT_ADDRESS.parse().unwrap(),
    )
    .await;
}

// verify that peer connection is made when valid reserved_node parameter is used
async fn connection_reserved_node<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = Arc::new(config::create_mainnet());

    // Start first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender, _shutdown_sender, _subscribers_sender) = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_1,
        time_getter.get_time_getter(),
    )
    .await;

    // Get the first peer manager's bind address
    let (response_sender, response_receiver) = oneshot_nofail::channel();
    peer_mgr_event_sender
        .send(PeerManagerEvent::GetBindAddresses(response_sender))
        .unwrap();
    let bind_addresses =
        timeout(Duration::from_secs(20), response_receiver).await.unwrap().unwrap();
    assert_eq!(bind_addresses.len(), 1);
    let reserved_nodes = bind_addresses
        .iter()
        .map(|s| IpOrSocketAddress::new_socket_address(s.socket_addr()))
        .collect();

    // Start second peer manager and let it know about first manager via reserved
    let p2p_config_2 = Arc::new(P2pConfig {
        reserved_nodes,

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender, _shutdown_sender, _subscribers_sender) = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_2,
        time_getter.get_time_getter(),
    )
    .await;

    // The first peer manager must report new connection after some time
    let started_at = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(10)).await;
        time_getter.advance_time(Duration::from_secs(1));
        let (response_sender, response_receiver) = oneshot_nofail::channel();
        peer_mgr_event_sender
            .send(PeerManagerEvent::GetConnectedPeers(response_sender))
            .unwrap();
        let connected_peers =
            timeout(Duration::from_secs(10), response_receiver).await.unwrap().unwrap();
        if connected_peers.len() == 1 {
            break;
        }
        assert!(
            Instant::now().duration_since(started_at) < Duration::from_secs(10),
            "Unexpected peer count: {}",
            connected_peers.len()
        );
    }
}

#[tracing::instrument]
#[tokio::test]
async fn connection_reserved_node_tcp() {
    connection_reserved_node::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>()
        .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connection_reserved_node_noise() {
    connection_reserved_node::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>()
        .await;
}

#[tracing::instrument]
#[tokio::test]
async fn connection_reserved_node_channel() {
    connection_reserved_node::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>()
        .await;
}

// Verify that peers announce own addresses and are discovered by other peers.
// All listening addresses are discovered and multiple connections are made.
async fn discovered_node<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let chain_config = Arc::new(config::create_mainnet());

    let time_getter = P2pBasicTestTimeGetter::new();

    // Start the first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        allow_discover_private_ips: true.into(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender1, _shutdown_sender, _subscribers_sender) = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_1,
        time_getter.get_time_getter(),
    )
    .await;

    // Get the first peer manager's bind address
    let (response_sender, response_receiver) = oneshot_nofail::channel();
    peer_mgr_event_sender1
        .send(PeerManagerEvent::GetBindAddresses(response_sender))
        .unwrap();

    let bind_addresses = timeout(Duration::from_secs(1), response_receiver).await.unwrap().unwrap();
    assert_eq!(bind_addresses.len(), 1);
    let reserved_nodes = bind_addresses
        .iter()
        .map(|s| IpOrSocketAddress::new_socket_address(s.socket_addr()))
        .collect();

    // Start the second peer manager and let it know about the first peer using reserved
    let p2p_config_2 = Arc::new(P2pConfig {
        reserved_nodes,
        allow_discover_private_ips: true.into(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender2, _shutdown_sender, _subscribers_sender) = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_2,
        time_getter.get_time_getter(),
    )
    .await;

    let reserved_nodes = bind_addresses
        .iter()
        .map(|s| IpOrSocketAddress::new_socket_address(s.socket_addr()))
        .collect();

    // Start the third peer manager and let it know about the first peer using reserved
    let p2p_config_3 = Arc::new(P2pConfig {
        reserved_nodes,
        allow_discover_private_ips: true.into(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender3, _shutdown_sender, _subscribers_sender) = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_3,
        time_getter.get_time_getter(),
    )
    .await;

    let started_at = Instant::now();

    // All peers should discover each other
    loop {
        let connected_peers = tokio::join!(
            get_connected_peers(&peer_mgr_event_sender1),
            get_connected_peers(&peer_mgr_event_sender2),
            get_connected_peers(&peer_mgr_event_sender3)
        );
        let counts = [connected_peers.0.len(), connected_peers.1.len(), connected_peers.2.len()];

        // There should be:
        // - 2 outbound and 2 inbound connections to/from reserved peers.
        // - 3 outbound connections to the discovered addresses
        //   (each peer can make only one outbound connection because all discovered addresses are in the same address group).
        // - 3 inbound connections to the discovered addresses.
        // Since outbound connections are random, we don't know which peer will get 4 connections.
        if counts == [3, 3, 4] || counts == [3, 4, 3] || counts == [4, 3, 3] {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        time_getter.advance_time(Duration::from_millis(1000));

        assert!(
            Instant::now().duration_since(started_at) < Duration::from_secs(60),
            "Unexpected peer counts: {counts:?}"
        );
    }
}

#[tracing::instrument]
#[tokio::test]
async fn discovered_node_tcp() {
    discovered_node::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn discovered_node_noise() {
    discovered_node::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn discovered_node_channel() {
    discovered_node::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>().await;
}
