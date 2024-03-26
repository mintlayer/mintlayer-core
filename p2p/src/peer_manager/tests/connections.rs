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
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use logging::log;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};

use crypto::random::Rng;
use p2p_test_utils::{expect_no_recv, expect_recv, run_with_timeout, P2pBasicTestTimeGetter};
use p2p_types::socket_address::SocketAddress;
use test_utils::random::Seed;
use utils_networking::IpOrSocketAddress;

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::ConnectionValidationError,
    message::AddrListRequest,
    net::{
        default_backend::{
            types::{Command, Message},
            ConnectivityHandle,
        },
        types::{services::Service, ConnectionType, ConnectivityEvent},
    },
    peer_manager::{
        config::{MaxInboundConnections, PeerManagerConfig},
        peerdb::{
            self, config::PeerDbConfig,
            test_utils::make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups,
        },
        tests::{
            get_connected_peers, make_standalone_peer_manager, run_peer_manager,
            utils::{
                expect_cmd_connect_to, expect_cmd_connect_to_one_of,
                inbound_block_relay_peer_accepted_by_backend, make_full_relay_peer_info,
                mutate_peer_manager, outbound_full_relay_peer_accepted_by_backend,
                query_peer_manager, recv_command_advance_time, start_manually_connecting,
            },
        },
        PeerManager,
    },
    testing_utils::{
        connect_and_accept_services, connect_services, get_connectivity_event,
        make_transport_with_local_addr_in_group, peerdb_inmemory_store, test_p2p_config,
        test_p2p_config_with_peer_mgr_config, TestAddressMaker, TestTransportChannel,
        TestTransportMaker, TestTransportNoise, TestTransportTcp, TEST_PROTOCOL_VERSION,
    },
    tests::helpers::TestPeersInfo,
    types::peer_id::PeerId,
    utils::oneshot_nofail,
};
use common::{
    chain::config::{self, MagicBytes},
    primitives::user_agent::mintlayer_core_user_agent,
    time_getter::TimeGetter,
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

async fn validate_invalid_connection<A, S>(seed: Seed)
where
    A: TestTransportMaker<Transport = S::Transport>,
    S: NetworkingService + 'static + std::fmt::Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let mut rng = make_seedable_rng(seed);

    for conn_type in [ConnectionType::OutboundFullRelay, ConnectionType::Inbound] {
        let config = Arc::new(config::create_unit_test_config());
        let (mut peer_manager, _shutdown_sender, _subscribers_sender) =
            make_peer_manager::<S>(A::make_transport(), A::make_address(), Arc::clone(&config))
                .await;

        // invalid magic bytes
        let peer_id = PeerId::new();
        let res = peer_manager.try_accept_connection(
            TestAddressMaker::new_random_address(&mut rng),
            TestAddressMaker::new_random_address(&mut rng),
            conn_type,
            net::types::PeerInfo {
                peer_id,
                protocol_version: TEST_PROTOCOL_VERSION,
                network: MagicBytes::new([1, 2, 3, 4]),
                software_version: *config.software_version(),
                user_agent: mintlayer_core_user_agent(),
                common_services: [Service::Blocks, Service::Transactions, Service::PeerAddresses]
                    .as_slice()
                    .into(),
            },
            None,
        );
        assert!(res.is_err());
        assert!(!peer_manager.is_peer_connected(peer_id));
    }
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn validate_invalid_connection_tcp(#[case] seed: Seed) {
    validate_invalid_connection::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>(
        seed,
    )
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn validate_invalid_connection_channels(#[case] seed: Seed) {
    validate_invalid_connection::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >(seed)
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn validate_invalid_connection_noise(#[case] seed: Seed) {
    validate_invalid_connection::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>(
        seed,
    )
    .await;
}

async fn inbound_connection_invalid_magic<A, T>()
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
        Arc::new(config::create_unit_test_config()),
    )
    .await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::Builder::test_chain().magic_bytes(MagicBytes::new([1, 2, 3, 4])).build()),
    )
    .await;

    let (_address, peer_info, _) = connect_and_accept_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    logging::spawn_in_current_span(async move { pm1.run().await });

    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    match event {
        Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id })
            if peer_id == peer_info.peer_id => {}
        _ => panic!("unexpected event: {event:?}"),
    }
}

#[tracing::instrument]
#[tokio::test]
async fn inbound_connection_invalid_magic_tcp() {
    inbound_connection_invalid_magic::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn inbound_connection_invalid_magic_channels() {
    inbound_connection_invalid_magic::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn inbound_connection_invalid_magic_noise() {
    inbound_connection_invalid_magic::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

// try to connect to an address that no one listening on and verify it fails
async fn test_peer_manager_connect<T: NetworkingService>(
    transport: T::Transport,
    bind_addr: SocketAddress,
    remote_addr: SocketAddress,
) where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_unit_test_config());
    let (mut peer_manager, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(transport, bind_addr, config).await;

    peer_manager
        .try_connect(remote_addr, None, ConnectionType::OutboundManual)
        .unwrap();

    assert!(matches!(
        peer_manager.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionError {
            peer_address: _,
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

    let config = Arc::new(config::create_unit_test_config());
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
    pm1.heartbeat();

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

    let config = Arc::new(config::create_unit_test_config());
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

    let config = Arc::new(config::create_unit_test_config());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::Builder::test_chain().magic_bytes(MagicBytes::new([1, 2, 3, 4])).build()),
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

    let config = Arc::new(config::create_unit_test_config());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    pm2.try_accept_connection(
        address,
        pm2.peer_connectivity_handle.local_addresses()[0],
        ConnectionType::Inbound,
        peer_info,
        None,
    )
    .unwrap();
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
        Arc::new(config::create_unit_test_config()),
    )
    .await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::Builder::test_chain().magic_bytes(MagicBytes::new([1, 2, 3, 4])).build()),
    )
    .await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    assert_eq!(
        pm2.try_accept_connection(
            address,
            pm2.peer_connectivity_handle.local_addresses()[0],
            ConnectionType::Inbound,
            peer_info,
            None
        ),
        Err(P2pError::ConnectionValidationFailed(
            ConnectionValidationError::DifferentNetwork {
                our_network: MagicBytes::new([1, 2, 3, 4]),
                their_network: *config::create_unit_test_config().magic_bytes(),
            }
        ))
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
        Arc::new(config::create_unit_test_config()),
    )
    .await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::create_unit_test_config()),
    )
    .await;

    let (_address, peer_info, _) = connect_and_accept_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    assert_eq!(
        pm2.peer_connectivity_handle.disconnect(peer_info.peer_id, None),
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

    let config = Arc::new(config::create_unit_test_config());
    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let (mut pm2, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr2, Arc::clone(&config)).await;

    for peer in peers.into_iter() {
        pm1.try_accept_connection(peer.0, addr2, ConnectionType::Inbound, peer.1, None)
            .unwrap();
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
    let config = Arc::new(config::create_unit_test_config());
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
    let config = Arc::new(config::create_unit_test_config());
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
    let config = Arc::new(config::create_unit_test_config());
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
    let config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn, _, _, _) = T::start(
        true,
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
                peer_address: _,
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
    let config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        outbound_connection_timeout: Duration::from_secs(1).into(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    });
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let time_getter = TimeGetter::default();
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (conn, _, _, _) = T::start(
        true,
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
        true,
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
    let chain_config = Arc::new(config::create_unit_test_config());

    // Start first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
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
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
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
// All peers are in the same address group
async fn discovered_node_same_address_group<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let chain_config = Arc::new(config::create_unit_test_config());

    let time_getter = P2pBasicTestTimeGetter::new();

    let peer_manager_config = PeerManagerConfig {
        allow_same_ip_connections: true.into(),

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        peerdb_config: Default::default(),
    };

    // Start the first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        allow_discover_private_ips: true.into(),
        peer_manager_config: peer_manager_config.clone(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
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
    let reserved_nodes: Vec<_> = bind_addresses
        .iter()
        .map(|s| IpOrSocketAddress::new_socket_address(s.socket_addr()))
        .collect();

    // Start the second peer manager and let it know about the first peer using reserved
    let p2p_config_2 = Arc::new(P2pConfig {
        reserved_nodes: reserved_nodes.clone(),
        allow_discover_private_ips: true.into(),
        peer_manager_config: peer_manager_config.clone(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
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

    // Start the third peer manager and let it know about the first peer using reserved
    let p2p_config_3 = Arc::new(P2pConfig {
        reserved_nodes,
        allow_discover_private_ips: true.into(),
        peer_manager_config,

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
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

        // Since outbound connections are random, we don't know which peer will connect first.
        let counts = {
            let mut counts =
                [connected_peers.0.len(), connected_peers.1.len(), connected_peers.2.len()];
            counts.sort();
            counts
        };

        // There should be:
        // - 1 outbound and 2 inbound connections to/from reserved peer.
        // - 1 outbound and 1 inbound connections from one of the peers to reserved.
        // - 1 outbound connections to the reserved peer.
        // No connections are made to discovered peers because they are in the same group and are already
        // covered by reserved connections which are treated as manual.
        if counts == [1, 2, 3] {
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
    discovered_node_same_address_group::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn discovered_node_noise() {
    discovered_node_same_address_group::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn discovered_node_channel() {
    discovered_node_same_address_group::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

// Create 3 peers and make one of them a reserved node.
// Put reserved node in a separate address group.
#[tracing::instrument]
#[tokio::test]
async fn discovered_node_2_groups() {
    let chain_config = Arc::new(config::create_unit_test_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let peer_manager_config = PeerManagerConfig {
        allow_same_ip_connections: true.into(),

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        peerdb_config: Default::default(),
    };

    // Start the first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        allow_discover_private_ips: true.into(),
        peer_manager_config: peer_manager_config.clone(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender1, _shutdown_sender, _subscribers_sender) =
        run_peer_manager::<DefaultNetworkingService<MpscChannelTransport>>(
            make_transport_with_local_addr_in_group(1),
            TestTransportChannel::make_address(),
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
    let reserved_nodes: Vec<_> = bind_addresses
        .iter()
        .map(|s| IpOrSocketAddress::new_socket_address(s.socket_addr()))
        .collect();

    // Start the second peer manager and let it know about the first peer using reserved
    let p2p_config_2 = Arc::new(P2pConfig {
        reserved_nodes: reserved_nodes.clone(),
        allow_discover_private_ips: true.into(),
        peer_manager_config: peer_manager_config.clone(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender2, _shutdown_sender, _subscribers_sender) =
        run_peer_manager::<DefaultNetworkingService<MpscChannelTransport>>(
            make_transport_with_local_addr_in_group(2),
            TestTransportChannel::make_address(),
            Arc::clone(&chain_config),
            p2p_config_2,
            time_getter.get_time_getter(),
        )
        .await;

    // Start the third peer manager and let it know about the first peer using reserved
    let p2p_config_3 = Arc::new(P2pConfig {
        reserved_nodes,
        allow_discover_private_ips: true.into(),
        peer_manager_config,

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender3, _shutdown_sender, _subscribers_sender) =
        run_peer_manager::<DefaultNetworkingService<MpscChannelTransport>>(
            make_transport_with_local_addr_in_group(2),
            TestTransportChannel::make_address(),
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
        // - 1 outbound and 2 inbound connections for one of the non-reserved peers.
        // - 2 outbound and 1 inbound connections to the other non-reserved peer.
        // Since outbound connections are random, we don't know which peer will connect first.
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
async fn discovered_node_separate_groups() {
    let chain_config = Arc::new(config::create_unit_test_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let peer_manager_config = PeerManagerConfig {
        allow_same_ip_connections: true.into(),

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        peerdb_config: Default::default(),
    };

    // Start the first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        allow_discover_private_ips: true.into(),
        peer_manager_config: peer_manager_config.clone(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender1, _shutdown_sender, _subscribers_sender) =
        run_peer_manager::<DefaultNetworkingService<MpscChannelTransport>>(
            make_transport_with_local_addr_in_group(1),
            TestTransportChannel::make_address(),
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
    let reserved_nodes: Vec<_> = bind_addresses
        .iter()
        .map(|s| IpOrSocketAddress::new_socket_address(s.socket_addr()))
        .collect();

    // Start the second peer manager and let it know about the first peer using reserved
    let p2p_config_2 = Arc::new(P2pConfig {
        reserved_nodes: reserved_nodes.clone(),
        allow_discover_private_ips: true.into(),
        peer_manager_config: peer_manager_config.clone(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender2, _shutdown_sender, _subscribers_sender) =
        run_peer_manager::<DefaultNetworkingService<MpscChannelTransport>>(
            make_transport_with_local_addr_in_group(2),
            TestTransportChannel::make_address(),
            Arc::clone(&chain_config),
            p2p_config_2,
            time_getter.get_time_getter(),
        )
        .await;

    // Start the third peer manager and let it know about the first peer using reserved
    let p2p_config_3 = Arc::new(P2pConfig {
        reserved_nodes,
        allow_discover_private_ips: true.into(),
        peer_manager_config,

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });
    let (peer_mgr_event_sender3, _shutdown_sender, _subscribers_sender) =
        run_peer_manager::<DefaultNetworkingService<MpscChannelTransport>>(
            make_transport_with_local_addr_in_group(3),
            TestTransportChannel::make_address(),
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

        // Each peer has 2 outbound and 2 inbound connections with 2 other peers
        if counts == [4, 4, 4] {
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

// 1) Configure the peer manager to only allow 1 full outbound connection. Make it discover
// a number of addresses.
// 2) Wait for the normal outbound connection attempt; make it succeed and check that it's not
// closed immediately.
// 3) In a loop wait for feeler connection attempts while advancing mocked time. Make some of
// them succeed and some fail. The succeeded connections must be disconnected immediately anyway.
// 4) In the end check that "successful" addresses were moved to the 'tried' table and failed ones
// remain in 'new'.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn feeler_connections_test(#[case] seed: Seed) {
    run_with_timeout(feeler_connections_test_impl(seed)).await;
}

async fn feeler_connections_test_impl(seed: Seed) {
    use feeler_connections_test_utils::*;

    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());

    // Though this is mocked time, we still want to make the interval small, because
    // we'll be advancing mocked time by this value frequently. And with the default
    // value we can reach the lifetime limit for unreachable connection addresses,
    // after which some "failed" addresses might be purged and the assertion at the end
    // of the test will fail.
    let feeler_connections_interval = Duration::from_secs(1);
    let p2p_config = Arc::new(make_p2p_config(feeler_connections_interval, &mut rng));

    let bind_address = TestTransportTcp::make_address();
    let (cmd_sender, mut cmd_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (conn_event_sender, conn_event_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (peer_mgr_event_sender, peer_mgr_event_receiver) =
        tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle =
        ConnectivityHandle::<TestNetworkingService>::new(vec![], cmd_sender, conn_event_receiver);

    let mut peer_mgr = PeerManager::<TestNetworkingService, _>::new(
        true,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_mgr_event_receiver,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    // Note: need to make sure that the generated addresses won't collide with each other when
    // put into either of the tables. Otherwise the checks below will fail, e.g. when a previously
    // "tried" address gets moved back into "new".
    let addresses = peerdb::test_utils::make_non_colliding_addresses_for_peer_db(
        &peer_mgr.peerdb,
        10,
        &mut rng,
    );
    let mut addresses = BTreeSet::from_iter(addresses.into_iter());
    for addr in &addresses {
        peer_mgr.peerdb.peer_discovered(*addr);
    }
    // All the addresses are in the "new" table and none are in "tried".
    let peerdb_new_addresses = new_addr_table_as_set(&peer_mgr.peerdb);
    assert_eq!(peerdb_new_addresses, addresses);
    let peerdb_tried_addresses = tried_addr_table_as_set(&peer_mgr.peerdb);
    assert!(peerdb_tried_addresses.is_empty());

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    let mut successful_conn_addresses = BTreeSet::new();
    let mut unsuccessful_conn_addresses = BTreeSet::new();

    log::debug!("Expecting normal outbound connection attempt");
    let cmd = cmd_receiver.recv().await.unwrap();
    let outbound_peer_addr = expect_cmd_connect_to_one_of(&cmd, &mut addresses);

    let outbound_peer_id = PeerId::new();
    conn_event_sender
        .send(ConnectivityEvent::OutboundAccepted {
            peer_address: outbound_peer_addr,
            bind_address,
            peer_info: make_full_relay_peer_info(outbound_peer_id, &chain_config),
            node_address_as_seen_by_peer: None,
        })
        .unwrap();
    successful_conn_addresses.insert(outbound_peer_addr);

    log::debug!("Expecting Command::Accept");
    let cmd = cmd_receiver.recv().await.unwrap();
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: outbound_peer_id
        }
    );

    log::debug!("Expecting AddrListRequest");
    let cmd = cmd_receiver.recv().await.unwrap();
    assert_eq!(
        cmd,
        Command::SendMessage {
            peer_id: outbound_peer_id,
            message: Message::AddrListRequest(AddrListRequest {})
        }
    );

    // No other commands are sent immediately.
    expect_no_recv!(cmd_receiver);

    let mut had_successful_feelers = false;
    let mut had_unsuccessful_feelers = false;

    // Check for feeler connections in a loop.
    while !addresses.is_empty() {
        log::debug!("addresses.len() == {}", addresses.len());

        log::debug!("Expecting feeler connection attempt");
        let cmd =
            recv_command_advance_time(&mut cmd_receiver, &time_getter, feeler_connections_interval)
                .await
                .unwrap();
        let addr = expect_cmd_connect_to_one_of(&cmd, &mut addresses);
        let is_last_addr = addresses.is_empty();
        let should_succeed = {
            let rand_bool = rng.gen_bool(0.5);
            if is_last_addr {
                if !had_successful_feelers {
                    true
                } else if !had_unsuccessful_feelers {
                    false
                } else {
                    rand_bool
                }
            } else {
                rand_bool
            }
        };

        if should_succeed {
            log::debug!("Feeler connection to {addr} will succeed");

            let cur_peer_id = PeerId::new();
            conn_event_sender
                .send(ConnectivityEvent::OutboundAccepted {
                    peer_address: addr,
                    bind_address,
                    peer_info: make_full_relay_peer_info(cur_peer_id, &chain_config),
                    node_address_as_seen_by_peer: None,
                })
                .unwrap();

            log::debug!("Expecting Command::Accept");
            let cmd = cmd_receiver.recv().await.unwrap();
            assert_eq!(
                cmd,
                Command::Accept {
                    peer_id: cur_peer_id
                }
            );

            // Disconnect command should be sent immediately.
            log::debug!("Expecting Command::Disconnect");
            let cmd = cmd_receiver.recv().await.unwrap();
            assert_eq!(
                cmd,
                Command::Disconnect {
                    peer_id: cur_peer_id,
                    reason: Some(DisconnectionReason::FeelerConnection)
                }
            );

            conn_event_sender
                .send(ConnectivityEvent::ConnectionClosed {
                    peer_id: cur_peer_id,
                })
                .unwrap();

            successful_conn_addresses.insert(addr);
            had_successful_feelers = true;
        } else {
            log::debug!("Feeler connection to {addr} will fail");

            conn_event_sender
                .send(ConnectivityEvent::ConnectionError {
                    peer_address: addr,
                    error: P2pError::ProtocolError(ProtocolError::Unresponsive),
                })
                .unwrap();
            unsuccessful_conn_addresses.insert(addr);
            had_unsuccessful_feelers = true;
        }

        // No other commands are sent immediately.
        expect_no_recv!(cmd_receiver);
    }

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let peer_mgr = peer_mgr_join_handle.await.unwrap();

    let peerdb_new_addresses = new_addr_table_as_set(&peer_mgr.peerdb);
    assert_eq!(peerdb_new_addresses, unsuccessful_conn_addresses);

    let peerdb_tried_addresses = tried_addr_table_as_set(&peer_mgr.peerdb);
    assert_eq!(peerdb_tried_addresses, successful_conn_addresses);
}

mod feeler_connections_test_utils {
    use crate::peer_manager::{
        config::PeerManagerConfig,
        peerdb::{salt::Salt, storage::PeerDbStorage, PeerDb},
    };

    use super::*;

    pub fn make_p2p_config(feeler_connections_interval: Duration, rng: &mut impl Rng) -> P2pConfig {
        P2pConfig {
            peer_manager_config: PeerManagerConfig {
                outbound_full_relay_count: 1.into(),
                outbound_block_relay_count: 0.into(),

                outbound_full_relay_extra_count: 0.into(),
                outbound_block_relay_extra_count: 0.into(),

                feeler_connections_interval: feeler_connections_interval.into(),

                peerdb_config: PeerDbConfig {
                    salt: Some(Salt::new_random_with_rng(rng)),

                    new_addr_table_bucket_count: Default::default(),
                    tried_addr_table_bucket_count: Default::default(),
                    addr_tables_bucket_size: Default::default(),
                },

                preserved_inbound_count_address_group: Default::default(),
                preserved_inbound_count_ping: Default::default(),
                preserved_inbound_count_new_blocks: Default::default(),
                preserved_inbound_count_new_transactions: Default::default(),

                max_inbound_connections: Default::default(),
                outbound_block_relay_connection_min_age: Default::default(),
                outbound_full_relay_connection_min_age: Default::default(),
                stale_tip_time_diff: Default::default(),
                enable_feeler_connections: Default::default(),
                main_loop_tick_interval: Default::default(),
                force_dns_query_if_no_global_addresses_known: Default::default(),
                allow_same_ip_connections: Default::default(),
            },
            // Disable pings to simplify the test.
            ping_check_period: Duration::ZERO.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            protocol_config: Default::default(),
        }
    }

    pub fn new_addr_table_as_set<S: PeerDbStorage>(peerdb: &PeerDb<S>) -> BTreeSet<SocketAddress> {
        peerdb
            .address_tables()
            .new_addr_table()
            .addr_iter()
            .copied()
            .collect::<BTreeSet<_>>()
    }

    pub fn tried_addr_table_as_set<S: PeerDbStorage>(
        peerdb: &PeerDb<S>,
    ) -> BTreeSet<SocketAddress> {
        peerdb
            .address_tables()
            .tried_addr_table()
            .addr_iter()
            .copied()
            .collect::<BTreeSet<_>>()
    }
}

// Check that an automatic outbound connection won't be attempted if an inbound connection to
// the same ip address already exists.
// Test scenario:
// 1) Make the peer manager accept an inbound connection.
// 2) Make it "discover" a peer address with the same ip address as the inbound connection,
// but with a different port number; no connection attempt should be made;
// 3) (sanity check) Make it "discover" a peer address with a different ip address;
// a connection attempt should be made.
// 4) Make a manual connection to the address from "2)"; the connection should be made successfully.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn reject_connection_to_existing_ip(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        peer_manager_config: PeerManagerConfig {
            outbound_full_relay_count: 2.into(),
            outbound_full_relay_extra_count: 0.into(),
            outbound_block_relay_count: 0.into(),
            outbound_block_relay_extra_count: 0.into(),

            // Disable feeler connections because they'll mess up the test.
            enable_feeler_connections: false.into(),

            max_inbound_connections: Default::default(),
            preserved_inbound_count_address_group: Default::default(),
            preserved_inbound_count_ping: Default::default(),
            preserved_inbound_count_new_blocks: Default::default(),
            preserved_inbound_count_new_transactions: Default::default(),
            outbound_block_relay_connection_min_age: Default::default(),
            outbound_full_relay_connection_min_age: Default::default(),
            stale_tip_time_diff: Default::default(),
            main_loop_tick_interval: Default::default(),
            feeler_connections_interval: Default::default(),
            force_dns_query_if_no_global_addresses_known: Default::default(),
            allow_same_ip_connections: Default::default(),
            peerdb_config: Default::default(),
        },

        // Disable pings so that they don't interfere with the testing logic.
        ping_check_period: Duration::ZERO.into(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });

    let time_getter = P2pBasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address();

    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        _peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_addr],
        time_getter.get_time_getter(),
    );

    let peer_addrs = make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups(
        &peer_mgr.peerdb,
        2,
        &mut rng,
    );
    let [peer1_addr, peer2_addr]: [_; 2] = peer_addrs.try_into().unwrap();

    let outbound_peer1_addr = peer1_addr;
    let inbound_peer1_addr = {
        let mut socket_addr = peer1_addr.socket_addr();
        socket_addr.set_port(socket_addr.port().wrapping_add(1));
        SocketAddress::new(socket_addr)
    };

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    // Accept an inbound connection.
    let peer1_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        inbound_peer1_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id: peer1_id });

    // "Discover" outbound_peer1_addr; no connection attempt should be made.
    mutate_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db_mut().peer_discovered(outbound_peer1_addr);
    })
    .await;
    time_getter.advance_time(peer_manager::HEARTBEAT_INTERVAL_MAX);
    expect_no_recv!(cmd_receiver);

    // "Discover" peer2_addr; a connection attempt should be made and
    // the connection should be accepted.
    mutate_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db_mut().peer_discovered(peer2_addr)
    })
    .await;
    time_getter.advance_time(peer_manager::HEARTBEAT_INTERVAL_MAX);

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &peer2_addr);

    let peer2_id = outbound_full_relay_peer_accepted_by_backend(
        &conn_event_sender,
        peer2_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id: peer2_id });
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::SendMessage {
            peer_id: peer2_id,
            message: Message::AddrListRequest(AddrListRequest {})
        }
    );

    // Try manually connecting to outbound_peer1_addr; the connection should be accepted.
    let manual_conn_result_recv =
        start_manually_connecting(&peer_mgr_event_sender, outbound_peer1_addr);

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &outbound_peer1_addr);
    let peer1_id_as_outbound = outbound_full_relay_peer_accepted_by_backend(
        &conn_event_sender,
        outbound_peer1_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: peer1_id_as_outbound
        }
    );

    manual_conn_result_recv.await.unwrap().unwrap();

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check that a feeler connection attempt will be made even if we have an inbound connection
// from the same ip address (which normally would prevent other automatic outbound connections).
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn feeler_connection_to_ip_address_of_inbound_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config_with_peer_mgr_config(PeerManagerConfig {
        // Allow a feeler connection attempt to happen immediately.
        feeler_connections_interval: Duration::ZERO.into(),

        // Normal outbound connections are not allowed, because they'll mess up the test.
        outbound_full_relay_count: 0.into(),
        outbound_full_relay_extra_count: 0.into(),
        outbound_block_relay_count: 0.into(),
        outbound_block_relay_extra_count: 0.into(),

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
        peerdb_config: Default::default(),
    }));

    let time_getter = P2pBasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address();

    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        _peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_addr],
        time_getter.get_time_getter(),
    );

    let peer_addr = TestAddressMaker::new_random_address(&mut rng);
    let outbound_peer_addr = peer_addr;
    let inbound_peer_addr = {
        let mut socket_addr = peer_addr.socket_addr();
        socket_addr.set_port(socket_addr.port().wrapping_add(1));
        SocketAddress::new(socket_addr)
    };

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    // Accept an inbound connection.
    let inbound_peer_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        inbound_peer_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: inbound_peer_id
        }
    );

    // "Discover" outbound_peer_addr.
    mutate_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db_mut().peer_discovered(outbound_peer_addr);
    })
    .await;
    time_getter.advance_time(peer_manager::HEARTBEAT_INTERVAL_MAX);

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &outbound_peer_addr);

    let outbound_peer_id = outbound_full_relay_peer_accepted_by_backend(
        &conn_event_sender,
        outbound_peer_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: outbound_peer_id
        }
    );

    let peers_info = query_peer_manager(&peer_mgr_event_sender, |peer_mgr| {
        TestPeersInfo::from_peer_mgr_peer_contexts(peer_mgr.peers())
    })
    .await;
    let peers_info: BTreeMap<_, _> =
        peers_info.info.into_iter().map(|(addr, info)| (addr, info.conn_type)).collect();
    let expected_peers_info: BTreeMap<_, _> = [
        (inbound_peer_addr, ConnectionType::Inbound),
        (outbound_peer_addr, ConnectionType::Feeler),
    ]
    .into_iter()
    .collect();
    assert_eq!(peers_info, expected_peers_info);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}
