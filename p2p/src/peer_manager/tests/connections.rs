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
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{sync::oneshot, time::timeout};

use crate::{
    config::P2pConfig,
    net::types::Role,
    peer_manager::tests::run_peer_manager,
    testing_utils::{
        connect_services, get_connectivity_event, TestTransportChannel, TestTransportMaker,
        TestTransportNoise, TestTransportTcp,
    },
};
use common::chain::config;

use crate::{
    error::{DialError, P2pError, ProtocolError},
    event::PeerManagerEvent,
    net::{
        self,
        default_backend::{
            transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            types::PeerId,
            DefaultNetworkingService,
        },
        types::{PeerInfo, PubSubTopic},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{self, tests::make_peer_manager},
};

// try to connect to an address that no one listening on and verify it fails
async fn test_peer_manager_connect<T: NetworkingService>(
    transport: T::Transport,
    bind_addr: T::Address,
    remote_addr: T::Address,
) where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let mut peer_manager = make_peer_manager::<T>(transport, bind_addr, config).await;

    peer_manager.connect(remote_addr).await.unwrap();

    assert!(matches!(
        peer_manager.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionError {
            address: _,
            error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut)
        })
    ));
}

#[tokio::test]
async fn test_peer_manager_connect_tcp() {
    let transport = TestTransportTcp::make_transport();
    let bind_addr = TestTransportTcp::make_address();
    let remote_addr: SocketAddr = "[::1]:1".parse().unwrap();

    test_peer_manager_connect::<DefaultNetworkingService<TcpTransportSocket>>(
        transport,
        bind_addr,
        remote_addr,
    )
    .await;
}

#[tokio::test]
async fn test_peer_manager_connect_tcp_noise() {
    let transport = TestTransportNoise::make_transport();
    let bind_addr = TestTransportTcp::make_address();
    let remote_addr: SocketAddr = "[::1]:1".parse().unwrap();

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
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    let addr = pm2.peer_connectivity_handle.local_addresses()[0].clone();

    tokio::spawn(async move {
        loop {
            assert!(pm2.peer_connectivity_handle.poll_next().await.is_ok());
        }
    });

    // "discover" the other networking service
    pm1.peerdb.peer_discovered(&addr);
    pm1.heartbeat().await.unwrap();

    assert_eq!(pm1.pending.len(), 1);
    assert!(std::matches!(
        pm1.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::OutboundAccepted { .. })
    ));
}

#[tokio::test]
async fn test_auto_connect_tcp() {
    test_auto_connect::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn test_auto_connect_channels() {
    test_auto_connect::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>()
        .await;
}

#[tokio::test]
async fn test_auto_connect_noise() {
    test_auto_connect::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn connect_outbound_same_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
}

#[tokio::test]
async fn connect_outbound_same_network_tcp() {
    connect_outbound_same_network::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn connect_outbound_same_network_channels() {
    connect_outbound_same_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn connect_outbound_same_network_noise() {
    connect_outbound_same_network::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn connect_outbound_different_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(common::chain::config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    let (_address, peer_info, _) = connect_services::<T>(
        &mut pm2.peer_connectivity_handle,
        &mut pm1.peer_connectivity_handle,
    )
    .await;
    assert_ne!(peer_info.network, *config.magic_bytes());
}

#[tokio::test]
async fn connect_outbound_different_network_tcp() {
    connect_outbound_different_network::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tokio::test]
async fn connect_outbound_different_network_channels() {
    connect_outbound_different_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

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
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    assert_eq!(
        pm2.accept_inbound_connection(address, peer_info, None).await,
        Ok(())
    );
}

#[tokio::test]
async fn connect_inbound_same_network_tcp() {
    connect_inbound_same_network::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>(
    )
    .await;
}

#[tokio::test]
async fn connect_inbound_same_network_channel() {
    connect_inbound_same_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn connect_inbound_same_network_noise() {
    connect_inbound_same_network::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn connect_inbound_different_network<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let mut pm1 = make_peer_manager::<T>(
        A::make_transport(),
        addr1,
        Arc::new(config::create_mainnet()),
    )
    .await;
    let mut pm2 = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(common::chain::config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    assert_eq!(
        pm2.accept_inbound_connection(address, peer_info, None).await,
        Err(P2pError::ProtocolError(ProtocolError::DifferentNetwork(
            [1, 2, 3, 4],
            *config::create_mainnet().magic_bytes(),
        )))
    );
}

#[tokio::test]
async fn connect_inbound_different_network_tcp() {
    connect_inbound_different_network::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tokio::test]
async fn connect_inbound_different_network_channels() {
    connect_inbound_different_network::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

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
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let mut pm1 = make_peer_manager::<T>(
        A::make_transport(),
        addr1,
        Arc::new(config::create_mainnet()),
    )
    .await;
    let mut pm2 = make_peer_manager::<T>(
        A::make_transport(),
        addr2,
        Arc::new(config::create_mainnet()),
    )
    .await;

    let (_address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    assert_eq!(
        pm2.peer_connectivity_handle.disconnect(peer_info.peer_id).await,
        Ok(())
    );
    assert!(std::matches!(
        pm1.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn remote_closes_connection_tcp() {
    remote_closes_connection::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>()
        .await;
}

#[tokio::test]
async fn remote_closes_connection_channels() {
    remote_closes_connection::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>().await;
}

#[tokio::test]
async fn remote_closes_connection_noise() {
    remote_closes_connection::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>()
        .await;
}

async fn inbound_connection_too_many_peers<A, T>(peers: Vec<(T::Address, PeerInfo<T::PeerId>)>)
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(A::make_transport(), addr2, Arc::clone(&config)).await;

    peers.into_iter().for_each(|peer| {
        pm1.peerdb.peer_connected(peer.0, Role::Inbound, peer.1);
    });
    assert_eq!(
        pm1.peerdb.active_peer_count(),
        peer_manager::MAX_ACTIVE_CONNECTIONS
    );

    let (_address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    tokio::spawn(async move { pm1.run().await });

    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    if let Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id }) = event {
        assert_eq!(peer_id, peer_info.peer_id);
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn inbound_connection_too_many_peers_tcp() {
    let config = Arc::new(config::create_mainnet());
    let peers = (0..peer_manager::MAX_ACTIVE_CONNECTIONS)
        .map(|index| {
            (
                format!("127.0.0.1:{}", index + 10000).parse().expect("valid address"),
                PeerInfo {
                    peer_id: PeerId::new(),
                    network: *config.magic_bytes(),
                    version: common::primitives::semver::SemVer::new(0, 1, 0),
                    agent: None,
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
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

#[tokio::test]
async fn inbound_connection_too_many_peers_channels() {
    let config = Arc::new(config::create_mainnet());
    let peers = (0..peer_manager::MAX_ACTIVE_CONNECTIONS)
        .map(|index| {
            (
                format!("{}", index + 10000).parse().expect("valid address"),
                PeerInfo {
                    peer_id: PeerId::new(),
                    network: *config.magic_bytes(),
                    version: common::primitives::semver::SemVer::new(0, 1, 0),
                    agent: None,
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
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

#[tokio::test]
async fn inbound_connection_too_many_peers_noise() {
    let config = Arc::new(config::create_mainnet());
    let peers = (0..peer_manager::MAX_ACTIVE_CONNECTIONS)
        .map(|index| {
            (
                format!("127.0.0.1:{}", index + 10000).parse().expect("valid address"),
                PeerInfo {
                    peer_id: PeerId::new(),
                    network: *config.magic_bytes(),
                    version: common::primitives::semver::SemVer::new(0, 1, 0),
                    agent: None,
                    subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions]
                        .into_iter()
                        .collect(),
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

async fn connection_timeout<T>(transport: T::Transport, addr1: T::Address, addr2: T::Address)
where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(transport, addr1, Arc::clone(&config)).await;

    pm1.peer_connectivity_handle.connect(addr2).await.expect("dial to succeed");

    match timeout(
        *pm1.p2p_config.outbound_connection_timeout,
        pm1.peer_connectivity_handle.poll_next(),
    )
    .await
    {
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

#[tokio::test]
async fn connection_timeout_tcp() {
    connection_timeout::<DefaultNetworkingService<TcpTransportSocket>>(
        TestTransportTcp::make_transport(),
        TestTransportTcp::make_address(),
        TestTransportTcp::make_address(),
    )
    .await;
}

#[tokio::test]
async fn connection_timeout_channels() {
    connection_timeout::<DefaultNetworkingService<MpscChannelTransport>>(
        TestTransportChannel::make_transport(),
        TestTransportChannel::make_address(),
        65_535,
    )
    .await;
}

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
    addr1: T::Address,
    addr2: T::Address,
) where
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(Default::default());
    let (conn, _) = T::start(
        transport,
        vec![addr1],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let (tx_sync, mut rx_sync) = tokio::sync::mpsc::unbounded_channel();

    let mut peer_manager = peer_manager::PeerManager::<T>::new(
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        conn,
        rx,
        tx_sync,
    )
    .unwrap();

    tokio::spawn(async move { while rx_sync.recv().await.is_some() {} });
    tokio::spawn(async move {
        peer_manager.run().await.unwrap();
    });

    let (rtx, rrx) = oneshot::channel();
    tx.send(PeerManagerEvent::Connect(addr2, rtx)).unwrap();

    match timeout(*p2p_config.outbound_connection_timeout, rrx).await {
        Ok(res) => assert!(std::matches!(
            res.unwrap(),
            Err(P2pError::DialError(DialError::ConnectionRefusedOrTimedOut))
        )),
        Err(_err) => panic!("did not receive `ConnectionError` in time"),
    }
}

#[tokio::test]
async fn connection_timeout_rpc_notified_tcp() {
    connection_timeout_rpc_notified::<DefaultNetworkingService<TcpTransportSocket>>(
        TestTransportTcp::make_transport(),
        TestTransportTcp::make_address(),
        TestTransportTcp::make_address(),
    )
    .await;
}

#[tokio::test]
async fn connection_timeout_rpc_notified_channels() {
    connection_timeout_rpc_notified::<DefaultNetworkingService<MpscChannelTransport>>(
        TestTransportChannel::make_transport(),
        TestTransportChannel::make_address(),
        9999,
    )
    .await;
}

#[tokio::test]
async fn connection_timeout_rpc_notified_noise() {
    connection_timeout_rpc_notified::<DefaultNetworkingService<NoiseTcpTransport>>(
        TestTransportNoise::make_transport(),
        TestTransportNoise::make_address(),
        TestTransportNoise::make_address(),
    )
    .await;
}

// verify that peer connection is made when valid add_node parameter is used
async fn connection_add_node<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let chain_config = Arc::new(config::create_mainnet());

    // Start first peer manager
    let p2p_config_1 = Arc::new(P2pConfig::default());
    let tx1 = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_1,
    )
    .await;

    // Get the first peer manager's bind address
    let (rtx, rrx) = oneshot::channel();
    tx1.send(PeerManagerEvent::GetBindAddresses(rtx)).unwrap();
    let bind_addresses = timeout(Duration::from_secs(1), rrx).await.unwrap().unwrap();
    assert_eq!(bind_addresses.len(), 1);

    // Start second peer manager and let it know about first manager via added_nodes
    let p2p_config_2 = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: bind_addresses,
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        node_type: Default::default(),
        discover_private_ips: Default::default(),
    });
    let tx1 = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_2,
    )
    .await;

    // The first peer manager must report new connection after some time
    let started_at = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (rtx, rrx) = oneshot::channel();
        tx1.send(PeerManagerEvent::GetConnectedPeers(rtx)).unwrap();
        let connected_peers = timeout(Duration::from_secs(1), rrx).await.unwrap().unwrap();
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

#[tokio::test]
async fn connection_add_node_tcp() {
    connection_add_node::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn connection_add_node_noise() {
    connection_add_node::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

#[tokio::test]
async fn connection_add_node_channel() {
    connection_add_node::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>()
        .await;
}

// Verify that peers announce own addresses and are discovered by other peers
async fn discovered_node<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let chain_config = Arc::new(config::create_mainnet());

    // Start the first peer manager
    let p2p_config_1 = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        node_type: Default::default(),
        discover_private_ips: true.into(),
    });
    let tx1 = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_1,
    )
    .await;

    // Get the first peer manager's bind address
    let (rtx, rrx) = oneshot::channel();
    tx1.send(PeerManagerEvent::GetBindAddresses(rtx)).unwrap();
    let bind_addresses = timeout(Duration::from_secs(1), rrx).await.unwrap().unwrap();
    assert_eq!(bind_addresses.len(), 1);

    // Start the second peer manager and let it know about first manager via added_nodes
    let p2p_config_2 = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: bind_addresses.clone(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        node_type: Default::default(),
        discover_private_ips: true.into(),
    });
    let tx2 = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_2,
    )
    .await;

    // Start the third peer manager and let it know about first manager via added_nodes
    let p2p_config_3 = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: bind_addresses,
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        node_type: Default::default(),
        discover_private_ips: true.into(),
    });
    let tx3 = run_peer_manager::<T>(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        p2p_config_3,
    )
    .await;

    let started_at = Instant::now();

    // The second peer manager should discover the third manager and connect to it
    // (or accept connection from it)
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (rtx, rrx) = oneshot::channel();
        tx2.send(PeerManagerEvent::GetConnectedPeers(rtx)).unwrap();
        let connected_peers = timeout(Duration::from_secs(1), rrx).await.unwrap().unwrap();
        // Connection to the first and the third managers
        if connected_peers.len() == 2 {
            break;
        }
        assert!(
            Instant::now().duration_since(started_at) < Duration::from_secs(10),
            "Unexpected peer count: {}",
            connected_peers.len()
        );
    }

    // The third peer manager should also report 2 connections
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (rtx, rrx) = oneshot::channel();
        tx3.send(PeerManagerEvent::GetConnectedPeers(rtx)).unwrap();
        let connected_peers = timeout(Duration::from_secs(1), rrx).await.unwrap().unwrap();
        if connected_peers.len() == 2 {
            break;
        }
        assert!(
            Instant::now().duration_since(started_at) < Duration::from_secs(10),
            "Unexpected peer count: {}",
            connected_peers.len()
        );
    }
}

#[tokio::test]
async fn discovered_node_tcp() {
    discovered_node::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn discovered_node_noise() {
    discovered_node::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

#[tokio::test]
async fn discovered_node_channel() {
    discovered_node::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>().await;
}
