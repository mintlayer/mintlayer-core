// Copyright (c) 2023 RBB S.r.l
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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use p2p_test_utils::P2pBasicTestTimeGetter;
use p2p_types::socket_address::SocketAddress;
use test_utils::assert_matches;

use crate::{
    config::{NodeType, P2pConfig},
    message::{AnnounceAddrRequest, PeerManagerMessage},
    net::{
        default_backend::{
            transport::{MpscChannelTransport, TcpTransportSocket},
            types::{CategorizedMessage, Command},
            ConnectivityHandle, DefaultNetworkingService,
        },
        types::{PeerInfo, Role},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{
        tests::{make_peer_manager_custom, utils::cmd_to_peer_man_msg},
        OutboundConnectType, PeerManager,
    },
    testing_utils::{
        peerdb_inmemory_store, test_p2p_config, TestAddressMaker, TestTransportChannel,
        TestTransportMaker, TEST_PROTOCOL_VERSION,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    PeerManagerEvent,
};

async fn test_address_rate_limiter<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr = A::make_address();
    let config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let time_getter = P2pBasicTestTimeGetter::new();
    let (mut pm, _tx, _shutdown_sender, _subscribers_sender) = make_peer_manager_custom::<T>(
        A::make_transport(),
        addr,
        Arc::clone(&config),
        p2p_config,
        time_getter.get_time_getter(),
    )
    .await;

    let address = TestAddressMaker::new_random_address();
    let peer_id = PeerId::new();
    let peer_info = PeerInfo {
        peer_id,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *config.magic_bytes(),
        software_version: *config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::Full.into(),
    };
    pm.accept_connection(address, Role::Inbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    let get_new_public_address = || loop {
        let address = TestAddressMaker::new_random_address().as_peer_address();
        if SocketAddress::from_peer_address(&address, false).is_some() {
            return address;
        }
    };

    // Check that nodes are allowed to send own address immediately after connecting
    let address = get_new_public_address();
    pm.handle_announce_addr_request(peer_id, address);
    let accepted_count = pm.peerdb.known_addresses().count();
    assert_eq!(accepted_count, 1);

    for _ in 0..120 {
        time_getter.advance_time(Duration::from_secs(1));
        for _ in 0..100 {
            pm.handle_announce_addr_request(
                peer_id,
                TestAddressMaker::new_random_address().as_peer_address(),
            );
        }
    }
    let accepted_count = pm.peerdb.known_addresses().count();
    // The average expected count is 13 (1 + 120 * 0.1), but the exact number is not very important
    assert!(
        (5..25).contains(&accepted_count),
        "Unexpected accepted address count: {accepted_count}"
    );
}

// Test only TestTransportChannel because actual networking is not used
#[tracing::instrument]
#[tokio::test]
async fn test_address_rate_limiter_channels() {
    test_address_rate_limiter::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[test]
fn test_addr_list_handling_inbound() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle =
        ConnectivityHandle::<TestNetworkingService>::new(vec![], cmd_tx, conn_rx);

    let mut pm = PeerManager::<TestNetworkingService, _>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_rx,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id_1 = PeerId::new();
    let peer_info = PeerInfo {
        peer_id: peer_id_1,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::Full.into(),
    };
    pm.accept_connection(
        TestAddressMaker::new_random_address(),
        Role::Inbound,
        peer_info,
        None,
    );
    assert_eq!(pm.peers.len(), 1);

    // Peer is accepted by the peer manager
    match cmd_rx.try_recv() {
        Ok(Command::Accept { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected result: {v:?}"),
    }

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected result: {v:?}"),
    }

    // Peer manager sends response normally to first address list request
    pm.handle_addr_list_request(peer_id_1);
    let cmd = cmd_rx.try_recv().unwrap();
    let (peer_id, peer_msg) = cmd_to_peer_man_msg(cmd);
    assert_eq!(peer_id, peer_id_1);
    assert_matches!(peer_msg, PeerManagerMessage::AddrListResponse(_));

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected result: {v:?}"),
    }

    // Other requests are ignored but the peer is not scored
    pm.handle_addr_list_request(peer_id_1);
    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected result: {v:?}"),
    }
    assert_eq!(pm.peers.get(&peer_id_1).unwrap().score, 0);

    // Check that the peer is scored if it tries to send an unexpected address list response
    pm.handle_addr_list_response(
        peer_id_1,
        vec![TestAddressMaker::new_random_address().as_peer_address()],
    );
    assert_ne!(pm.peers.get(&peer_id_1).unwrap().score, 0);
}

#[tracing::instrument]
#[test]
fn test_addr_list_handling_outbound() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(P2pConfig {
        enable_block_relay_peers: false.into(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        sync_stalling_timeout: Default::default(),
        connection_count_limits: Default::default(),
    });
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle =
        ConnectivityHandle::<TestNetworkingService>::new(vec![], cmd_tx, conn_rx);

    let mut pm = PeerManager::<TestNetworkingService, _>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_rx,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id_1 = PeerId::new();
    let peer_address = TestAddressMaker::new_random_address();
    let peer_info = PeerInfo {
        peer_id: peer_id_1,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::Full.into(),
    };
    pm.connect(peer_address, OutboundConnectType::Automatic);

    // New peer connection is requested
    match cmd_rx.try_recv() {
        Ok(Command::Connect {
            address,
            local_services_override: _,
        }) if address == peer_address => {}
        v => panic!("unexpected result: {v:?}"),
    }

    pm.accept_connection(peer_address, Role::Outbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    // Peer is accepted by the peer manager
    match cmd_rx.try_recv() {
        Ok(Command::Accept { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected result: {v:?}"),
    }

    // Address list is requested from the connected peer
    let cmd = cmd_rx.try_recv().unwrap();
    let (peer_id, peer_msg) = cmd_to_peer_man_msg(cmd);
    assert_eq!(peer_id, peer_id_1);
    assert_matches!(peer_msg, PeerManagerMessage::AddrListRequest(_));

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected result: {v:?}"),
    }

    // Check that the address list response is processed normally and that the peer is not scored
    pm.handle_addr_list_response(
        peer_id_1,
        vec![TestAddressMaker::new_random_address().as_peer_address()],
    );
    assert_eq!(pm.peers.get(&peer_id_1).unwrap().score, 0);

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected result: {v:?}"),
    }

    // Check that the peer is scored if it tries to send an unexpected address list response
    pm.handle_addr_list_response(
        peer_id_1,
        vec![TestAddressMaker::new_random_address().as_peer_address()],
    );
    assert_ne!(pm.peers.get(&peer_id_1).unwrap().score, 0);
}

// Verify that the node periodically resends its own address
#[tracing::instrument]
#[tokio::test]
async fn resend_own_addresses() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    // The addresses on which the node is listening
    let listening_addresses: Vec<SocketAddress> =
        vec!["1.2.3.4:3031".parse().unwrap(), "[2001:bc8:1600::1]:3031".parse().unwrap()];

    // Outbound connections normally use random ports
    let outbound_address_1: std::net::SocketAddr = "1.2.3.4:12345".parse().unwrap();
    let outbound_address_2: std::net::SocketAddr = "[2001:bc8:1600::1]:23456".parse().unwrap();

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle = ConnectivityHandle::<TestNetworkingService>::new(
        listening_addresses.clone(),
        cmd_tx,
        conn_rx,
    );

    let mut pm = PeerManager::<TestNetworkingService, _>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_rx,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_count = p2p_config.connection_count_limits.outbound_full_and_block_relay_count();
    for peer_index in 0..peer_count {
        let new_peer_id = PeerId::new();
        let peer_address = TestAddressMaker::new_random_address();
        let peer_info = PeerInfo {
            peer_id: new_peer_id,
            protocol_version: TEST_PROTOCOL_VERSION,
            network: *chain_config.magic_bytes(),
            software_version: *chain_config.software_version(),
            user_agent: mintlayer_core_user_agent(),
            common_services: NodeType::Full.into(),
        };
        pm.connect(peer_address, OutboundConnectType::Reserved);

        // New peer connection is requested
        while !matches!(
            cmd_rx.try_recv().unwrap(),
            Command::Connect {
                address: _,
                local_services_override: _
            }
        ) {}

        let own_ip = if peer_index % 2 == 0 {
            outbound_address_1
        } else {
            outbound_address_2
        };

        pm.accept_connection(peer_address, Role::Outbound, peer_info, Some(own_ip.into()));
    }
    assert_eq!(pm.peers.len(), peer_count);

    let (started_tx, started_rx) = oneshot_nofail::channel();
    logging::spawn_in_current_span(async move { pm.run_internal(Some(started_tx)).await });
    started_rx.await.unwrap();

    // Flush all pending messages
    while cmd_rx.try_recv().is_ok() {}

    // Advance the current time by 5 days (resends are not deterministic, but this should be more than enough)
    time_getter.advance_time(Duration::from_secs(5 * 24 * 60 * 60));

    // PeerManager should resend own addresses
    let mut listening_addresses = listening_addresses.into_iter().collect::<BTreeSet<_>>();
    while !listening_addresses.is_empty() {
        let cmd = tokio::time::timeout(Duration::from_secs(60), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();

        if let Command::SendMessage {
            peer_id: _,
            message,
        } = cmd
        {
            if let CategorizedMessage::PeerManagerMessage(
                PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest { address }),
            ) = message.categorize()
            {
                let announced_addr = SocketAddress::from_peer_address(&address, false).unwrap();
                listening_addresses.remove(&announced_addr);
            }
        }
    }
}
