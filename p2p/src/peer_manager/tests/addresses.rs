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

use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use p2p_test_utils::P2pBasicTestTimeGetter;

use crate::{
    config::NodeType,
    message::AnnounceAddrRequest,
    net::{
        default_backend::{
            transport::{MpscChannelTransport, TcpTransportSocket, TransportAddress},
            types::{Command, Message},
            ConnectivityHandle, DefaultNetworkingService,
        },
        types::{PeerInfo, Role},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{tests::make_peer_manager_custom, PeerManager, MAX_OUTBOUND_CONNECTIONS},
    protocol::NETWORK_PROTOCOL_CURRENT,
    testing_utils::{
        peerdb_inmemory_store, test_p2p_config, RandomAddressMaker, TestTcpAddressMaker,
        TestTransportChannel, TestTransportMaker,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    PeerManagerEvent,
};

async fn test_address_rate_limiter<A, T, B>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    B: RandomAddressMaker<Address = T::Address>,
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

    let address = B::new();
    let peer_id = PeerId::new();
    let peer_info = PeerInfo {
        peer_id,
        protocol: NETWORK_PROTOCOL_CURRENT,
        network: *config.magic_bytes(),
        version: *config.version(),
        user_agent: mintlayer_core_user_agent(),
        services: NodeType::Full.into(),
    };
    pm.accept_connection(address, Role::Inbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    let get_new_public_address = || loop {
        let address = B::new().as_peer_address();
        if T::Address::from_peer_address(&address, false).is_some() {
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
            pm.handle_announce_addr_request(peer_id, B::new().as_peer_address());
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
#[tokio::test]
async fn test_address_rate_limiter_channels() {
    test_address_rate_limiter::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
        TestTcpAddressMaker,
    >()
    .await;
}

#[test]
fn test_addr_list_handling_inbound() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) =
        tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent<TestNetworkingService>>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle = ConnectivityHandle::<TestNetworkingService, TcpTransportSocket>::new(
        vec![],
        cmd_tx,
        conn_rx,
    );

    let mut pm = PeerManager::new(
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
        protocol: NETWORK_PROTOCOL_CURRENT,
        network: *chain_config.magic_bytes(),
        version: *chain_config.version(),
        user_agent: mintlayer_core_user_agent(),
        services: NodeType::Full.into(),
    };
    pm.accept_connection(TestTcpAddressMaker::new(), Role::Inbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    // Peer is accepted by the peer manager
    match cmd_rx.try_recv() {
        Ok(Command::Accept { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // Peer manager sends response normally to first address list request
    pm.handle_addr_list_request(peer_id_1);
    match cmd_rx.try_recv() {
        Ok(Command::SendMessage { peer, message: Message::AddrListResponse(_) })
            if peer == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // Other requests are ignored but the peer is not scored
    pm.handle_addr_list_request(peer_id_1);
    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }
    assert_eq!(pm.peers.get(&peer_id_1).unwrap().score, 0);

    // Check that the peer is scored if it tries to send an unexpected address list response
    pm.handle_addr_list_response(peer_id_1, vec![TestTcpAddressMaker::new().as_peer_address()]);
    assert_ne!(pm.peers.get(&peer_id_1).unwrap().score, 0);
}

#[test]
fn test_addr_list_handling_outbound() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) =
        tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent<TestNetworkingService>>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle = ConnectivityHandle::<TestNetworkingService, TcpTransportSocket>::new(
        vec![],
        cmd_tx,
        conn_rx,
    );

    let mut pm = PeerManager::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_rx,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id_1 = PeerId::new();
    let peer_address = TestTcpAddressMaker::new();
    let peer_info = PeerInfo {
        peer_id: peer_id_1,
        protocol: NETWORK_PROTOCOL_CURRENT,
        network: *chain_config.magic_bytes(),
        version: *chain_config.version(),
        user_agent: mintlayer_core_user_agent(),
        services: NodeType::Full.into(),
    };
    pm.connect(peer_address, None);

    // New peer connection is requested
    match cmd_rx.try_recv() {
        Ok(Command::Connect { address }) if address == peer_address => {}
        v => panic!("unexpected command: {v:?}"),
    }

    pm.accept_connection(peer_address, Role::Outbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    // Peer is accepted by the peer manager
    match cmd_rx.try_recv() {
        Ok(Command::Accept { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // Address list is requested from the connected peer
    match cmd_rx.try_recv() {
        Ok(Command::SendMessage { peer, message: Message::AddrListRequest(_) })
            if peer == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // Check that the address list response is processed normally and that the peer is not scored
    pm.handle_addr_list_response(peer_id_1, vec![TestTcpAddressMaker::new().as_peer_address()]);
    assert_eq!(pm.peers.get(&peer_id_1).unwrap().score, 0);

    // No more messages
    match cmd_rx.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // Check that the peer is scored if it tries to send an unexpected address list response
    pm.handle_addr_list_response(peer_id_1, vec![TestTcpAddressMaker::new().as_peer_address()]);
    assert_ne!(pm.peers.get(&peer_id_1).unwrap().score, 0);
}

// Verify that the node periodically resends its own address
#[tokio::test]
async fn resend_own_addresses() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    // The addresses on which the node is listening
    let listening_addresses: Vec<std::net::SocketAddr> =
        vec!["1.2.3.4:3031".parse().unwrap(), "[2001:bc8:1600::1]:3031".parse().unwrap()];

    // Outbound connections normally use random ports
    let outbound_address_1: std::net::SocketAddr = "1.2.3.4:12345".parse().unwrap();
    let outbound_address_2: std::net::SocketAddr = "[2001:bc8:1600::1]:23456".parse().unwrap();

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) =
        tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent<TestNetworkingService>>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle = ConnectivityHandle::<TestNetworkingService, TcpTransportSocket>::new(
        listening_addresses.clone(),
        cmd_tx,
        conn_rx,
    );

    let mut pm = PeerManager::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_rx,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    for peer_index in 0..MAX_OUTBOUND_CONNECTIONS {
        let new_peer_id = PeerId::new();
        let peer_address = TestTcpAddressMaker::new();
        let peer_info = PeerInfo {
            peer_id: new_peer_id,
            protocol: NETWORK_PROTOCOL_CURRENT,
            network: *chain_config.magic_bytes(),
            version: *chain_config.version(),
            user_agent: mintlayer_core_user_agent(),
            services: NodeType::Full.into(),
        };
        pm.connect(peer_address, None);

        // New peer connection is requested
        while !matches!(cmd_rx.try_recv().unwrap(), Command::Connect { address: _ }) {}

        let own_ip = if peer_index % 2 == 0 {
            outbound_address_1
        } else {
            outbound_address_2
        };

        pm.accept_connection(peer_address, Role::Outbound, peer_info, Some(own_ip.into()));
    }
    assert_eq!(pm.peers.len(), MAX_OUTBOUND_CONNECTIONS);

    let (started_tx, started_rx) = oneshot_nofail::channel();
    tokio::spawn(async move { pm.run_internal(Some(started_tx)).await });
    started_rx.await.unwrap();

    // Flush all pending messages
    while cmd_rx.try_recv().is_ok() {}

    // Advance the current time by 5 days (resends are not deterministic, but this should be more than enough)
    time_getter.advance_time(Duration::from_secs(5 * 24 * 60 * 60));

    // PeerManager should resend own addresses
    let mut listening_addresses = listening_addresses.into_iter().collect::<BTreeSet<_>>();
    while !listening_addresses.is_empty() {
        let event = tokio::time::timeout(Duration::from_secs(60), cmd_rx.recv())
            .await
            .unwrap()
            .unwrap();

        if let Command::SendMessage {
            peer: _,
            message: Message::AnnounceAddrRequest(AnnounceAddrRequest { address }),
        } = event
        {
            let announced_addr: SocketAddr =
                TransportAddress::from_peer_address(&address, false).unwrap();
            listening_addresses.remove(&announced_addr);
        }
    }
}
