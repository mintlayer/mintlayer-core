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

use std::{net::IpAddr, sync::Arc, time::Duration};

use p2p_types::socket_address::SocketAddress;
use rstest::rstest;

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use networking::test_helpers::{
    TestAddressMaker, TestTransportChannel, TestTransportMaker, TestTransportNoise,
    TestTransportTcp,
};
use networking::{
    transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
    types::ConnectionDirection,
};
use p2p_types::bannable_address::BannableAddress;
use test_utils::{
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};
use utils::atomics::SeqCstAtomicBool;

use crate::{
    config::{NodeType, P2pConfig},
    disconnection_reason::DisconnectionReason,
    net::{
        default_backend::{types::Command, ConnectivityHandle, DefaultNetworkingService},
        types::{PeerInfo, PeerRole},
        ConnectivityService, NetworkingService,
    },
    peer_manager::{
        peerdb::{salt::Salt, storage::PeerDbStorageWrite, CURRENT_STORAGE_VERSION},
        peerdb_common::storage::{TransactionRw, Transactional},
        tests::{make_peer_manager, make_peer_manager_custom},
        PeerManager,
    },
    test_helpers::{connect_services, peerdb_inmemory_store, TEST_PROTOCOL_VERSION},
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    PeerManagerEvent,
};

fn p2p_config_with_whitelisted(whitelisted_addresses: Vec<IpAddr>) -> P2pConfig {
    P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses,
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
    }
}

async fn no_automatic_ban_for_whitelisted<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1: SocketAddress = A::make_address().into();
    let addr2 = A::make_address().into();

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(p2p_config_with_whitelisted(vec![addr1.ip_addr()]));

    let (mut pm1, _, _shutdown_sender, _subscribers_sender) = make_peer_manager_custom::<T>(
        A::make_transport(),
        addr1,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        Default::default(),
    )
    .await;

    let (mut pm2, _, _shutdown_sender, _subscribers_sender) = make_peer_manager_custom::<T>(
        A::make_transport(),
        addr2,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        Default::default(),
    )
    .await;

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    let peer_id = peer_info.peer_id;
    pm2.accept_connection(
        address,
        pm2.peer_connectivity_handle.local_addresses()[0],
        ConnectionDirection::Inbound,
        peer_info,
        None,
    );

    assert!(pm2.is_whitelisted_node(PeerRole::Inbound, &addr1));

    // automatic ban
    pm2.adjust_peer_score(peer_id, 1000);
    assert!(!pm2.peerdb.is_address_banned(&addr1.as_bannable()));
}

#[tracing::instrument]
#[tokio::test]
async fn no_automatic_ban_for_whitelisted_tcp() {
    no_automatic_ban_for_whitelisted::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn no_automatic_ban_for_whitelisted_channels() {
    no_automatic_ban_for_whitelisted::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn no_automatic_ban_for_whitelisted_noise() {
    no_automatic_ban_for_whitelisted::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

// if an address was banned it won't be unbanned automatically if whitelisted
async fn no_automatic_unban_for_whitelisted<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let addr1 = A::make_address().into();
    let addr2: SocketAddress = A::make_address().into();

    let chain_config = Arc::new(config::create_unit_test_config());

    let (mut pm1, _shutdown_sender, _subscribers_sender) =
        make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&chain_config)).await;

    let p2p_config = Arc::new(p2p_config_with_whitelisted(vec![
        addr1.ip_addr(),
        addr2.ip_addr(),
    ]));
    let (_peer_sender, peer_receiver) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = BasicTestTimeGetter::new();
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (_shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (connectivity_handle, _, _, _) = T::start(
        true,
        A::make_transport(),
        vec![addr2],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        Default::default(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();
    // add banned localhost to the storage
    let db = {
        let db = peerdb_inmemory_store();
        let ban_until = time_getter
            .get_time_getter()
            .get_time()
            .saturating_duration_add(Duration::from_secs(60));

        let mut tx = db.transaction_rw().unwrap();
        tx.set_version(CURRENT_STORAGE_VERSION).unwrap();
        tx.set_salt(Salt::new_random()).unwrap();
        tx.add_banned_address(&BannableAddress::new(addr1.ip_addr()), ban_until)
            .unwrap();
        tx.commit().unwrap();
        db
    };

    let mut pm2 = PeerManager::<T, _>::new(
        true,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_receiver,
        time_getter.get_time_getter(),
        db,
    )
    .unwrap();

    let (address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    pm2.accept_connection(
        address,
        pm2.peer_connectivity_handle.local_addresses()[0],
        ConnectionDirection::Inbound,
        peer_info,
        None,
    );

    // address is whitelisted and still banned
    assert!(pm2.peerdb.is_address_banned(&addr1.as_bannable()));
    assert!(pm2.is_whitelisted_node(PeerRole::Inbound, &addr1));
}

#[tracing::instrument]
#[tokio::test]
async fn no_automatic_unban_for_whitelisted_tcp() {
    no_automatic_unban_for_whitelisted::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn no_automatic_unban_for_whitelisted_channels() {
    no_automatic_unban_for_whitelisted::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn no_automatic_unban_for_whitelisted_noise() {
    no_automatic_unban_for_whitelisted::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn manual_ban_overrides_whitelisting(#[case] seed: Seed) {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;
    let mut rng = make_seedable_rng(seed);
    let address_1: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();
    let address_2 = TestAddressMaker::new_random_address(&mut rng).into();

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(p2p_config_with_whitelisted(vec![address_1.ip_addr()]));
    let (cmd_sender, mut cmd_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_sender, conn_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_sender, peer_receiver) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = BasicTestTimeGetter::new();
    let connectivity_handle = ConnectivityHandle::<TestNetworkingService>::new(
        vec![address_2],
        cmd_sender,
        conn_receiver,
    );

    let mut pm = PeerManager::<TestNetworkingService, _>::new(
        true,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_receiver,
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
        address_1,
        pm.peer_connectivity_handle.local_addresses()[0],
        ConnectionDirection::Inbound,
        peer_info,
        None,
    );
    assert_eq!(pm.peers.len(), 1);

    // Peer is accepted by the peer manager
    match cmd_receiver.try_recv() {
        Ok(Command::Accept { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    assert!(pm.is_whitelisted_node(PeerRole::Inbound, &address_1));

    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm.handle_control_event(PeerManagerEvent::Ban(
        address_1.as_bannable(),
        Duration::from_secs(60 * 60),
        ban_sender,
    ));
    ban_receiver.try_recv().unwrap().unwrap();

    // Peer is disconnected by the peer manager
    match cmd_receiver.try_recv() {
        Ok(Command::Disconnect { peer_id, reason }) if peer_id == peer_id_1 => {
            assert_eq!(reason, Some(DisconnectionReason::AddressBanned));
        }
        v => panic!("unexpected command: {v:?}"),
    }

    // No more messages
    match cmd_receiver.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }
}
