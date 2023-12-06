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

use std::sync::Arc;

use crate::{
    config::NodeType,
    net::{
        default_backend::{types::Command, ConnectivityHandle},
        types::{PeerInfo, Role},
    },
    peer_manager::PeerManager,
    testing_utils::{
        connect_services, peerdb_inmemory_store, test_p2p_config, TestAddressMaker,
        TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
        TEST_PROTOCOL_VERSION,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    PeerManagerEvent,
};
use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use p2p_test_utils::P2pBasicTestTimeGetter;

use crate::{
    net::{
        default_backend::{
            transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            DefaultNetworkingService,
        },
        ConnectivityService, NetworkingService,
    },
    peer_manager::tests::make_peer_manager,
};

async fn no_automatic_ban_for_whitelisted<A, T>()
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
    let peer_id = peer_info.peer_id;
    pm2.accept_connection(address, Role::Inbound, peer_info, None);

    let addr1 = pm1.peer_connectivity_handle.local_addresses()[0];

    assert!(!pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));

    // whitelist
    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm2.handle_control_event(PeerManagerEvent::Whitelist(addr1.ip_addr(), ban_sender));
    ban_receiver.try_recv().unwrap().unwrap();
    assert!(pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));

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
    let peer_id = peer_info.peer_id;
    pm2.accept_connection(address, Role::Inbound, peer_info, None);

    let addr1 = pm1.peer_connectivity_handle.local_addresses()[0];

    // automatic ban
    pm2.adjust_peer_score(peer_id, 1000);
    assert!(pm2.peerdb.is_address_banned(&addr1.as_bannable()));
    assert!(!pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));

    // add to whitelist
    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm2.handle_control_event(PeerManagerEvent::Whitelist(addr1.ip_addr(), ban_sender));
    ban_receiver.try_recv().unwrap().unwrap();

    // address is not whitelisted but still banned
    assert!(pm2.peerdb.is_address_banned(&addr1.as_bannable()));
    assert!(pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));
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

// if an address was banned it won't be unbanned automatically if whitelisted
async fn remove_from_whitelisted<A, T>()
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
    let peer_id = peer_info.peer_id;
    pm2.accept_connection(address, Role::Inbound, peer_info, None);

    let addr1 = pm1.peer_connectivity_handle.local_addresses()[0];

    assert!(!pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));

    // add to whitelist
    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm2.handle_control_event(PeerManagerEvent::Whitelist(addr1.ip_addr(), ban_sender));
    ban_receiver.try_recv().unwrap().unwrap();
    assert!(pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));

    // try ban
    pm2.adjust_peer_score(peer_id, 1000);
    assert!(!pm2.peerdb.is_address_banned(&addr1.as_bannable()));

    // remove from whitelist
    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm2.handle_control_event(PeerManagerEvent::Unwhitelist(addr1.ip_addr(), ban_sender));
    ban_receiver.try_recv().unwrap().unwrap();
    assert!(!pm2.peerdb().is_whitelisted_node(&addr1.ip_addr()));

    // ban
    pm2.adjust_peer_score(peer_id, 1000);
    assert!(pm2.peerdb.is_address_banned(&addr1.as_bannable()));
}

#[tracing::instrument]
#[tokio::test]
async fn remove_from_whitelisted_tcp() {
    remove_from_whitelisted::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>()
        .await;
}

#[tracing::instrument]
#[tokio::test]
async fn remove_from_whitelisted_channels() {
    remove_from_whitelisted::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tracing::instrument]
#[tokio::test]
async fn remove_from_whitelisted_noise() {
    remove_from_whitelisted::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>()
        .await;
}

#[tracing::instrument]
#[test]
fn manual_ban_overrides_whitelisting() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (cmd_sender, mut cmd_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (_conn_sender, conn_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_sender, peer_receiver) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle =
        ConnectivityHandle::<TestNetworkingService>::new(vec![], cmd_sender, conn_receiver);

    let mut pm = PeerManager::<TestNetworkingService, _>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_receiver,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id_1 = PeerId::new();
    let address_1 = TestAddressMaker::new_random_address();
    let peer_info = PeerInfo {
        peer_id: peer_id_1,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::Full.into(),
    };
    pm.accept_connection(address_1, Role::Inbound, peer_info, None);
    assert_eq!(pm.peers.len(), 1);

    // Peer is accepted by the peer manager
    match cmd_receiver.try_recv() {
        Ok(Command::Accept { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    assert!(!pm.peerdb().is_whitelisted_node(&address_1.ip_addr()));

    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm.handle_control_event(PeerManagerEvent::Whitelist(address_1.ip_addr(), ban_sender));
    ban_receiver.try_recv().unwrap().unwrap();

    assert!(pm.peerdb().is_whitelisted_node(&address_1.ip_addr()));

    let (ban_sender, mut ban_receiver) = oneshot_nofail::channel();
    pm.handle_control_event(PeerManagerEvent::Ban(address_1.as_bannable(), ban_sender));
    ban_receiver.try_recv().unwrap().unwrap();

    // Peer is disconnected by the peer manager
    match cmd_receiver.try_recv() {
        Ok(Command::Disconnect { peer_id }) if peer_id == peer_id_1 => {}
        v => panic!("unexpected command: {v:?}"),
    }

    // No more messages
    match cmd_receiver.try_recv() {
        Err(_) => {}
        v => panic!("unexpected command: {v:?}"),
    }
}
