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

use std::sync::Arc;

use crate::{
    net::types::{services::Service, Role},
    protocol::{NETWORK_PROTOCOL_CURRENT, NETWORK_PROTOCOL_MIN},
    testing_utils::{
        connect_and_accept_services, connect_services, get_connectivity_event, RandomAddressMaker,
        TestChannelAddressMaker, TestTcpAddressMaker, TestTransportChannel, TestTransportMaker,
        TestTransportNoise, TestTransportTcp,
    },
    types::peer_id::PeerId,
    utils::oneshot_nofail,
};
use common::{
    chain::config,
    primitives::{semver::SemVer, user_agent::mintlayer_core_user_agent},
};

use crate::{
    error::{P2pError, PeerError},
    net::{
        self,
        default_backend::{
            transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            DefaultNetworkingService,
        },
        AsBannableAddress, ConnectivityService, NetworkingService,
    },
    peer_manager::tests::make_peer_manager,
};

// ban peer whose connected to us
async fn ban_connected_peer<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
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

    pm2.adjust_peer_score(peer_id, 1000);
    let addr1 = pm1.peer_connectivity_handle.local_addresses()[0].clone().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    assert!(std::matches!(
        event,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn ban_connected_peer_tcp() {
    ban_connected_peer::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn ban_connected_peer_channels() {
    ban_connected_peer::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>()
        .await;
}

#[tokio::test]
async fn ban_connected_peer_noise() {
    ban_connected_peer::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

async fn banned_peer_attempts_to_connect<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + std::fmt::Debug + 'static,
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

    pm2.adjust_peer_score(peer_id, 1000);
    let addr1 = pm1.peer_connectivity_handle.local_addresses()[0].clone().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    assert!(std::matches!(
        event,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_tcp() {
    banned_peer_attempts_to_connect::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_channel() {
    banned_peer_attempts_to_connect::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_noise() {
    banned_peer_attempts_to_connect::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}

// attempt to connect to banned peer
async fn connect_to_banned_peer<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
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

    let (address, peer_info1, _peer_info2) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    let peer_id = peer_info1.peer_id;
    pm2.accept_connection(address, Role::Inbound, peer_info1, None);

    let remote_addr = pm1.peer_connectivity_handle.local_addresses()[0].clone();

    pm2.adjust_peer_score(peer_id, 10);
    assert!(!pm2.peerdb.is_address_banned(&remote_addr.as_bannable()));

    pm2.adjust_peer_score(peer_id, 90);
    assert!(pm2.peerdb.is_address_banned(&remote_addr.as_bannable()));

    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    match &event {
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. }) => {}
        _ => panic!("unexpected event: {event:?}"),
    }
    pm2.handle_connectivity_event(event.unwrap());

    let (tx, rx) = oneshot_nofail::channel();
    pm2.connect(remote_addr, Some(tx));
    let res = rx.await.unwrap();
    match res {
        Err(P2pError::PeerError(PeerError::BannedAddress(_))) => {}
        _ => panic!("unexpected result: {res:?}"),
    }
}

#[tokio::test]
async fn connect_to_banned_peer_tcp() {
    connect_to_banned_peer::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>()
        .await;
}

#[tokio::test]
async fn connect_to_banned_peer_channels() {
    connect_to_banned_peer::<TestTransportChannel, DefaultNetworkingService<MpscChannelTransport>>(
    )
    .await;
}

#[tokio::test]
async fn connect_to_banned_peer_noise() {
    connect_to_banned_peer::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>()
        .await;
}

async fn validate_invalid_connection<A, S, B>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + std::fmt::Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    B: RandomAddressMaker<Address = S::Address>,
{
    for role in [Role::Outbound, Role::Inbound] {
        let config = Arc::new(config::create_mainnet());
        let (mut peer_manager, _shutdown_sender, _subscribers_sender) =
            make_peer_manager::<S>(A::make_transport(), A::make_address(), Arc::clone(&config))
                .await;

        // invalid protocol
        let peer_id = PeerId::new();
        let res = peer_manager.try_accept_connection(
            B::new(),
            role,
            net::types::PeerInfo {
                peer_id,
                protocol: 0,
                network: *config.magic_bytes(),
                version: *config.version(),
                user_agent: mintlayer_core_user_agent(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
            },
            None,
        );
        assert!(res.is_err());
        assert!(!peer_manager.is_peer_connected(peer_id));

        // invalid magic bytes
        let peer_id = PeerId::new();
        let res = peer_manager.try_accept_connection(
            B::new(),
            role,
            net::types::PeerInfo {
                peer_id,
                protocol: NETWORK_PROTOCOL_CURRENT,
                network: [1, 2, 3, 4],
                version: *config.version(),
                user_agent: mintlayer_core_user_agent(),
                services: [Service::Blocks, Service::Transactions].as_slice().into(),
            },
            None,
        );
        assert!(res.is_err());
        assert!(!peer_manager.is_peer_connected(peer_id));

        // valid connections
        const NETWORK_PROTOCOL_FUTURE: u32 = u32::MAX; // Some future version of the node is trying to connect to us
        for protocol in [NETWORK_PROTOCOL_CURRENT, NETWORK_PROTOCOL_MIN, NETWORK_PROTOCOL_FUTURE] {
            let address = B::new();
            let peer_id = PeerId::new();
            let res = peer_manager.try_accept_connection(
                address.clone(),
                role,
                net::types::PeerInfo {
                    peer_id,
                    protocol,
                    network: *config.magic_bytes(),
                    version: SemVer::new(123, 123, 12345),
                    user_agent: mintlayer_core_user_agent(),
                    services: [Service::Blocks, Service::Transactions].as_slice().into(),
                },
                None,
            );
            assert!(res.is_ok());
            assert!(peer_manager.is_peer_connected(peer_id));
            assert!(!peer_manager.peerdb.is_address_banned(&address.as_bannable()));
        }
    }
}

#[tokio::test]
async fn validate_invalid_connection_tcp() {
    validate_invalid_connection::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
        TestTcpAddressMaker,
    >()
    .await;
}

#[tokio::test]
async fn validate_invalid_connection_channels() {
    validate_invalid_connection::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
        TestChannelAddressMaker,
    >()
    .await;
}

#[tokio::test]
async fn validate_invalid_connection_noise() {
    validate_invalid_connection::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
        TestTcpAddressMaker,
    >()
    .await;
}

async fn inbound_connection_invalid_magic<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
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

    let (_address, peer_info, _) = connect_and_accept_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    tokio::spawn(async move { pm1.run().await });

    let event = get_connectivity_event::<T>(&mut pm2.peer_connectivity_handle).await;
    match event {
        Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id })
            if peer_id == peer_info.peer_id => {}
        _ => panic!("unexpected event: {event:?}"),
    }
}

#[tokio::test]
async fn inbound_connection_invalid_magic_tcp() {
    inbound_connection_invalid_magic::<
        TestTransportTcp,
        DefaultNetworkingService<TcpTransportSocket>,
    >()
    .await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_channels() {
    inbound_connection_invalid_magic::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_noise() {
    inbound_connection_invalid_magic::<
        TestTransportNoise,
        DefaultNetworkingService<NoiseTcpTransport>,
    >()
    .await;
}
