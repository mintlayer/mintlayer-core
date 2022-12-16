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

use crate::testing_utils::{
    TestTransportChannel, TestTransportLibp2p, TestTransportMaker, TestTransportNoise,
    TestTransportTcp,
};
use common::{chain::config, primitives::semver::SemVer};

use crate::{
    error::{P2pError, PeerError},
    net::{
        self,
        libp2p::Libp2pService,
        mock::{
            transport::{MockChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            types::MockPeerId,
            MockService,
        },
        types::{Protocol, ProtocolType, PubSubTopic},
        AsBannableAddress, ConnectivityService, NetworkingService,
    },
    peer_manager::helpers::connect_services,
    peer_manager::tests::{default_protocols, make_peer_manager},
};

// ban peer whose connected to us
async fn ban_connected_peer<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
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
    let peer_id = peer_info.peer_id;
    pm2.accept_inbound_connection(address, peer_info).unwrap();

    assert_eq!(pm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    let addr1 = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    assert!(std::matches!(
        pm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn ban_connected_peer_libp2p() {
    ban_connected_peer::<TestTransportLibp2p, Libp2pService>().await;
}

#[tokio::test]
async fn ban_connected_peer_mock_tcp() {
    ban_connected_peer::<TestTransportTcp, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn ban_connected_peer_mock_channels() {
    ban_connected_peer::<TestTransportChannel, MockService<MockChannelTransport>>().await;
}

#[tokio::test]
async fn ban_connected_peer_mock_noise() {
    ban_connected_peer::<TestTransportNoise, MockService<NoiseTcpTransport>>().await;
}

async fn banned_peer_attempts_to_connect<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + std::fmt::Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
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
    let peer_id = peer_info.peer_id;
    pm2.accept_inbound_connection(address, peer_info).unwrap();

    assert_eq!(pm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    let addr1 = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    assert!(std::matches!(
        pm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_libp2p() {
    banned_peer_attempts_to_connect::<TestTransportLibp2p, Libp2pService>().await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_tcp() {
    banned_peer_attempts_to_connect::<TestTransportTcp, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_channel() {
    banned_peer_attempts_to_connect::<TestTransportChannel, MockService<MockChannelTransport>>()
        .await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_noise() {
    banned_peer_attempts_to_connect::<TestTransportNoise, MockService<NoiseTcpTransport>>().await;
}

// attempt to connect to banned peer
async fn connect_to_banned_peer<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(A::make_transport(), addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(A::make_transport(), addr2, config).await;

    let (address, peer_info1, _peer_info2) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    let peer_id = peer_info1.peer_id;
    pm2.accept_inbound_connection(address, peer_info1).unwrap();

    assert_eq!(pm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    let addr1 = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    assert!(matches!(
        pm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    let remote_addr = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap();

    tokio::spawn(async move {
        loop {
            let _ = pm1.peer_connectivity_handle.poll_next().await.unwrap();
        }
    });

    pm2.peer_connectivity_handle.connect(remote_addr.clone()).await.unwrap();
    if let Ok(net::types::ConnectivityEvent::ConnectionError { address, error }) =
        pm2.peer_connectivity_handle.poll_next().await
    {
        assert_eq!(remote_addr, address);
        assert!(matches!(
            error,
            P2pError::PeerError(PeerError::BannedPeer(_))
        ));
    }
}

#[tokio::test]
async fn connect_to_banned_peer_libp2p() {
    connect_to_banned_peer::<TestTransportLibp2p, Libp2pService>().await;
}

#[tokio::test]
async fn connect_to_banned_peer_mock_tcp() {
    connect_to_banned_peer::<TestTransportTcp, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn connect_to_banned_peer_mock_channels() {
    connect_to_banned_peer::<TestTransportChannel, MockService<MockChannelTransport>>().await;
}

#[tokio::test]
async fn connect_to_banned_peer_mock_noise() {
    connect_to_banned_peer::<TestTransportNoise, MockService<NoiseTcpTransport>>().await;
}

async fn validate_invalid_outbound_connection<A, S>(peer_address: S::Address, peer_id: S::PeerId)
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + std::fmt::Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    <S as net::NetworkingService>::Address: std::str::FromStr,
    <<S as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let config = Arc::new(config::create_mainnet());
    let mut peer_manager =
        make_peer_manager::<S>(A::make_transport(), A::make_address(), Arc::clone(&config)).await;

    // valid connection
    let res = peer_manager.accept_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(peer_manager.peerdb.is_active_peer(&peer_id));
    assert!(!peer_manager.peerdb.is_address_banned(&peer_address.as_bannable()));

    // invalid magic bytes
    let res = peer_manager.accept_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));

    // invalid version
    let res = peer_manager.accept_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(1, 1, 1),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));

    // protocol missing
    let res = peer_manager.accept_connection(
        peer_address,
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: [
                Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
            ]
            .into_iter()
            .collect(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));
}

#[tokio::test]
async fn validate_invalid_outbound_connection_libp2p() {
    validate_invalid_outbound_connection::<TestTransportLibp2p, Libp2pService>(
        "/ip4/175.69.140.46".parse().unwrap(),
        libp2p::PeerId::random(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_outbound_connection_mock_tcp() {
    validate_invalid_outbound_connection::<TestTransportTcp, MockService<TcpTransportSocket>>(
        "210.113.67.107:2525".parse().unwrap(),
        MockPeerId::new(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_outbound_connection_mock_channels() {
    validate_invalid_outbound_connection::<TestTransportChannel, MockService<MockChannelTransport>>(
        1,
        MockPeerId::new(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_outbound_connection_mock_noise() {
    validate_invalid_outbound_connection::<TestTransportNoise, MockService<NoiseTcpTransport>>(
        "210.113.67.107:2525".parse().unwrap(),
        MockPeerId::new(),
    )
    .await;
}

async fn validate_invalid_inbound_connection<A, S>(peer_address: S::Address, peer_id: S::PeerId)
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + 'static + std::fmt::Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    <S as net::NetworkingService>::Address: std::str::FromStr,
    <<S as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let config = Arc::new(config::create_mainnet());
    let mut peer_manager =
        make_peer_manager::<S>(A::make_transport(), A::make_address(), Arc::clone(&config)).await;

    // invalid magic bytes
    let res = peer_manager.accept_inbound_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));

    // invalid version
    let res = peer_manager.accept_inbound_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(1, 1, 1),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));

    // protocol missing
    let res = peer_manager.accept_inbound_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: [
                Protocol::new(ProtocolType::PubSub, SemVer::new(1, 0, 0)),
                Protocol::new(ProtocolType::PubSub, SemVer::new(1, 1, 0)),
                Protocol::new(ProtocolType::Ping, SemVer::new(1, 0, 0)),
            ]
            .into_iter()
            .collect(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));

    // valid connection
    let res = peer_manager.accept_inbound_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_address_banned(&peer_address.as_bannable()));
}

#[tokio::test]
async fn validate_invalid_inbound_connection_libp2p() {
    validate_invalid_inbound_connection::<TestTransportLibp2p, Libp2pService>(
        "/ip4/175.69.140.46".parse().unwrap(),
        libp2p::PeerId::random(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_inbound_connection_mock_tcp() {
    validate_invalid_inbound_connection::<TestTransportTcp, MockService<TcpTransportSocket>>(
        "210.113.67.107:2525".parse().unwrap(),
        MockPeerId::new(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_inbound_connection_mock_channels() {
    validate_invalid_inbound_connection::<TestTransportChannel, MockService<MockChannelTransport>>(
        1,
        MockPeerId::new(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_inbound_connection_mock_noise() {
    validate_invalid_inbound_connection::<TestTransportNoise, MockService<NoiseTcpTransport>>(
        "210.113.67.107:2525".parse().unwrap(),
        MockPeerId::new(),
    )
    .await;
}

async fn inbound_connection_invalid_magic<A, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
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

    let (_address, peer_info, _) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    tokio::spawn(async move { pm1.run().await });

    if let Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id }) =
        pm2.peer_connectivity_handle.poll_next().await
    {
        assert_eq!(peer_id, peer_info.peer_id);
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn inbound_connection_invalid_magic_libp2p() {
    inbound_connection_invalid_magic::<TestTransportLibp2p, Libp2pService>().await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_mock_tcp() {
    inbound_connection_invalid_magic::<TestTransportTcp, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_mock_channels() {
    inbound_connection_invalid_magic::<TestTransportChannel, MockService<MockChannelTransport>>()
        .await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_mock_noise() {
    inbound_connection_invalid_magic::<TestTransportNoise, MockService<NoiseTcpTransport>>().await;
}
