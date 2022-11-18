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

use common::{chain::config, primitives::semver::SemVer};
use p2p_test_utils::{MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress};

use crate::{
    error::{P2pError, PeerError},
    net::{
        self,
        libp2p::Libp2pService,
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            types::MockPeerId,
            MockService,
        },
        types::{Protocol, ProtocolType},
        AsBannableAddress, ConnectivityService, NetworkingService,
    },
    peer_manager::helpers::connect_services,
    peer_manager::tests::{default_protocols, make_peer_manager},
};

// ban peer whose connected to us
async fn ban_connected_peer<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(addr2, config).await;

    let (address, peer_info) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    pm2.accept_inbound_connection(address, peer_info).unwrap();

    let peer_id = *pm1.peer_connectivity_handle.peer_id();
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
    ban_connected_peer::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn ban_connected_peer_mock_tcp() {
    ban_connected_peer::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[ignore]
#[tokio::test]
async fn ban_connected_peer_mock_channels() {
    // TODO: Currently in the channels backend peer receives a new address everytime it connects.
    // For the banning to work properly the addresses must be persistent.
    ban_connected_peer::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

async fn banned_peer_attempts_to_connect<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + std::fmt::Debug + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(addr2, config).await;

    let (address, peer_info) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    pm2.accept_inbound_connection(address, peer_info).unwrap();

    let peer_id = *pm1.peer_connectivity_handle.peer_id();
    assert_eq!(pm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    let addr1 = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    assert!(std::matches!(
        pm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    // try to reestablish connection, it timeouts because it's rejected in the backend
    let addr = pm2.peer_connectivity_handle.local_addr().await.unwrap().unwrap();
    tokio::spawn(async move { pm1.peer_connectivity_handle.connect(addr).await });

    tokio::select! {
        _event = pm2.peer_connectivity_handle.poll_next() => {
            panic!("did not expect event, received {:?}", _event)
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
    }
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_libp2p() {
    banned_peer_attempts_to_connect::<MakeP2pAddress, Libp2pService>().await;
}

#[ignore]
#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_tcp() {
    // TODO: implement proper peer banning
    banned_peer_attempts_to_connect::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[ignore]
#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_channel() {
    // TODO: implement proper peer banning
    banned_peer_attempts_to_connect::<MakeChannelAddress, MockService<ChannelMockTransport>>()
        .await;
}

// attempt to connect to banned peer
async fn connect_to_banned_peer<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let config = Arc::new(config::create_mainnet());
    let mut pm1 = make_peer_manager::<T>(addr1, Arc::clone(&config)).await;
    let mut pm2 = make_peer_manager::<T>(addr2, config).await;

    let (address, peer_info) = connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    pm2.accept_inbound_connection(address, peer_info).unwrap();

    let peer_id = *pm1.peer_connectivity_handle.peer_id();
    assert_eq!(pm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    let addr1 = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap().as_bannable();
    assert!(pm2.peerdb.is_address_banned(&addr1));
    assert!(std::matches!(
        pm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    let remote_addr = pm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap();
    let remote_id = *pm1.peer_connectivity_handle.peer_id();

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
        assert_eq!(
            error,
            P2pError::PeerError(PeerError::BannedPeer(remote_id.to_string()))
        );
    }
}

#[tokio::test]
async fn connect_to_banned_peer_libp2p() {
    connect_to_banned_peer::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn connect_to_banned_peer_mock_tcp() {
    connect_to_banned_peer::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[ignore]
#[tokio::test]
async fn connect_to_banned_peer_mock_channels() {
    // TODO: Currently in the channels backend peer receives a new address everytime it connects.
    // For the banning to work properly the addresses must be persistent.
    connect_to_banned_peer::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

async fn validate_invalid_outbound_connection<A, S>(peer_address: S::Address, peer_id: S::PeerId)
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + 'static + std::fmt::Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    <S as net::NetworkingService>::Address: std::str::FromStr,
    <<S as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let config = Arc::new(config::create_mainnet());
    let mut peer_manager = make_peer_manager::<S>(A::make_address(), Arc::clone(&config)).await;

    // valid connection
    let res = peer_manager.accept_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: *config.magic_bytes(),
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
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
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_active_peer(&peer_id));
}

#[tokio::test]
async fn validate_invalid_outbound_connection_libp2p() {
    validate_invalid_outbound_connection::<MakeP2pAddress, Libp2pService>(
        "/ip4/175.69.140.46".parse().unwrap(),
        libp2p::PeerId::random(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_outbound_connection_mock_tcp() {
    validate_invalid_outbound_connection::<MakeTcpAddress, MockService<TcpMockTransport>>(
        "210.113.67.107:2525".parse().unwrap(),
        MockPeerId::random(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_outbound_connection_mock_channels() {
    validate_invalid_outbound_connection::<MakeChannelAddress, MockService<ChannelMockTransport>>(
        1,
        MockPeerId::random(),
    )
    .await;
}

async fn validate_invalid_inbound_connection<A, S>(peer_address: S::Address, peer_id: S::PeerId)
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + 'static + std::fmt::Debug,
    S::ConnectivityHandle: ConnectivityService<S>,
    <S as net::NetworkingService>::Address: std::str::FromStr,
    <<S as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let config = Arc::new(config::create_mainnet());
    let mut peer_manager = make_peer_manager::<S>(A::make_address(), Arc::clone(&config)).await;

    // invalid magic bytes
    let res = peer_manager.accept_inbound_connection(
        peer_address.clone(),
        net::types::PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
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
        },
    );
    assert_eq!(peer_manager.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!peer_manager.peerdb.is_address_banned(&peer_address.as_bannable()));
}

#[tokio::test]
async fn validate_invalid_inbound_connection_libp2p() {
    validate_invalid_inbound_connection::<MakeP2pAddress, Libp2pService>(
        "/ip4/175.69.140.46".parse().unwrap(),
        libp2p::PeerId::random(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_inbound_connection_mock_tcp() {
    validate_invalid_inbound_connection::<MakeTcpAddress, MockService<TcpMockTransport>>(
        "210.113.67.107:2525".parse().unwrap(),
        MockPeerId::random(),
    )
    .await;
}

#[tokio::test]
async fn validate_invalid_inbound_connection_mock_channels() {
    validate_invalid_inbound_connection::<MakeChannelAddress, MockService<ChannelMockTransport>>(
        1,
        MockPeerId::random(),
    )
    .await;
}

async fn inbound_connection_invalid_magic<A, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    T: NetworkingService + 'static + std::fmt::Debug,
    T::ConnectivityHandle: ConnectivityService<T>,
    <T as net::NetworkingService>::Address: std::str::FromStr,
    <<T as net::NetworkingService>::Address as std::str::FromStr>::Err: std::fmt::Debug,
{
    let addr1 = A::make_address();
    let addr2 = A::make_address();

    let mut pm1 = make_peer_manager::<T>(addr1, Arc::new(config::create_mainnet())).await;
    let mut pm2 = make_peer_manager::<T>(
        addr2,
        Arc::new(common::chain::config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    connect_services::<T>(
        &mut pm1.peer_connectivity_handle,
        &mut pm2.peer_connectivity_handle,
    )
    .await;
    let pm1_id = *pm1.peer_connectivity_handle.peer_id();

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    tokio::spawn(async move { pm1.run().await });

    if let Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id }) =
        pm2.peer_connectivity_handle.poll_next().await
    {
        assert_eq!(peer_id, pm1_id);
    } else {
        panic!("invalid event received");
    }
}

#[tokio::test]
async fn inbound_connection_invalid_magic_libp2p() {
    inbound_connection_invalid_magic::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_mock_tcp() {
    inbound_connection_invalid_magic::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn inbound_connection_invalid_magic_mock_channels() {
    inbound_connection_invalid_magic::<MakeChannelAddress, MockService<ChannelMockTransport>>()
        .await;
}
