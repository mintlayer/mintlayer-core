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

use libp2p::Multiaddr;

use common::{chain::config, primitives::semver::SemVer};
use p2p_test_utils::{MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress};

use crate::{
    error::{P2pError, PeerError},
    net::{
        self,
        libp2p::Libp2pService,
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            MockService,
        },
        types::{Protocol, ProtocolType},
        ConnectivityService, NetworkingService,
    },
    peer_manager::tests::{connect_services, default_protocols, make_peer_manager},
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
    let mut swarm1 = make_peer_manager::<T>(addr1, Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<T>(addr2, config).await;

    let (address, peer_info) = connect_services::<T>(
        &mut swarm1.peer_connectivity_handle,
        &mut swarm2.peer_connectivity_handle,
    )
    .await;
    swarm2.accept_inbound_connection(address, peer_info).await.unwrap();

    let peer_id = *swarm1.peer_connectivity_handle.peer_id();
    assert_eq!(swarm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    assert!(!swarm2.validate_peer_id(&peer_id));
    assert!(std::matches!(
        swarm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));
}

#[tokio::test]
async fn ban_connected_peer_libp2p() {
    ban_connected_peer::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn ban_connected_peer_mock_tcp() {
    // TODO: implement `ban_peer()`
    // ban_connected_peer::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn ban_connected_peer_mock_channels() {
    // TODO: implement `ban_peer()`
    // ban_connected_peer::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
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
    let mut swarm1 = make_peer_manager::<T>(addr1, Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<T>(addr2, config).await;

    let (address, peer_info) = connect_services::<T>(
        &mut swarm1.peer_connectivity_handle,
        &mut swarm2.peer_connectivity_handle,
    )
    .await;
    swarm2.accept_inbound_connection(address, peer_info).await.unwrap();

    let peer_id = *swarm1.peer_connectivity_handle.peer_id();
    assert_eq!(swarm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    assert!(!swarm2.validate_peer_id(&peer_id));
    assert!(std::matches!(
        swarm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    // try to restablish connection, it timeouts because it's rejected in the backend
    let addr = swarm2.peer_connectivity_handle.local_addr().await.unwrap().unwrap();
    tokio::spawn(async move { swarm1.peer_connectivity_handle.connect(addr).await });

    tokio::select! {
        _event = swarm2.peer_connectivity_handle.poll_next() => {
            panic!("did not expect event, received {:?}", _event)
        },
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
    }
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_libp2p() {
    banned_peer_attempts_to_connect::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_tcp() {
    // TODO: implement proper peer banning
    // banned_peer_attempts_to_connect::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn banned_peer_attempts_to_connect_mock_channel() {
    // TODO: implement proper peer banning
    // banned_peer_attempts_to_connect::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
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
    let mut swarm1 = make_peer_manager::<T>(addr1, Arc::clone(&config)).await;
    let mut swarm2 = make_peer_manager::<T>(addr2, config).await;

    let (address, peer_info) = connect_services::<T>(
        &mut swarm1.peer_connectivity_handle,
        &mut swarm2.peer_connectivity_handle,
    )
    .await;
    swarm2.accept_inbound_connection(address, peer_info).await.unwrap();

    let peer_id = *swarm1.peer_connectivity_handle.peer_id();
    assert_eq!(swarm2.adjust_peer_score(peer_id, 1000).await, Ok(()));
    assert!(!swarm2.validate_peer_id(&peer_id));
    assert!(std::matches!(
        swarm2.peer_connectivity_handle.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionClosed { .. })
    ));

    let remote_addr = swarm1.peer_connectivity_handle.local_addr().await.unwrap().unwrap();
    let remote_id = *swarm1.peer_connectivity_handle.peer_id();

    tokio::spawn(async move {
        loop {
            let _ = swarm1.peer_connectivity_handle.poll_next().await.unwrap();
        }
    });

    swarm2.peer_connectivity_handle.connect(remote_addr.clone()).await.unwrap();
    if let Ok(net::types::ConnectivityEvent::ConnectionError { address, error }) =
        swarm2.peer_connectivity_handle.poll_next().await
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
    // TODO: implement proper peer banning
    // connect_to_banned_peer::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn connect_to_banned_peer_mock_channels() {
    // TODO: implement proper peer banning
    // connect_to_banned_peer::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

#[tokio::test]
async fn validate_invalid_outbound_connection() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm =
        make_peer_manager::<Libp2pService>(MakeP2pAddress::make_address(), Arc::clone(&config))
            .await;

    // valid connection
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: default_protocols(),
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!swarm.peerdb.is_id_banned(&peer_id));

    // invalid magic bytes
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: [1, 2, 3, 4],
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: default_protocols(),
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // invalid version
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(1, 1, 1),
                agent: None,
                protocols: default_protocols(),
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // protocol missing
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
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
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));
}

#[tokio::test]
async fn validate_invalid_inbound_connection() {
    let config = Arc::new(config::create_mainnet());
    let mut swarm =
        make_peer_manager::<Libp2pService>(MakeP2pAddress::make_address(), Arc::clone(&config))
            .await;

    // valid connection
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: default_protocols(),
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(!swarm.peerdb.is_id_banned(&peer_id));

    // invalid magic bytes
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: [1, 2, 3, 4],
                version: common::primitives::semver::SemVer::new(0, 1, 0),
                agent: None,
                protocols: default_protocols(),
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // invalid version
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
                peer_id,
                magic_bytes: *config.magic_bytes(),
                version: common::primitives::semver::SemVer::new(1, 1, 1),
                agent: None,
                protocols: default_protocols(),
            },
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));

    // protocol missing
    let peer_id = libp2p::PeerId::random();
    let res = swarm
        .accept_inbound_connection(
            Multiaddr::empty(),
            net::types::PeerInfo::<Libp2pService> {
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
        )
        .await;
    assert_eq!(swarm.handle_result(Some(peer_id), res).await, Ok(()));
    assert!(swarm.peerdb.is_id_banned(&peer_id));
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

    let mut swarm1 = make_peer_manager::<T>(addr1, Arc::new(config::create_mainnet())).await;
    let mut swarm2 = make_peer_manager::<T>(
        addr2,
        Arc::new(common::chain::config::Builder::test_chain().magic_bytes([1, 2, 3, 4]).build()),
    )
    .await;

    connect_services::<T>(
        &mut swarm1.peer_connectivity_handle,
        &mut swarm2.peer_connectivity_handle,
    )
    .await;
    let swarm1_id = *swarm1.peer_connectivity_handle.peer_id();

    // run the first peer manager in the background and poll events from the peer manager
    // that tries to connect to the first manager
    tokio::spawn(async move { swarm1.run().await });

    if let Ok(net::types::ConnectivityEvent::ConnectionClosed { peer_id }) =
        swarm2.peer_connectivity_handle.poll_next().await
    {
        assert_eq!(peer_id, swarm1_id);
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
