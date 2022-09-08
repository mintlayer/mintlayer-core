// Copyright (c) 2021-2022 RBB S.r.l
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

use crate::{
    config,
    error::{ConversionError, DialError, P2pError},
    net::{
        self,
        libp2p::{
            service::connectivity::{parse_discovered_addr, parse_peers},
            Libp2pService,
        },
        types::ConnectivityEvent,
        ConnectivityService, NetworkingService,
    },
};
use libp2p::{core::PeerId, multiaddr::Protocol, Multiaddr};
use p2p_test_utils::{MakeP2pAddress, MakeTestAddress};
use serialization::{Decode, Encode};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Encode, Decode, PartialEq, Eq, Copy, Clone)]
struct Transaction {
    hash: u64,
    value: u128,
}

#[tokio::test]
async fn test_connect_new() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let service =
        Libp2pService::start(MakeP2pAddress::make_address(), config, Default::default()).await;
    assert!(service.is_ok());
}

// verify that binding to the same interface twice is not possible
#[ignore]
#[tokio::test]
async fn test_connect_new_addrinuse() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let service = Libp2pService::start(
        MakeP2pAddress::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await;
    assert!(service.is_ok());

    let service =
        Libp2pService::start(MakeP2pAddress::make_address(), config, Default::default()).await;

    match service {
        Err(e) => {
            assert_eq!(
                e,
                P2pError::DialError(DialError::IoError(std::io::ErrorKind::AddrInUse))
            );
        }
        Ok(_) => panic!("address is not in use"),
    }
}

// try to connect two nodes together by having `service1` listen for network events
// and having `service2` trying to connect to `service1`
#[tokio::test]
async fn test_connect_accept() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let service1 = Libp2pService::start(
        MakeP2pAddress::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await;
    let service2 = Libp2pService::start(
        MakeP2pAddress::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await;
    assert!(service1.is_ok());
    assert!(service2.is_ok());

    let (mut service1, _, _) = service1.unwrap();
    let (mut service2, _, _) = service2.unwrap();
    let conn_addr = service1.local_addr().await.unwrap().unwrap();

    let (res1, res2): (crate::Result<ConnectivityEvent<Libp2pService>>, _) =
        tokio::join!(service1.poll_next(), service2.connect(conn_addr));

    assert!(res2.is_ok());
    assert!(res1.is_ok());
}

// try to connect to a remote peer with a multiaddress that's missing the peerid
// and verify that the connection fails
#[tokio::test]
async fn test_connect_peer_id_missing() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let addr: Multiaddr = "/ip6/::1/tcp/8904".parse().unwrap();
    let (mut service, _, _) =
        Libp2pService::start(MakeP2pAddress::make_address(), config, Default::default())
            .await
            .unwrap();

    match service.connect(addr.clone()).await {
        Ok(_) => panic!("connect succeeded without peer id"),
        Err(e) => {
            assert_eq!(
                e,
                P2pError::ConversionError(ConversionError::InvalidAddress(addr.to_string()))
            )
        }
    }
}

#[test]
fn test_parse_discovered_addr() {
    let peer_id: PeerId = "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();

    assert_eq!(
        parse_discovered_addr(peer_id, "/ip4/127.0.0.1/udp/9090/quic".parse().unwrap()),
        None
    );
    assert_eq!(
        parse_discovered_addr(peer_id, "/ip6/::1/udp/3217".parse().unwrap()),
        None
    );
    assert_eq!(
        parse_discovered_addr(peer_id, "/ip4/127.0.0.1/tcp/9090/quic".parse().unwrap()),
        None
    );
    assert_eq!(
        parse_discovered_addr(peer_id, "/ip4/127.0.0.1/tcp/80/http".parse().unwrap()),
        None
    );
    assert_eq!(
        parse_discovered_addr(peer_id, "/dns4/foo.com/tcp/80/http".parse().unwrap()),
        None
    );
    assert_eq!(
        parse_discovered_addr(peer_id, "/dns6/foo.com/tcp/443/https".parse().unwrap()),
        None
    );

    let addr: Multiaddr =
        "/ip6/::1/tcp/3217/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
            .parse()
            .unwrap();
    let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
    assert_eq!(parse_discovered_addr(id, addr.clone()), Some(addr));

    let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
    let addr: Multiaddr =
        "/ip4/127.0.0.1/tcp/9090/p2p/12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ"
            .parse()
            .unwrap();
    assert_eq!(parse_discovered_addr(id, addr.clone()), Some(addr));

    let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
    let addr: Multiaddr = "/ip6/::1/tcp/3217".parse().unwrap();
    assert_eq!(
        parse_discovered_addr(id, addr.clone()),
        Some(addr.with(Protocol::P2p(id.into())))
    );

    let id: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();
    assert_eq!(
        parse_discovered_addr(id, addr.clone()),
        Some(addr.with(Protocol::P2p(id.into())))
    );
}

impl PartialEq for Libp2pService {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<T: NetworkingService> PartialEq for net::types::PeerInfo<T> {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
            && self.magic_bytes == other.magic_bytes
            && self.version == other.version
            && self.agent == other.agent
            && self.protocols == other.protocols
    }
}

// verify that vector of address (that all belong to one peer) parse into one `net::types::Peer` entry
#[test]
fn test_parse_peers_valid_1_peer() {
    let peer_id = PeerId::random();
    let ip4: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();
    let ip6: Multiaddr = "/ip6/::1/tcp/9091".parse().unwrap();
    let addrs = vec![(peer_id, ip4.clone()), (peer_id, ip6.clone())];

    let parsed: Vec<net::types::AddrInfo<Libp2pService>> = parse_peers(addrs);
    assert_eq!(
        parsed,
        vec![net::types::AddrInfo {
            peer_id,
            ip4: vec![ip4.with(Protocol::P2p(peer_id.into()))],
            ip6: vec![ip6.with(Protocol::P2p(peer_id.into()))],
        }]
    );
}

// discovery 5 different addresses, ipv4 and ipv6 for both peer and an additional
// dns address for peer
//
// verify that `parse_peers` returns two peers and both only have ipv4 and ipv6 addresses
#[test]
fn test_parse_peers_valid_2_peers() {
    let id_1: PeerId = "12D3KooWRn14SemPVxwzdQNg8e8Trythiww1FWrNfPbukYBmZEbJ".parse().unwrap();
    let ip4_1: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();
    let ip6_1: Multiaddr = "/ip6/::1/tcp/9091".parse().unwrap();

    let id_2: PeerId = "12D3KooWE3kBRAnn6jxZMdK1JMWx1iHtR1NKzXSRv5HLTmfD9u9c".parse().unwrap();
    let ip4_2: Multiaddr = "/ip4/127.0.0.1/tcp/8080".parse().unwrap();
    let ip6_2: Multiaddr = "/ip6/::1/tcp/8081".parse().unwrap();
    let dns: Multiaddr = "/dns4/foo.com/tcp/80/http".parse().unwrap();

    let addrs = vec![
        (id_1, ip4_1.clone()),
        (id_2, ip4_2.clone()),
        (id_2, ip6_2.clone()),
        (id_1, ip6_1.clone()),
        (id_2, dns),
    ];

    let mut parsed: Vec<net::types::AddrInfo<Libp2pService>> = parse_peers(addrs);
    parsed.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

    assert_eq!(
        parsed,
        vec![
            net::types::AddrInfo {
                peer_id: id_2,
                ip4: vec![ip4_2.with(Protocol::P2p(id_2.into()))],
                ip6: vec![ip6_2.with(Protocol::P2p(id_2.into()))],
            },
            net::types::AddrInfo {
                peer_id: id_1,
                ip4: vec![ip4_1.with(Protocol::P2p(id_1.into()))],
                ip6: vec![ip6_1.with(Protocol::P2p(id_1.into()))],
            },
        ]
    );
}

// find 3 peers but only one of the peers have an accepted address available so verify
// that `parse_peers()` returns only that peer
#[test]
fn test_parse_peers_valid_3_peers_1_valid() {
    let id_1 = PeerId::random();
    let ip4: Multiaddr = "/ip4/127.0.0.1/tcp/9090".parse().unwrap();

    let id_2 = PeerId::random();
    let dns: Multiaddr = "/dns4/foo.com/tcp/80/http".parse().unwrap();

    let id_3 = PeerId::random();
    let quic: Multiaddr = "/ip4/127.0.0.1/tcp/9090/quic".parse().unwrap();

    let addrs = vec![(id_1, ip4.clone()), (id_2, dns), (id_3, quic)];
    let parsed: Vec<net::types::AddrInfo<Libp2pService>> = parse_peers(addrs);

    assert_eq!(
        parsed,
        vec![net::types::AddrInfo {
            peer_id: id_1,
            ip4: vec![ip4.with(Protocol::P2p(id_1.into()))],
            ip6: vec![],
        }]
    );
}

// try to connect to a service that is not listening with a small timeout and verify that the connection fails
#[tokio::test]
async fn test_connect_with_timeout() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut service, _, _) = Libp2pService::start(
        MakeP2pAddress::make_address(),
        config,
        Arc::new(config::P2pConfig {
            outbound_connection_timeout: 2,
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    let port = portpicker::pick_unused_port().unwrap();
    let mut addr: Multiaddr = format!("/ip6/::1/tcp/{}", port).parse().unwrap();
    addr.push(Protocol::P2p(PeerId::random().into()));

    // first try to connect to address nobody is listening to
    // and verify that the connection is refused immediately
    let start = std::time::SystemTime::now();
    assert_eq!(service.connect(addr.clone()).await, Ok(()));
    assert!(std::matches!(
        service.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionError {
            address: _,
            error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut)
        })
    ));

    let timeout = if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
        0
    } else {
        2
    };
    assert_eq!(
        std::time::SystemTime::now().duration_since(start).unwrap().as_secs(),
        timeout
    );

    // then create a socket that listens to the address and verify that it takes
    // 2 seconds to get the `ConnectionRefusedOrTimedOut` error, as expected
    let _service = TcpListener::bind(format!("[::1]:{}", port)).await.unwrap();
    let start = std::time::SystemTime::now();

    assert_eq!(service.connect(addr).await, Ok(()),);
    assert!(std::matches!(
        service.poll_next().await,
        Ok(net::types::ConnectivityEvent::ConnectionError {
            address: _,
            error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut)
        })
    ));
    assert!(std::time::SystemTime::now().duration_since(start).unwrap().as_secs() >= 2);
}
