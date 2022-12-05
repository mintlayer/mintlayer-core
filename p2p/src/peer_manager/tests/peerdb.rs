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

use std::{collections::HashMap, sync::Arc, time::Duration};

use libp2p::{multiaddr, Multiaddr, PeerId};

use crate::{
    config::{MdnsConfig, P2pConfig},
    net::{libp2p::Libp2pService, types, AsBannableAddress},
    peer_manager::{
        peerdb::{Peer, PeerDb},
        tests::default_protocols,
    },
    NetworkingService,
};

fn make_peer_info() -> (PeerId, types::PeerInfo<Libp2pService>) {
    let peer_id = PeerId::random();

    (
        peer_id,
        types::PeerInfo::<Libp2pService> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: default_protocols(),
        },
    )
}

fn add_active_peer(peerdb: &mut PeerDb<Libp2pService>) -> PeerId {
    let (id, info) = make_peer_info();
    peerdb.peer_connected("/ip4/160.9.112.44".parse().unwrap(), info);

    id
}

fn add_idle_peer(peerdb: &mut PeerDb<Libp2pService>) -> PeerId {
    let (id, info) = make_peer_info();
    peerdb.register_peer_info("/ip4/160.9.112.45".parse().unwrap(), info);

    id
}

fn add_discovered_peer(peerdb: &mut PeerDb<Libp2pService>) -> PeerId {
    let peer_id = PeerId::random();
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id,
        ip4: vec![],
        ip6: vec![],
    });

    peer_id
}

fn add_banned_peer_address(peerdb: &mut PeerDb<Libp2pService>, address: Multiaddr) -> PeerId {
    let (id, info) = make_peer_info();
    peerdb.register_peer_info(address, info);
    peerdb.ban_peer(&id);

    id
}

fn add_banned_peer(peerdb: &mut PeerDb<Libp2pService>) -> PeerId {
    add_banned_peer_address(peerdb, "/ip4/160.9.112.46".parse().unwrap())
}

#[test]
fn num_active_peers() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    assert_eq!(peerdb.idle_peer_count(), 0);
    assert_eq!(peerdb.active_peer_count(), 0);

    // add three active peers
    for _ in 0..3 {
        let _id = add_active_peer(&mut peerdb);
    }
    assert_eq!(peerdb.idle_peer_count(), 0);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 3);

    // add 2 idle peers
    for _ in 0..2 {
        let _id = add_idle_peer(&mut peerdb);
    }
    assert_eq!(peerdb.idle_peer_count(), 2);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 5);

    // add 4 discovered peers
    for _ in 0..2 {
        let _id = add_discovered_peer(&mut peerdb);
    }
    assert_eq!(peerdb.idle_peer_count(), 4);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 7);

    // add 5 banned peers
    let addresses = [
        "/ip4/160.9.112.1",
        "/ip4/160.9.112.2",
        "/ip4/160.9.112.3",
        "/ip4/160.9.112.4",
        "/ip4/160.9.112.5",
    ];
    for address in addresses {
        let _id = add_banned_peer_address(&mut peerdb, address.parse().unwrap());
    }
    assert_eq!(peerdb.idle_peer_count(), 4);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 12);
}

#[test]
fn is_active_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id1 = add_active_peer(&mut peerdb);
    assert!(peerdb.is_active_peer(&id1));

    let id2 = add_idle_peer(&mut peerdb);
    assert!(!peerdb.is_active_peer(&id2));

    let id3 = add_discovered_peer(&mut peerdb);
    assert!(!peerdb.is_active_peer(&id3));

    let id4 = add_banned_peer(&mut peerdb);
    assert!(!peerdb.is_active_peer(&id4));
}

#[test]
fn adjust_peer_score_normal_threshold() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id = add_active_peer(&mut peerdb);
    assert!(peerdb.adjust_peer_score(&id, 100));

    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
}

#[test]
fn adjust_peer_score_higher_threshold() {
    let config = P2pConfig {
        bind_address: "/ip6/::1/tcp/3031".to_owned().into(),
        ban_threshold: 200.into(),
        outbound_connection_timeout: 10.into(),
        mdns_config: MdnsConfig::Disabled.into(),
        request_timeout: Duration::from_secs(10).into(),
    };
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config));

    let id = add_active_peer(&mut peerdb);
    assert!(!peerdb.adjust_peer_score(&id, 100));

    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(!peerdb.is_address_banned(&address));
}

#[test]
fn adjust_peer_score_lower_threshold() {
    let config = P2pConfig {
        bind_address: "/ip6/::1/tcp/3031".to_owned().into(),
        ban_threshold: 20.into(),
        outbound_connection_timeout: 10.into(),
        mdns_config: MdnsConfig::Disabled.into(),
        request_timeout: Duration::from_secs(10).into(),
    };
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config));

    let id = add_active_peer(&mut peerdb);
    assert!(peerdb.adjust_peer_score(&id, 30));
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
}

#[test]
fn ban_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    // idle peer
    let id = add_banned_peer(&mut peerdb);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
    assert!(!peerdb.available().contains(&id));

    // active peer
    let id = add_active_peer(&mut peerdb);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
    assert!(!peerdb.available().contains(&id));

    // discovered peer
    let id = add_discovered_peer(&mut peerdb);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id));
}

#[test]
fn peer_disconnected_unknown() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    // unknown peer doesn't cause any changes
    assert_eq!(peerdb.peers().len(), 0);
    peerdb.peer_disconnected(&PeerId::random());
    assert_eq!(peerdb.peers().len(), 0);
}

#[test]
fn peer_disconnected_idle() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    // idle peer
    let id = add_idle_peer(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

#[test]
fn peer_disconnected_discovered() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id = add_discovered_peer(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Discovered(_))
    ));
    assert!(peerdb.available().contains(&id));
}

#[test]
fn peer_disconnected_banned() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id = add_banned_peer(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
}

#[test]
fn peer_disconnected_active() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id = add_active_peer(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

#[test]
fn peer_connected_discovered() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    // register information for a discovered peer
    let (peer_id, info) = make_peer_info();
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id,
        ip4: vec![],
        ip6: vec![remote_addr.clone(), "/ip6/::1/tcp/8889".parse().unwrap()],
    });
    assert!(std::matches!(
        peerdb.peers().get(&peer_id),
        Some(Peer::Discovered(_))
    ));
    assert!(peerdb.take_best_peer_addr().unwrap().is_some());

    assert!(peerdb.pending().contains_key(&remote_addr));
    peerdb.peer_connected(remote_addr.clone(), info);

    assert!(std::matches!(
        peerdb.peers().get(&peer_id),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&peer_id));
    assert!(!peerdb.pending().contains_key(&remote_addr));
}

#[test]
fn peer_connected_idle() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    let (id, info) = make_peer_info();
    let (_id, mut new_info) = make_peer_info();
    new_info.peer_id = id;

    peerdb.register_peer_info(Multiaddr::empty(), info);
    assert!(peerdb.available().contains(&id));

    peerdb.peer_connected(remote_addr.clone(), new_info);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id));
    assert!(!peerdb.pending().contains_key(&remote_addr));
}

#[test]
fn peer_connected_unknown() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    let (id, info) = make_peer_info();

    assert!(!peerdb.available().contains(&id));
    assert!(!peerdb.peers().contains_key(&id));
    assert!(!peerdb.pending().contains_key(&remote_addr));

    peerdb.peer_connected(remote_addr.clone(), info);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id));
    assert!(!peerdb.pending().contains_key(&remote_addr));
}

#[test]
fn peer_connected_active() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    // active peer
    let id1 = add_active_peer(&mut peerdb);
    let (_id, mut info1) = make_peer_info();
    info1.peer_id = id1;

    peerdb.peer_connected(Multiaddr::empty(), info1);
    assert!(std::matches!(
        peerdb.peers().get(&id1),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id1));
}

#[test]
fn peer_connected_banned() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id2 = add_banned_peer(&mut peerdb);
    let (_id, mut info2) = make_peer_info();
    info2.peer_id = id2;

    peerdb.peer_connected(Multiaddr::empty(), info2);
    assert!(std::matches!(
        peerdb.peers().get(&id2),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id2));
}

#[test]
fn register_peer_info_discovered_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    // register information for a discovered peer
    let (peer_id, info) = make_peer_info();
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id,
        ip4: vec![],
        ip6: vec![remote_addr.clone(), "/ip6/::1/tcp/8889".parse().unwrap()],
    });
    assert!(std::matches!(
        peerdb.peers().get(&peer_id),
        Some(Peer::Discovered(_))
    ));
    assert!(peerdb.take_best_peer_addr().unwrap().is_some());

    assert!(peerdb.pending().get(&remote_addr).is_some());
    peerdb.register_peer_info(remote_addr, info);
    assert!(std::matches!(
        peerdb.peers().get(&peer_id),
        Some(Peer::Idle(_))
    ));
    assert!(peerdb.available().contains(&peer_id));
}

// for idle peers the information is updated
#[test]
fn register_peer_info_idle_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id = add_idle_peer(&mut peerdb);
    if let Some(Peer::Idle(ctx)) = peerdb.peers().get(&id) {
        assert_eq!(ctx.info.magic_bytes, [1, 2, 3, 4]);
    } else {
        panic!("invalid peer type");
    }

    let (_id, mut info) = make_peer_info();
    info.peer_id = id;
    info.magic_bytes = [13, 37, 13, 38];
    peerdb.register_peer_info("/ip6/::1/tcp/8888".parse().unwrap(), info);

    // verify that the information has been updated for an idle peer
    if let Some(Peer::Idle(ctx)) = peerdb.peers().get(&id) {
        assert_eq!(ctx.info.magic_bytes, [13, 37, 13, 38]);
    } else {
        panic!("invalid peer type");
    }
    assert!(peerdb.available().contains(&id));
}

#[test]
fn register_peer_info_unknown_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let (id, info) = make_peer_info();
    assert!(peerdb.peers().get(&id).is_none());
    peerdb.register_peer_info("/ip6/::1/tcp/8888".parse().unwrap(), info);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

#[test]
fn register_peer_info_active() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    let id1 = add_active_peer(&mut peerdb);
    let (_id, info1) = make_peer_info();

    peerdb.register_peer_info(Multiaddr::empty(), info1);
    assert!(std::matches!(
        peerdb.peers().get(&id1),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id1));
}

#[test]
fn register_peer_info_banned() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(P2pConfig::default()));

    // banned peer
    let id2 = add_banned_peer(&mut peerdb);
    let (_id, info2) = make_peer_info();

    peerdb.register_peer_info(Multiaddr::empty(), info2);
    assert!(std::matches!(
        peerdb.peers().get(&id2),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id2));
}

#[test]
fn peer_discovered_libp2p() {
    let mut peerdb = PeerDb::new(Arc::new(P2pConfig::default()));

    let id_1: libp2p::PeerId = PeerId::random();
    let id_2: libp2p::PeerId = PeerId::random();
    let id_3: libp2p::PeerId = PeerId::random();

    // check that peer with `id` has the correct ipv4 and ipv6 addresses
    let check_peer =
        |peers: &HashMap<<Libp2pService as NetworkingService>::PeerId, Peer<Libp2pService>>,
         peer_id: PeerId,
         ip4: Vec<Multiaddr>,
         ip6: Vec<Multiaddr>| {
            let (p_ip4, p_ip6) = {
                match peers.get(&peer_id).unwrap() {
                    Peer::Idle(_) => panic!("invalid peer type"),
                    Peer::Active(_) => panic!("invalid peer type"),
                    Peer::Banned(_) => panic!("invalid peer type"),
                    Peer::Discovered(info) => {
                        let mut ip4 = vec![];
                        let mut ip6 = vec![];

                        for addr in info {
                            let components = addr.iter().collect::<Vec<_>>();
                            if std::matches!(components[0], multiaddr::Protocol::Ip6(_)) {
                                ip6.push(addr.clone());
                            } else {
                                ip4.push(addr.clone());
                            }
                        }

                        (ip4, ip6)
                    }
                }
            };

            assert_eq!(ip4.len(), p_ip4.len());
            assert_eq!(ip6.len(), p_ip6.len());

            for ip in ip4.iter() {
                assert!(p_ip4.contains(ip));
            }

            for ip in ip6.iter() {
                assert!(p_ip6.contains(ip));
            }
        };

    // first add two new peers, both with ipv4 and ipv6 address
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id: id_1,
        ip4: vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
        ip6: vec!["/ip6/::1/tcp/9091".parse().unwrap()],
    });
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id: id_2,
        ip4: vec!["/ip4/127.0.0.1/tcp/9092".parse().unwrap()],
        ip6: vec!["/ip6/::1/tcp/9093".parse().unwrap()],
    });

    assert_eq!(peerdb.peers().len(), 2);
    assert_eq!(
        peerdb.peers().iter().filter(|x| std::matches!(x.1, Peer::Idle(_))).count(),
        0
    );
    assert_eq!(peerdb.available().len(), 2);

    check_peer(
        peerdb.peers(),
        id_1,
        vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
        vec!["/ip6/::1/tcp/9091".parse().unwrap()],
    );

    check_peer(
        peerdb.peers(),
        id_2,
        vec!["/ip4/127.0.0.1/tcp/9092".parse().unwrap()],
        vec!["/ip6/::1/tcp/9093".parse().unwrap()],
    );

    // then discover one new peer and two additional ipv6 addresses for peer 1
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id: id_1,
        ip4: vec![],
        ip6: vec!["/ip6/::1/tcp/9094".parse().unwrap(), "/ip6/::1/tcp/9095".parse().unwrap()],
    });
    peerdb.peer_discovered(&types::AddrInfo {
        peer_id: id_3,
        ip4: vec!["/ip4/127.0.0.1/tcp/9096".parse().unwrap()],
        ip6: vec!["/ip6/::1/tcp/9097".parse().unwrap()],
    });

    check_peer(
        peerdb.peers(),
        id_1,
        vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
        vec![
            "/ip6/::1/tcp/9091".parse().unwrap(),
            "/ip6/::1/tcp/9094".parse().unwrap(),
            "/ip6/::1/tcp/9095".parse().unwrap(),
        ],
    );

    check_peer(
        peerdb.peers(),
        id_3,
        vec!["/ip4/127.0.0.1/tcp/9096".parse().unwrap()],
        vec!["/ip6/::1/tcp/9097".parse().unwrap()],
    );
}
