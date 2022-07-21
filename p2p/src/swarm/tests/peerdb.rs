// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen

use super::*;
use crate::{
    config,
    net::{libp2p::Libp2pService, types},
    swarm::peerdb::{Peer, PeerContext, PeerDb},
};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use std::collections::{HashMap, VecDeque};

fn make_peer_info() -> (PeerId, types::PeerInfo<Libp2pService>) {
    let peer_id = PeerId::random();

    (
        peer_id,
        types::PeerInfo::<Libp2pService> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            protocols: vec![
                "/meshsub/1.1.0".to_string(),
                "/meshsub/1.0.0".to_string(),
                "/ipfs/ping/1.0.0".to_string(),
                "/ipfs/id/push/1.0.0".to_string(),
                "/mintlayer/sync/0.1.0".to_string(),
            ],
        },
    )
}

fn make_peer_ctx() -> (PeerId, PeerContext<Libp2pService>) {
    let (peer_id, info) = make_peer_info();

    (
        peer_id,
        PeerContext {
            info,
            address: None,
            addresses: Default::default(),
            score: 0,
        },
    )
}

#[test]
fn num_active_peers() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    assert_eq!(peerdb.idle_peer_count(), 0);
    assert_eq!(peerdb.active_peer_count(), 0);

    // add three active peers
    for _ in 0..3 {
        let (id, ctx) = make_peer_ctx();
        peerdb.peers().insert(id, Peer::Active(ctx));
    }
    assert_eq!(peerdb.idle_peer_count(), 0);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 3);

    // add 2 idle peers
    for _ in 0..2 {
        let (id, ctx) = make_peer_ctx();
        peerdb.peers().insert(id, Peer::Idle(ctx));
        peerdb.available().insert(id);
    }
    assert_eq!(peerdb.idle_peer_count(), 2);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 5);

    // add 4 discovered peers
    for _ in 0..2 {
        let id = PeerId::random();
        peerdb.peers().insert(id, Peer::Discovered(Default::default()));
        peerdb.available().insert(id);
    }
    assert_eq!(peerdb.idle_peer_count(), 4);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 7);

    // add 5 banned peers
    for _ in 0..5 {
        let (id, ctx) = make_peer_ctx();
        peerdb.peers().insert(id, Peer::Banned(either::Left(ctx)));
        peerdb.banned().insert(id);
    }
    assert_eq!(peerdb.idle_peer_count(), 4);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 12);
}

#[test]
fn is_active_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    let (id1, ctx) = make_peer_ctx();
    peerdb.peers().insert(id1, Peer::Active(ctx));
    assert!(peerdb.is_active_peer(&id1));

    let (id2, ctx) = make_peer_ctx();
    peerdb.peers().insert(id2, Peer::Idle(ctx));
    assert!(!peerdb.is_active_peer(&id2));

    let id3 = PeerId::random();
    peerdb.peers().insert(id3, Peer::Discovered(Default::default()));
    assert!(!peerdb.is_active_peer(&id3));

    let (id4, ctx) = make_peer_ctx();
    peerdb.peers().insert(id4, Peer::Banned(either::Left(ctx)));
    assert!(!peerdb.is_active_peer(&id4));
}

#[test]
fn adjust_peer_score() {
    // peer banned after adjustment
    {
        let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

        let (id, ctx) = make_peer_ctx();
        peerdb.peers().insert(id, Peer::Active(ctx));
        peerdb.available().insert(id);
        assert!(peerdb.adjust_peer_score(&id, 100));
        assert!(peerdb.banned().contains(&id));
    }

    // higher threshold, no ban
    {
        let mut config = config::P2pConfig::new();
        config.ban_threshold = 200;
        let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config));

        let (id, ctx) = make_peer_ctx();
        peerdb.peers().insert(id, Peer::Active(ctx));
        peerdb.available().insert(id);
        assert!(!peerdb.adjust_peer_score(&id, 100));
        assert!(!peerdb.banned().contains(&id));
    }

    // lower threshold, ban for more minor offense
    {
        let mut config = config::P2pConfig::new();
        config.ban_threshold = 20;
        let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config));

        let (id, ctx) = make_peer_ctx();
        peerdb.peers().insert(id, Peer::Active(ctx));
        peerdb.available().insert(id);
        assert!(peerdb.adjust_peer_score(&id, 30));
        assert!(peerdb.banned().contains(&id));
    }
}

#[test]
fn ban_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    // unknown peer only updates the `banned` set
    assert_eq!(peerdb.banned().len(), 0);
    peerdb.ban_peer(&PeerId::random());
    assert_eq!(peerdb.banned().len(), 1);

    // idle peer
    let (id, ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Idle(ctx));
    peerdb.available().insert(id);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    assert!(peerdb.banned().contains(&id));
    assert!(!peerdb.available().contains(&id));

    // active peer
    let (id, ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Active(ctx));
    peerdb.available().insert(id);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    assert!(peerdb.banned().contains(&id));
    assert!(!peerdb.available().contains(&id));

    // discovered peer
    let (id, _ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Discovered(Default::default()));
    peerdb.available().insert(id);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    assert!(peerdb.banned().contains(&id));
    assert!(!peerdb.available().contains(&id));
}

#[test]
fn peer_disconnected() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    // unknown peer doesn't cause any changes
    assert_eq!(peerdb.peers().len(), 0);
    peerdb.peer_disconnected(&PeerId::random());
    assert_eq!(peerdb.peers().len(), 0);

    // idle peer
    let (id, ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Idle(ctx));
    peerdb.available().insert(id);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));

    // discovered peer
    let (id, _ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Discovered(Default::default()));
    peerdb.available().insert(id);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Discovered(_))
    ));
    assert!(peerdb.available().contains(&id));

    // banned peer
    let (id, ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Banned(either::Left(ctx)));
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));

    // active peer
    let (id, ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Active(ctx));
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

#[test]
fn peer_connected_discovered() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    // register information for a discovered peer
    let (id, info) = make_peer_info();
    peerdb.peers().insert(
        id,
        Peer::Discovered(VecDeque::from([
            remote_addr.clone(),
            "/ip6/::1/tcp/8889".parse().unwrap(),
        ])),
    );
    peerdb.pending().insert(remote_addr.clone(), id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Discovered(_))
    ));

    assert!(peerdb.pending().contains_key(&remote_addr));
    peerdb.peer_connected(remote_addr.clone(), info);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id));
    assert!(!peerdb.pending().contains_key(&remote_addr));
}

#[test]
fn peer_connected_idle() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    // register information for a discovered peer
    let (id, info) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Idle(info));

    peerdb.pending().insert(remote_addr.clone(), id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));

    let (_id, mut info) = make_peer_info();
    info.peer_id = id;

    assert!(peerdb.pending().contains_key(&remote_addr));
    peerdb.peer_connected(remote_addr.clone(), info);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id));
    assert!(!peerdb.pending().contains_key(&remote_addr));
}

#[test]
fn peer_connected_unknown() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));
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

// update is ignored for banned and active peers
#[test]
fn peer_connected_banned_and_active() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    // active peer
    let (id1, ctx1) = make_peer_ctx();
    let (_id, info1) = make_peer_info();

    peerdb.peers().insert(id1, Peer::Active(ctx1));
    peerdb.peer_connected(Multiaddr::empty(), info1);
    assert!(std::matches!(
        peerdb.peers().get(&id1),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id1));

    // banned peer
    let (id2, ctx2) = make_peer_ctx();
    let (_id, info2) = make_peer_info();

    peerdb.peers().insert(id2, Peer::Banned(either::Left(ctx2)));
    peerdb.peer_connected(Multiaddr::empty(), info2);
    assert!(std::matches!(
        peerdb.peers().get(&id2),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id1));
}

#[test]
fn register_peer_info_discovered_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));
    let remote_addr: Multiaddr = "/ip6/::1/tcp/8888".parse().unwrap();

    // register information for a discovered peer
    let (id, info) = make_peer_info();
    peerdb.peers().insert(
        id,
        Peer::Discovered(VecDeque::from([
            remote_addr.clone(),
            "/ip6/::1/tcp/8889".parse().unwrap(),
        ])),
    );
    peerdb.pending().insert(remote_addr.clone(), id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Discovered(_))
    ));

    assert!(peerdb.pending().get(&remote_addr).is_some());
    peerdb.register_peer_info(remote_addr, info);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

// for idle peers the information is updated
#[test]
fn register_peer_info_idle_peer() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    let (id, ctx) = make_peer_ctx();
    peerdb.peers().insert(id, Peer::Idle(ctx));
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
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    let (id, info) = make_peer_info();
    assert!(peerdb.peers().get(&id).is_none());
    peerdb.register_peer_info("/ip6/::1/tcp/8888".parse().unwrap(), info);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

// update is ignored for banned and active peers
#[test]
fn register_peer_info_banned_and_active() {
    let mut peerdb = PeerDb::<Libp2pService>::new(Arc::new(config::P2pConfig::new()));

    // active peer
    let (id1, ctx1) = make_peer_ctx();
    let (_id, info1) = make_peer_info();

    peerdb.peers().insert(id1, Peer::Active(ctx1));
    peerdb.register_peer_info(Multiaddr::empty(), info1);
    assert!(std::matches!(
        peerdb.peers().get(&id1),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id1));

    // banned peer
    let (id2, ctx2) = make_peer_ctx();
    let (_id, info2) = make_peer_info();

    peerdb.peers().insert(id2, Peer::Banned(either::Left(ctx2)));
    peerdb.register_peer_info(Multiaddr::empty(), info2);
    assert!(std::matches!(
        peerdb.peers().get(&id2),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id1));
}

#[test]
fn peer_discovered_libp2p() {
    let mut peerdb = PeerDb::new(Arc::new(config::P2pConfig::new()));

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
                            if std::matches!(components[0], Protocol::Ip6(_)) {
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
    peerdb.peer_discovered(
        &types::AddrInfo {
            peer_id: id_1,
            ip4: vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
            ip6: vec!["/ip6/::1/tcp/9091".parse().unwrap()],
        },
    );
    peerdb.peer_discovered(
        &types::AddrInfo {
            peer_id: id_2,
            ip4: vec!["/ip4/127.0.0.1/tcp/9092".parse().unwrap()],
            ip6: vec!["/ip6/::1/tcp/9093".parse().unwrap()],
        },
    );

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
    peerdb.peer_discovered(
        &types::AddrInfo {
            peer_id: id_1,
            ip4: vec![],
            ip6: vec!["/ip6/::1/tcp/9094".parse().unwrap(), "/ip6/::1/tcp/9095".parse().unwrap()],
        },
    );
    peerdb.peer_discovered(
        &types::AddrInfo {
            peer_id: id_3,
            ip4: vec!["/ip4/127.0.0.1/tcp/9096".parse().unwrap()],
            ip6: vec!["/ip6/::1/tcp/9097".parse().unwrap()],
        },
    );

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
