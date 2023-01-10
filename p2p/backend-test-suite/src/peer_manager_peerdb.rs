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

use p2p::{
    config::{MdnsConfig, NodeType, P2pConfig},
    net::{
        mock::types::MockPeerId,
        types::{AddrInfo, PeerInfo, PubSubTopic},
        AsBannableAddress, NetworkingService,
    },
    peer_manager::peerdb::{Peer, PeerDb},
    testing_utils::RandomAddressMaker,
};

tests![
    num_active_peers,
    is_active_peer,
    adjust_peer_score_normal_threshold,
    adjust_peer_score_higher_threshold,
    adjust_peer_score_lower_threshold,
    ban_peer,
    peer_disconnected_unknown,
    peer_disconnected_idle,
    peer_disconnected_discovered,
    peer_disconnected_banned,
    peer_disconnected_active,
    peer_connected_discovered,
    peer_connected_idle,
    peer_connected_unknown,
    peer_connected_active,
    peer_connected_banned,
    register_peer_info_discovered_peer,
    register_peer_info_idle_peer,
    register_peer_info_unknown_peer,
    register_peer_info_active,
    register_peer_info_banned,
];

fn num_active_peers<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    assert_eq!(peerdb.idle_peer_count(), 0);
    assert_eq!(peerdb.active_peer_count(), 0);

    // add three active peers
    for _ in 0..3 {
        let _id = add_active_peer::<S, A>(&mut peerdb);
    }
    assert_eq!(peerdb.idle_peer_count(), 0);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 3);

    // add 2 idle peers
    for _ in 0..2 {
        let _id = add_idle_peer::<S, A>(&mut peerdb);
    }
    assert_eq!(peerdb.idle_peer_count(), 2);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 5);

    // add 4 discovered peers
    for _ in 0..2 {
        let _id = add_discovered_peer::<S>(&mut peerdb);
    }
    assert_eq!(peerdb.idle_peer_count(), 4);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 7);

    // add 5 banned peers
    for _ in 0..5 {
        let _id = add_banned_peer_address::<S>(&mut peerdb, A::new());
    }
    assert_eq!(peerdb.idle_peer_count(), 4);
    assert_eq!(peerdb.active_peer_count(), 3);
    assert_eq!(peerdb.peers().len(), 12);
}

fn is_active_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id1 = add_active_peer::<S, A>(&mut peerdb);
    assert!(peerdb.is_active_peer(&id1));

    let id2 = add_idle_peer::<S, A>(&mut peerdb);
    assert!(!peerdb.is_active_peer(&id2));

    let id3 = add_discovered_peer::<S>(&mut peerdb);
    assert!(!peerdb.is_active_peer(&id3));

    let id4 = add_banned_peer::<S, A>(&mut peerdb);
    assert!(!peerdb.is_active_peer(&id4));
}

fn adjust_peer_score_normal_threshold<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id = add_active_peer::<S, A>(&mut peerdb);
    assert!(peerdb.adjust_peer_score(&id, 100));

    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
}

fn adjust_peer_score_higher_threshold<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let config = P2pConfig {
        bind_address: "[::1]:3031".to_owned().into(),
        ban_threshold: 200.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: 10.into(),
        mdns_config: MdnsConfig::Disabled.into(),
        node_type: NodeType::Full.into(),
    };
    let mut peerdb = PeerDb::<S>::new(Arc::new(config));

    let id = add_active_peer::<S, A>(&mut peerdb);
    assert!(!peerdb.adjust_peer_score(&id, 100));

    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(!peerdb.is_address_banned(&address));
}

fn adjust_peer_score_lower_threshold<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let config = P2pConfig {
        bind_address: "[::1]:3031".to_owned().into(),
        ban_threshold: 20.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: 10.into(),
        mdns_config: MdnsConfig::Disabled.into(),
        node_type: NodeType::Full.into(),
    };
    let mut peerdb = PeerDb::<S>::new(Arc::new(config));

    let id = add_active_peer::<S, A>(&mut peerdb);
    assert!(peerdb.adjust_peer_score(&id, 30));
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
}

fn ban_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    // idle peer
    let id = add_banned_peer::<S, A>(&mut peerdb);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
    assert!(!peerdb.available().contains(&id));

    // active peer
    let id = add_active_peer::<S, A>(&mut peerdb);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    let address = peerdb.peers().get(&id).unwrap().address().unwrap().as_bannable();
    assert!(peerdb.is_address_banned(&address));
    assert!(!peerdb.available().contains(&id));

    // discovered peer
    let id = add_discovered_peer::<S>(&mut peerdb);
    peerdb.ban_peer(&id);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id));
}

fn peer_disconnected_unknown<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    // unknown peer doesn't cause any changes
    assert_eq!(peerdb.peers().len(), 0);
    peerdb.peer_disconnected(&MockPeerId::new());
    assert_eq!(peerdb.peers().len(), 0);
}

fn peer_disconnected_idle<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    // idle peer
    let id = add_idle_peer::<S, A>(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

fn peer_disconnected_discovered<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id = add_discovered_peer::<S>(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Discovered(_))
    ));
    assert!(peerdb.available().contains(&id));
}

fn peer_disconnected_banned<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id = add_banned_peer::<S, A>(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Banned(_))
    ));
}

fn peer_disconnected_active<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id = add_active_peer::<S, A>(&mut peerdb);
    peerdb.peer_disconnected(&id);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

fn peer_connected_discovered<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));
    let remote_addr = A::new();

    // register information for a discovered peer
    let (peer_id, info) = make_peer_info::<S>();
    peerdb.peer_discovered(&AddrInfo {
        peer_id,
        ip4: vec![],
        ip6: vec![remote_addr.clone(), A::new()],
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

fn peer_connected_idle<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));
    let remote_addr = A::new();

    let (id, info) = make_peer_info::<S>();
    let (_id, mut new_info) = make_peer_info::<S>();
    new_info.peer_id = id;

    peerdb.register_peer_info(A::new(), info);
    assert!(peerdb.available().contains(&id));

    peerdb.peer_connected(remote_addr.clone(), new_info);

    assert!(std::matches!(
        peerdb.peers().get(&id),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id));
    assert!(!peerdb.pending().contains_key(&remote_addr));
}

fn peer_connected_unknown<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));
    let remote_addr = A::new();

    let (id, info) = make_peer_info::<S>();

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

fn peer_connected_active<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    // active peer
    let id1 = add_active_peer::<S, A>(&mut peerdb);
    let (_id, mut info1) = make_peer_info::<S>();
    info1.peer_id = id1;

    peerdb.peer_connected(A::new(), info1);
    assert!(std::matches!(
        peerdb.peers().get(&id1),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id1));
}

fn peer_connected_banned<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id2 = add_banned_peer::<S, A>(&mut peerdb);
    let (_id, mut info2) = make_peer_info::<S>();
    info2.peer_id = id2;

    peerdb.peer_connected(A::new(), info2);
    assert!(std::matches!(
        peerdb.peers().get(&id2),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id2));
}

fn register_peer_info_discovered_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));
    let remote_addr = A::new();

    // register information for a discovered peer
    let (peer_id, info) = make_peer_info::<S>();
    peerdb.peer_discovered(&AddrInfo {
        peer_id,
        ip4: vec![],
        ip6: vec![remote_addr.clone(), A::new()],
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
fn register_peer_info_idle_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id = add_idle_peer::<S, A>(&mut peerdb);
    if let Some(Peer::Idle(ctx)) = peerdb.peers().get(&id) {
        assert_eq!(ctx.info.magic_bytes, [1, 2, 3, 4]);
    } else {
        panic!("invalid peer type");
    }

    let (_id, mut info) = make_peer_info::<S>();
    info.peer_id = id;
    info.magic_bytes = [13, 37, 13, 38];
    peerdb.register_peer_info(A::new(), info);

    // verify that the information has been updated for an idle peer
    if let Some(Peer::Idle(ctx)) = peerdb.peers().get(&id) {
        assert_eq!(ctx.info.magic_bytes, [13, 37, 13, 38]);
    } else {
        panic!("invalid peer type");
    }
    assert!(peerdb.available().contains(&id));
}

fn register_peer_info_unknown_peer<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let (id, info) = make_peer_info::<S>();
    assert!(peerdb.peers().get(&id).is_none());
    peerdb.register_peer_info(A::new(), info);
    assert!(std::matches!(peerdb.peers().get(&id), Some(Peer::Idle(_))));
    assert!(peerdb.available().contains(&id));
}

fn register_peer_info_active<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    let id1 = add_active_peer::<S, A>(&mut peerdb);
    let (_id, info1) = make_peer_info::<S>();

    peerdb.register_peer_info(A::new(), info1);
    assert!(std::matches!(
        peerdb.peers().get(&id1),
        Some(Peer::Active(_))
    ));
    assert!(!peerdb.available().contains(&id1));
}

fn register_peer_info_banned<S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default()));

    // banned peer
    let id2 = add_banned_peer::<S, A>(&mut peerdb);
    let (_id, info2) = make_peer_info::<S>();

    peerdb.register_peer_info(A::new(), info2);
    assert!(std::matches!(
        peerdb.peers().get(&id2),
        Some(Peer::Banned(_))
    ));
    assert!(!peerdb.available().contains(&id2));
}

fn make_peer_info<S>() -> (S::PeerId, PeerInfo<S>)
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let peer_id = MockPeerId::new();

    (
        peer_id,
        PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    )
}

fn add_active_peer<S, A>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let (id, info) = make_peer_info::<S>();
    peerdb.peer_connected(A::new(), info);

    id
}

fn add_idle_peer<S, A>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let (id, info) = make_peer_info::<S>();
    peerdb.register_peer_info(A::new(), info);

    id
}

fn add_discovered_peer<S>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let peer_id = MockPeerId::new();
    peerdb.peer_discovered(&AddrInfo {
        peer_id,
        ip4: vec![],
        ip6: vec![],
    });

    peer_id
}

fn add_banned_peer_address<S>(peerdb: &mut PeerDb<S>, address: S::Address) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
{
    let (id, info) = make_peer_info::<S>();
    peerdb.register_peer_info(address, info);
    peerdb.ban_peer(&id);

    id
}

fn add_banned_peer<S, A>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    add_banned_peer_address::<S>(peerdb, A::new())
}
