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

use std::{sync::Arc, time::Duration};

use p2p::{
    config::P2pConfig,
    net::{
        mock::types::MockPeerId,
        types::{PeerInfo, PubSubTopic, Role},
        AsBannableAddress, NetworkingService,
    },
    peer_manager::peerdb::PeerDb,
    testing_utils::RandomAddressMaker,
};

tests![
    adjust_peer_score_normal_threshold,
    adjust_peer_score_higher_threshold,
    adjust_peer_score_lower_threshold,
    unban_peer,
];

async fn adjust_peer_score_normal_threshold<T, S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig::default())).unwrap();

    let peer_id = add_active_peer::<T, S, A>(&mut peerdb);
    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 100));
    assert!(peerdb.is_address_banned(&address));
}

async fn adjust_peer_score_higher_threshold<T, S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let config = P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: Default::default(),
        ban_threshold: 200.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    };
    let mut peerdb = PeerDb::<S>::new(Arc::new(config)).unwrap();

    let peer_id = add_active_peer::<T, S, A>(&mut peerdb);
    assert!(!peerdb.adjust_peer_score(&peer_id, 100));

    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(!peerdb.is_address_banned(&address));
}

async fn adjust_peer_score_lower_threshold<T, S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let config = P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: Default::default(),
        ban_threshold: 20.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    };
    let mut peerdb = PeerDb::<S>::new(Arc::new(config)).unwrap();

    let peer_id = add_active_peer::<T, S, A>(&mut peerdb);
    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 30));
    assert!(peerdb.is_address_banned(&address));
}

async fn unban_peer<T, S, A>()
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let mut peerdb = PeerDb::<S>::new(Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Duration::from_secs(2).into(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        node_type: Default::default(),
    }))
    .unwrap();

    let peer_id = add_active_peer::<T, S, A>(&mut peerdb);
    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 100));
    assert!(peerdb.is_address_banned(&address));

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(peerdb.is_address_banned(&address));

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!peerdb.is_address_banned(&address));
}

fn make_peer_info<T, S, A>() -> (S::PeerId, S::Address, PeerInfo<S>)
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let peer_id = MockPeerId::new();

    (
        peer_id,
        A::new(),
        PeerInfo::<S> {
            peer_id,
            magic_bytes: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    )
}

fn add_active_peer<T, S, A>(peerdb: &mut PeerDb<S>) -> S::PeerId
where
    S: NetworkingService<PeerId = MockPeerId>,
    A: RandomAddressMaker<Address = S::Address>,
{
    let (peer_id, address, info) = make_peer_info::<T, S, A>();
    peerdb.peer_connected(address, Role::Inbound, info);
    peer_id
}
