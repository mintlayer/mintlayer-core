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

// Test functions need to be marked async because of the `tests!` macro.
#![allow(clippy::unused_async)]

use std::{sync::Arc, time::Duration};

use p2p::{
    config::P2pConfig,
    net::{
        default_backend::types::PeerId,
        types::{PeerInfo, PubSubTopic, Role},
        AsBannableAddress, NetworkingService,
    },
    peer_manager::peerdb::{
        storage::{PeerDbStorage, PeerDbStorageRead, PeerDbTransactional},
        PeerDb,
    },
    testing_utils::{peerdb_inmemory_store, RandomAddressMaker},
};

tests![
    adjust_peer_score_normal_threshold,
    adjust_peer_score_higher_threshold,
    adjust_peer_score_lower_threshold,
    unban_peer,
];

async fn adjust_peer_score_normal_threshold<T, N, A>()
where
    N: NetworkingService<PeerId = PeerId>,
    A: RandomAddressMaker<Address = N::Address>,
{
    let mut peerdb = PeerDb::<N, _>::new(
        Arc::new(P2pConfig::default()),
        Default::default(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id = add_active_peer::<T, N, A, _>(&mut peerdb);
    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 100).unwrap());
    assert!(peerdb.is_address_banned(&address).unwrap());
}

async fn adjust_peer_score_higher_threshold<T, N, A>()
where
    N: NetworkingService<PeerId = PeerId>,
    A: RandomAddressMaker<Address = N::Address>,
{
    let config = P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: Default::default(),
        ban_threshold: 200.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        heartbeat_interval_min: Default::default(),
        heartbeat_interval_max: Default::default(),
    };
    let mut peerdb = PeerDb::<N, _>::new(
        Arc::new(config),
        Default::default(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id = add_active_peer::<T, N, A, _>(&mut peerdb);
    assert!(!peerdb.adjust_peer_score(&peer_id, 100).unwrap());

    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(!peerdb.is_address_banned(&address).unwrap());
}

async fn adjust_peer_score_lower_threshold<T, N, A>()
where
    N: NetworkingService<PeerId = PeerId>,
    A: RandomAddressMaker<Address = N::Address>,
{
    let config = P2pConfig {
        bind_addresses: Default::default(),
        added_nodes: Default::default(),
        ban_threshold: 20.into(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        heartbeat_interval_min: Default::default(),
        heartbeat_interval_max: Default::default(),
    };
    let mut peerdb = PeerDb::<N, _>::new(
        Arc::new(config),
        Default::default(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    let peer_id = add_active_peer::<T, N, A, _>(&mut peerdb);
    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 30).unwrap());
    assert!(peerdb.is_address_banned(&address).unwrap());
}

async fn unban_peer<T, N, A>()
where
    N: NetworkingService<PeerId = PeerId>,
    A: RandomAddressMaker<Address = N::Address>,
{
    let db_store = peerdb_inmemory_store();
    let mut peerdb = PeerDb::<N, _>::new(
        Arc::new(P2pConfig {
            bind_addresses: Default::default(),
            added_nodes: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Duration::from_secs(2).into(),
            outbound_connection_timeout: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            heartbeat_interval_min: Default::default(),
            heartbeat_interval_max: Default::default(),
        }),
        Default::default(),
        db_store,
    )
    .unwrap();

    let peer_id = add_active_peer::<T, N, A, _>(&mut peerdb);
    let address = peerdb.peer_address(&peer_id).unwrap().as_bannable();
    assert!(peerdb.adjust_peer_score(&peer_id, 100).unwrap());

    assert!(peerdb.is_address_banned(&address).unwrap());
    let banned_addresses = peerdb
        .get_storage_mut()
        .transaction_ro()
        .unwrap()
        .get_banned_addresses()
        .unwrap();
    assert_eq!(banned_addresses.len(), 1);

    tokio::time::sleep(Duration::from_secs(4)).await;

    assert!(!peerdb.is_address_banned(&address).unwrap());
    let banned_addresses = peerdb
        .get_storage_mut()
        .transaction_ro()
        .unwrap()
        .get_banned_addresses()
        .unwrap();
    assert_eq!(banned_addresses.len(), 0);
}

fn make_peer_info<T, N, A>() -> (N::PeerId, N::Address, PeerInfo<N::PeerId>)
where
    N: NetworkingService<PeerId = PeerId>,
    A: RandomAddressMaker<Address = N::Address>,
{
    let peer_id = PeerId::new();

    (
        peer_id,
        A::new(),
        PeerInfo::<N::PeerId> {
            peer_id,
            network: [1, 2, 3, 4],
            version: common::primitives::semver::SemVer::new(0, 1, 0),
            agent: None,
            subscriptions: [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect(),
        },
    )
}

fn add_active_peer<T, N, A, S>(peerdb: &mut PeerDb<N, S>) -> N::PeerId
where
    N: NetworkingService<PeerId = PeerId>,
    A: RandomAddressMaker<Address = N::Address>,
    S: PeerDbStorage,
{
    let (peer_id, address, info) = make_peer_info::<T, N, A>();
    peerdb.peer_connected(address, Role::Inbound, info);
    peer_id
}
