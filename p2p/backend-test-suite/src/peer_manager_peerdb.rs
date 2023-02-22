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
    net::{AsBannableAddress, NetworkingService},
    peer_manager::peerdb::{
        storage::{PeerDbStorageRead, PeerDbTransactional},
        PeerDb,
    },
    testing_utils::{peerdb_inmemory_store, P2pTestTimeGetter, RandomAddressMaker},
};

tests![unban_peer,];

async fn unban_peer<T, N, A>()
where
    N: NetworkingService,
    A: RandomAddressMaker<Address = N::Address>,
{
    let db_store = peerdb_inmemory_store();
    let time_getter = P2pTestTimeGetter::new();
    let mut peerdb = PeerDb::<N, _>::new(
        Arc::new(P2pConfig {
            bind_addresses: Default::default(),
            added_nodes: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Duration::from_secs(60).into(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            msg_header_count_limit: Default::default(),
            msg_max_locator_count: Default::default(),
            max_request_blocks_count: Default::default(),
        }),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = A::new();
    peerdb.ban_peer(&address).unwrap();

    assert!(peerdb.is_address_banned(&address.as_bannable()).unwrap());
    let banned_addresses = peerdb
        .get_storage_mut()
        .transaction_ro()
        .unwrap()
        .get_banned_addresses()
        .unwrap();
    assert_eq!(banned_addresses.len(), 1);

    time_getter.advance_time(Duration::from_secs(120)).await;

    assert!(!peerdb.is_address_banned(&address.as_bannable()).unwrap());
    let banned_addresses = peerdb
        .get_storage_mut()
        .transaction_ro()
        .unwrap()
        .get_banned_addresses()
        .unwrap();
    assert_eq!(banned_addresses.len(), 0);
}
