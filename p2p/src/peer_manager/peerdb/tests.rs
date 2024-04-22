// Copyright (c) 2022-2023 RBB S.r.l
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

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use itertools::Itertools;
use rstest::rstest;

use ::test_utils::random::{make_seedable_rng, Seed};
use common::{chain::config::create_unit_test_config, primitives::time::Time};
use p2p_test_utils::P2pBasicTestTimeGetter;
use randomness::Rng;

use crate::{
    ban_config::BanConfig,
    peer_manager::{
        peerdb::{
            address_data::{self, PURGE_REACHABLE_FAIL_COUNT, PURGE_UNREACHABLE_TIME},
            salt::Salt,
            storage::{KnownAddressState, PeerDbStorageRead},
        },
        peerdb_common::Transactional,
    },
    testing_utils::{
        peerdb_inmemory_store, test_p2p_config, test_p2p_config_with_ban_config,
        test_p2p_config_with_peer_db_config, TestAddressMaker,
    },
};

use super::{
    address_tables::{
        table::Table,
        test_utils::{make_non_colliding_addresses, make_random_address},
    },
    config::PeerDbConfig,
    storage::PeerDbStorage,
    PeerDb,
};

// Ban the peer, check that it's banned.
// Wait for the duration of the ban, check that it's no longer banned.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ban_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let ban_duration = Duration::from_secs(60);
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(test_p2p_config_with_ban_config(BanConfig {
            discouragement_duration: Duration::from_secs(600).into(),
            discouragement_threshold: Default::default(),
        })),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);
    peerdb.ban(address.as_bannable(), ban_duration);

    // The address is banned.
    assert!(peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 1);
    assert_eq!(banned_addresses[0].0, address.as_bannable());
    assert_eq!(
        banned_addresses[0].1,
        (time_getter.get_time_getter().get_time() + ban_duration).unwrap()
    );

    // But not discouraged.
    assert!(!peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 0);

    time_getter.advance_time(ban_duration);

    // Banned addresses are updated in the `heartbeat` function
    peerdb.heartbeat();

    // The address is no longer banned.
    assert!(!peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 0);

    // And still not discouraged.
    assert!(!peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 0);

    assert_addr_consistency(&peerdb);
}

// Ban the peer twice, check that the second duration overrides the first one.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ban_peer_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let ban_duration1 = Duration::from_secs(60);
    let ban_duration2 = Duration::from_secs(120);
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(test_p2p_config_with_ban_config(BanConfig {
            discouragement_duration: Duration::from_secs(600).into(),
            discouragement_threshold: Default::default(),
        })),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);

    peerdb.ban(address.as_bannable(), ban_duration1);

    // The address is banned for ban_duration1.
    assert!(peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 1);
    assert_eq!(banned_addresses[0].0, address.as_bannable());
    assert_eq!(
        banned_addresses[0].1,
        (time_getter.get_time_getter().get_time() + ban_duration1).unwrap()
    );

    peerdb.ban(address.as_bannable(), ban_duration2);

    // The address is banned for ban_duration2.
    assert!(peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 1);
    assert_eq!(banned_addresses[0].0, address.as_bannable());
    assert_eq!(
        banned_addresses[0].1,
        (time_getter.get_time_getter().get_time() + ban_duration2).unwrap()
    );

    assert_addr_consistency(&peerdb);
}

// Ban the peer for Duration::MAX; the ban end time should be the maximum possible time.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ban_for_max_duration(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(test_p2p_config()),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);

    peerdb.ban(address.as_bannable(), Duration::MAX);

    // The address is banned until the maximum possible time.
    assert!(peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 1);
    assert_eq!(banned_addresses[0].0, address.as_bannable());
    assert_eq!(
        banned_addresses[0].1,
        Time::from_duration_since_epoch(Duration::MAX)
    );

    assert_addr_consistency(&peerdb);
}

// Discourage the peer, check that it's discouraged.
// Wait for the duration of the discouragement, check that it's no longer discouraged.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn discourage_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let discouragement_duration = Duration::from_secs(60);
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(test_p2p_config_with_ban_config(BanConfig {
            discouragement_duration: discouragement_duration.into(),
            discouragement_threshold: Default::default(),
        })),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);
    peerdb.discourage(address.as_bannable());

    // The address is discouraged.
    assert!(peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 1);
    assert_eq!(discouraged_addresses[0].0, address.as_bannable());
    assert_eq!(
        discouraged_addresses[0].1,
        (time_getter.get_time_getter().get_time() + discouragement_duration).unwrap()
    );

    // But not banned.
    assert!(!peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 0);

    time_getter.advance_time(discouragement_duration);

    // Discouraged addresses are updated in the `heartbeat` function
    peerdb.heartbeat();

    // The address is no longer discouraged.
    assert!(!peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 0);

    // And still not banned.
    assert!(!peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 0);

    assert_addr_consistency(&peerdb);
}

// Discourage the peer, wait for some time then discourage it again. The discouragement duration
// should be refreshed.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn discourage_peer_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let discouragement_duration = Duration::from_secs(60);
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(test_p2p_config_with_ban_config(BanConfig {
            discouragement_duration: discouragement_duration.into(),
            discouragement_threshold: Default::default(),
        })),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);

    peerdb.discourage(address.as_bannable());

    // The address is discouraged for discouragement_duration.
    assert!(peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 1);
    assert_eq!(discouraged_addresses[0].0, address.as_bannable());
    assert_eq!(
        discouraged_addresses[0].1,
        (time_getter.get_time_getter().get_time() + discouragement_duration).unwrap()
    );

    time_getter.advance_time(discouragement_duration / 2);

    // The peer is still discouraged, the remaining duration is discouragement_duration/2.
    assert!(peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 1);
    assert_eq!(discouraged_addresses[0].0, address.as_bannable());
    assert_eq!(
        discouraged_addresses[0].1,
        (time_getter.get_time_getter().get_time() + discouragement_duration / 2).unwrap()
    );

    // Discourage it the second time
    peerdb.discourage(address.as_bannable());

    // The address is again discouraged for the full discouragement_duration.
    assert!(peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 1);
    assert_eq!(discouraged_addresses[0].0, address.as_bannable());
    assert_eq!(
        discouraged_addresses[0].1,
        (time_getter.get_time_getter().get_time() + discouragement_duration).unwrap()
    );

    assert_addr_consistency(&peerdb);
}

// Discourage the peer for Duration::MAX; the discouragement end time should be
// the maximum possible time.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn discourage_for_max_duration(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(test_p2p_config_with_ban_config(BanConfig {
            discouragement_duration: Duration::MAX.into(),
            discouragement_threshold: Default::default(),
        })),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);
    peerdb.discourage(address.as_bannable());

    // The address is discouraged until the maximum possible time.
    assert!(peerdb.is_address_discouraged(&address.as_bannable()));
    let discouraged_addresses =
        peerdb.storage.transaction_ro().unwrap().get_discouraged_addresses().unwrap();
    assert_eq!(discouraged_addresses.len(), 1);
    assert_eq!(discouraged_addresses[0].0, address.as_bannable());
    assert_eq!(
        discouraged_addresses[0].1,
        Time::from_duration_since_epoch(Duration::MAX)
    );

    assert_addr_consistency(&peerdb);
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connected_unreachable(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let p2p_config = Arc::new(test_p2p_config());
    let chain_config = create_unit_test_config();
    let mut peerdb = PeerDb::new(
        &chain_config,
        p2p_config,
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);
    peerdb.peer_discovered(address);
    peerdb.report_outbound_failure(address);
    assert!(peerdb.addresses.get(&address).unwrap().is_unreachable());

    // User requests connection to the currently unreachable node via RPC and connection succeeds.
    // PeerDb should process that normally.
    peerdb.outbound_peer_connected(address);
    assert!(peerdb.addresses.get(&address).unwrap().is_connected());

    assert_addr_consistency(&peerdb);
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connected_unknown(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let p2p_config = Arc::new(test_p2p_config());
    let mut peerdb = PeerDb::new(
        &chain_config,
        p2p_config,
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address(&mut rng);

    // User requests connection to some unknown node via RPC and connection succeeds.
    // PeerDb should process that normally.
    peerdb.outbound_peer_connected(address);
    assert!(peerdb.addresses.get(&address).unwrap().is_connected());

    assert_addr_consistency(&peerdb);
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn anchor_peers(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let p2p_config = Arc::new(test_p2p_config());

    let mut peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let mut anchors = [
        TestAddressMaker::new_random_address(&mut rng),
        TestAddressMaker::new_random_address(&mut rng),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    peerdb.set_anchors(anchors.clone());
    assert_eq!(*peerdb.anchors(), anchors);

    let new_address = TestAddressMaker::new_random_address(&mut rng);
    anchors.insert(new_address);
    peerdb.set_anchors(anchors.clone());
    assert_eq!(*peerdb.anchors(), anchors);

    let mut peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        peerdb.storage,
    )
    .unwrap();
    assert_eq!(*peerdb.anchors(), anchors);

    anchors.remove(&new_address);
    peerdb.set_anchors(anchors.clone());
    assert_eq!(*peerdb.anchors(), anchors);
    let peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        peerdb.storage,
    )
    .unwrap();
    assert_eq!(*peerdb.anchors(), anchors);

    assert_addr_consistency(&peerdb);
}

// Call 'remove_address' on new and tried addresses, check that the db is
// in consistent state.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn remove_addr(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let p2p_config = Arc::new(test_p2p_config_with_peer_db_config(PeerDbConfig {
        addr_tables_bucket_size: 10.into(),
        new_addr_table_bucket_count: 10.into(),
        tried_addr_table_bucket_count: 10.into(),
        salt: Some(Salt::new_random_with_rng(&mut rng)),
    }));

    let mut peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let addr_count = 10;

    let new_addrs = make_non_colliding_addresses(&[new_addr_table(&peerdb)], addr_count, &mut rng);
    let tried_addrs =
        make_non_colliding_addresses(&[tried_addr_table(&peerdb)], addr_count, &mut rng);

    let (new_addrs_to_remove, new_addrs_to_keep) = split_in_two_sets(&new_addrs, &mut rng);
    let (tried_addrs_to_remove, tried_addrs_to_keep) = split_in_two_sets(&tried_addrs, &mut rng);

    // Reserved addresses are often treated differently, so mark two of the to-remove addresses
    // as reserved.
    peerdb.add_reserved_node(*new_addrs_to_remove.first().unwrap());
    peerdb.add_reserved_node(*tried_addrs_to_remove.first().unwrap());

    for addr in &new_addrs {
        peerdb.peer_discovered(*addr);
    }

    for addr in &tried_addrs {
        peerdb.outbound_peer_connected(*addr);
    }

    for addr in new_addrs_to_remove.iter().chain(tried_addrs_to_remove.iter()) {
        peerdb.remove_address(addr);
    }

    let new_addrs_remaining = new_addr_table(&peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    let tried_addrs_remaining =
        tried_addr_table(&peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    assert_eq_sets(new_addrs_remaining.iter(), new_addrs_to_keep.iter());
    assert_eq_sets(tried_addrs_remaining.iter(), tried_addrs_to_keep.iter());
    assert_addr_consistency(&peerdb);
}

// Generate some Unreachable addresses, check that they are removed by 'heartbeat' once the
// corresponding conditions are met.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn remove_unreachable(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let p2p_config = Arc::new(test_p2p_config_with_peer_db_config(PeerDbConfig {
        addr_tables_bucket_size: 10.into(),
        new_addr_table_bucket_count: 10.into(),
        tried_addr_table_bucket_count: 10.into(),
        salt: Some(Salt::new_random_with_rng(&mut rng)),
    }));

    let mut peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let addr_count = 10;

    let new_addrs = make_non_colliding_addresses(&[new_addr_table(&peerdb)], addr_count, &mut rng);
    let tried_addrs =
        make_non_colliding_addresses(&[tried_addr_table(&peerdb)], addr_count, &mut rng);
    let tried_addrs_as_set = tried_addrs.iter().copied().collect::<BTreeSet<_>>();

    for addr in &new_addrs {
        peerdb.peer_discovered(*addr);
    }

    for addr in &tried_addrs {
        peerdb.outbound_peer_connected(*addr);
    }

    assert_eq!(new_addr_table(&peerdb).addr_count(), addr_count);
    assert_eq!(tried_addr_table(&peerdb).addr_count(), addr_count);
    assert_addr_consistency(&peerdb);

    let (new_addrs_unreachable, new_addrs_reachable) = split_in_two_sets(&new_addrs, &mut rng);
    let (tried_addrs_unreachable, tried_addrs_reachable) =
        split_in_two_sets(&tried_addrs, &mut rng);

    for addr in &new_addrs_unreachable {
        peerdb.report_outbound_failure(*addr);
    }

    for addr in &tried_addrs_unreachable {
        peerdb.outbound_peer_disconnected(*addr);
        peerdb.report_outbound_failure(*addr);
    }

    assert_addr_consistency(&peerdb);

    time_getter.advance_time(PURGE_UNREACHABLE_TIME);
    peerdb.heartbeat();

    // The failed "new" addresses have been removed, but the "tried" ones are still there, because
    // they were reachable once.
    let new_addrs_remaining = new_addr_table(&peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    let tried_addrs_remaining =
        tried_addr_table(&peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    assert_eq_sets(new_addrs_remaining.iter(), new_addrs_reachable.iter());
    assert_eq_sets(tried_addrs_remaining.iter(), tried_addrs_as_set.iter());
    assert_addr_consistency(&peerdb);

    // Call report_outbound_failure until the fail count reaches the limit.
    for addr in &tried_addrs_unreachable {
        for _ in 0..PURGE_REACHABLE_FAIL_COUNT - 1 {
            peerdb.report_outbound_failure(*addr);
        }
    }

    time_getter.advance_time(PURGE_UNREACHABLE_TIME);
    peerdb.heartbeat();

    // Now the failed "tried" addresses are also removed.
    let new_addrs_remaining = new_addr_table(&peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    let tried_addrs_remaining =
        tried_addr_table(&peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    assert_eq_sets(new_addrs_remaining.iter(), new_addrs_reachable.iter());
    assert_eq_sets(tried_addrs_remaining.iter(), tried_addrs_reachable.iter());
    assert_addr_consistency(&peerdb);
}

// Check that "new" addresses are correctly evicted from the table when the address count limit
// is exceeded.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn new_addr_count_limit(#[case] seed: Seed, #[values(true, false)] use_reserved_nodes: bool) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();

    let bucket_size = 10;
    let bucket_count = 10;
    let max_addrs_in_one_table = bucket_count * bucket_size;
    let p2p_config = Arc::new(test_p2p_config_with_peer_db_config(PeerDbConfig {
        addr_tables_bucket_size: bucket_size.into(),
        new_addr_table_bucket_count: bucket_count.into(),
        tried_addr_table_bucket_count: bucket_count.into(),
        salt: Some(Salt::new_random_with_rng(&mut rng)),
    }));

    let mut peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    assert_eq!(new_addr_table(&peerdb).addr_count(), 0);
    assert_eq!(tried_addr_table(&peerdb).addr_count(), 0);

    for i in 0..max_addrs_in_one_table * 10 {
        let addr = make_random_address(&mut rng);

        if use_reserved_nodes && i % 3 == 0 {
            peerdb.add_reserved_node(addr);
        }

        peerdb.peer_discovered(addr);

        if use_reserved_nodes && i % 3 == 1 {
            peerdb.add_reserved_node(addr);
        }

        let new_addr_count = new_addr_table(&peerdb).addr_count();

        if !use_reserved_nodes || i >= 3 {
            assert!(new_addr_count > 0);
        }

        assert!(new_addr_count <= max_addrs_in_one_table);
        assert_eq!(tried_addr_table(&peerdb).addr_count(), 0);
        assert_addr_consistency(&peerdb);
    }
}

// Check that "tried" addresses are correctly evicted from the table when the address count limit
// is exceeded.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn tried_addr_count_limit(#[case] seed: Seed, #[values(true, false)] use_reserved_nodes: bool) {
    let mut rng = make_seedable_rng(seed);

    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();

    let bucket_size = 10;
    let bucket_count = 10;
    let max_addrs_in_one_table = bucket_count * bucket_size;
    let p2p_config = Arc::new(test_p2p_config_with_peer_db_config(PeerDbConfig {
        addr_tables_bucket_size: bucket_size.into(),
        new_addr_table_bucket_count: bucket_count.into(),
        tried_addr_table_bucket_count: bucket_count.into(),
        salt: Some(Salt::new_random_with_rng(&mut rng)),
    }));

    let mut peerdb = PeerDb::new(
        &chain_config,
        Arc::clone(&p2p_config),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    assert_eq!(new_addr_table(&peerdb).addr_count(), 0);
    assert_eq!(tried_addr_table(&peerdb).addr_count(), 0);

    for i in 0..max_addrs_in_one_table * 10 {
        let addr = make_random_address(&mut rng);

        if use_reserved_nodes && i % 3 == 0 {
            peerdb.add_reserved_node(addr);
        }

        peerdb.outbound_peer_connected(addr);

        if use_reserved_nodes && i % 3 == 1 {
            peerdb.add_reserved_node(addr);
        }

        let tried_addr_count = tried_addr_table(&peerdb).addr_count();
        assert!(tried_addr_count > 0);
        assert!(tried_addr_count <= max_addrs_in_one_table);
        assert!(new_addr_table(&peerdb).addr_count() <= max_addrs_in_one_table);
        assert_addr_consistency(&peerdb);
    }
}

// Check that `select_non_reserved_outbound_addresses` selects roughly the same number of new and
// tried addresses, even if the number of existing addresses differ significantly.
// Note that this test can't be random, so we choose a predefined seed for it and repeat the
// body several times.
#[tracing::instrument]
#[rstest]
#[trace]
fn new_tried_addr_selection_frequency() {
    let mut rng = make_seedable_rng(Seed(123));

    let bucket_size = 1000;
    let bucket_count = 100;
    let addr_count1 = 1000;
    let addr_count2 = 100;
    let count_to_select_range = 50..100;
    let empty_addr_groups_set = BTreeSet::<_>::new();

    for _ in 0..3 {
        for (new_addr_count, tried_addr_count) in
            [(addr_count1, addr_count2), (addr_count2, addr_count1)]
        {
            let db_store = peerdb_inmemory_store();
            let time_getter = P2pBasicTestTimeGetter::new();
            let chain_config = create_unit_test_config();

            let p2p_config = Arc::new(test_p2p_config_with_peer_db_config(PeerDbConfig {
                addr_tables_bucket_size: bucket_size.into(),
                new_addr_table_bucket_count: bucket_count.into(),
                tried_addr_table_bucket_count: bucket_count.into(),
                salt: Some(Salt::new_random_with_rng(&mut rng)),
            }));

            let mut peerdb = PeerDb::new(
                &chain_config,
                Arc::clone(&p2p_config),
                time_getter.get_time_getter(),
                db_store,
            )
            .unwrap();
            // We'll be adding lots of addresses and the checks will cause a huge slowdown.
            peerdb.address_tables.set_should_check_consistency(false);

            let new_addrs = make_non_colliding_addresses(
                &[peerdb.address_tables.new_addr_table()],
                new_addr_count,
                &mut rng,
            );
            let tried_addrs = make_non_colliding_addresses(
                &[peerdb.address_tables.tried_addr_table()],
                tried_addr_count,
                &mut rng,
            );

            for addr in new_addrs {
                peerdb.peer_discovered(addr);
            }
            for addr in tried_addrs {
                peerdb.outbound_peer_connected(addr);
                // Mark the address as disconnected, otherwise it won't be selected by
                // select_non_reserved_outbound_addresses.
                peerdb.outbound_peer_disconnected(addr);
            }

            // Advance time, so that previously connected addresses can be selected again.
            time_getter.advance_time(address_data::MAX_DELAY_REACHABLE);

            let mut total_selected_new_addrs = 0;
            let mut total_selected_tried_addrs = 0;
            for _ in 0..100 {
                let count_to_select = rng.gen_range(count_to_select_range.clone());
                let selected_addrs = peerdb.select_non_reserved_outbound_addresses_with_rng(
                    &empty_addr_groups_set,
                    &|_| true,
                    count_to_select,
                    &mut rng,
                );

                let mut selected_new_addrs = 0;
                let mut selected_tried_addrs = 0;

                for addr in selected_addrs {
                    let is_in_new = peerdb.address_tables.is_in_new(&addr);
                    let is_in_tried = peerdb.address_tables.is_in_tried(&addr);

                    // Sanity check
                    assert_ne!(is_in_new, is_in_tried);

                    if is_in_new {
                        selected_new_addrs += 1;
                    } else {
                        selected_tried_addrs += 1;
                    }
                }

                total_selected_new_addrs += selected_new_addrs;
                total_selected_tried_addrs += selected_tried_addrs;
            }

            let min = std::cmp::min(total_selected_new_addrs, total_selected_tried_addrs);
            let max = std::cmp::max(total_selected_new_addrs, total_selected_tried_addrs);
            let ratio = max as f64 / min as f64;
            assert!(ratio <= 1.1);
        }
    }
}

fn assert_eq_sets<T, I1, I2>(iter1: I1, iter2: I2)
where
    I1: Iterator<Item = T>,
    I2: Iterator<Item = T>,
    T: Eq + Debug,
{
    assert_eq!(iter1.zip_eq(iter2).find(|(val1, val2)| val1 != val2), None);
}

fn assert_eq_sets_if_not_in<T, I1, I2>(iter1: I1, iter2: I2, items_to_ignore: &BTreeSet<T>)
where
    I1: Iterator<Item = T>,
    I2: Iterator<Item = T>,
    T: Eq + Ord + Debug,
{
    assert_eq_sets(
        iter1.filter(|a| !items_to_ignore.contains(a)),
        iter2.filter(|a| !items_to_ignore.contains(a)),
    );
}

/// Split the passed items into two sets of random (but usually roughly equal) sizes.
/// The first set is guaranteed to be non-empty (unless `items` is itself empty).
fn split_in_two_sets<T>(items: &[T], rng: &mut impl Rng) -> (BTreeSet<T>, BTreeSet<T>)
where
    T: Eq + Ord + Clone,
{
    let mut first = BTreeSet::new();
    let mut second = BTreeSet::new();

    for (idx, item) in items.iter().enumerate() {
        let is_last = idx == items.len() - 1;
        if rng.gen::<u32>() % 2 == 0 || (is_last && first.is_empty()) {
            first.insert(item.clone());
        } else {
            second.insert(item.clone());
        }
    }

    (first, second)
}

fn assert_addr_consistency<S: PeerDbStorage>(peerdb: &PeerDb<S>) {
    // Check that addresses in the new table are distinct.
    let new_addr_count = new_addr_table(peerdb).addr_count();
    let new_addrs = new_addr_table(peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(new_addrs.len(), new_addr_count);
    // Check that addresses in the tried table are distinct.
    let tried_addr_count = tried_addr_table(peerdb).addr_count();
    let tried_addrs = tried_addr_table(peerdb).addr_iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(tried_addrs.len(), tried_addr_count);
    // Check that the tables are disjoint.
    assert!(new_addrs.is_disjoint(&tried_addrs));

    let addrs_in_both_tables = new_addrs.union(&tried_addrs).copied().collect::<BTreeSet<_>>();
    let db_addrs = {
        let tx = peerdb.storage.transaction_ro().unwrap();
        tx.get_known_addresses().unwrap().iter().copied().collect::<BTreeMap<_, _>>()
    };

    // Addresses in the db and in peerdb.addresses are the same, if not taking "reserved"
    // ones into account.
    assert_eq_sets_if_not_in(
        db_addrs.keys().copied(),
        peerdb.addresses.keys().copied(),
        &peerdb.reserved_nodes,
    );

    // Addresses in the db and in the tables are the same, if not taking "reserved"
    // ones into account.
    assert_eq_sets_if_not_in(
        db_addrs.keys().copied(),
        addrs_in_both_tables.iter().copied(),
        &peerdb.reserved_nodes,
    );

    // Check that all "reserved" addresses are also in peerdb.addresses.
    for addr in &peerdb.reserved_nodes {
        assert!(peerdb.addresses.contains_key(addr));
    }

    // Check that addresses in a table are represented in the db with the correct "state".
    for addr in &new_addrs {
        assert_eq!(*db_addrs.get(addr).unwrap(), KnownAddressState::New);
    }
    for addr in &tried_addrs {
        assert_eq!(*db_addrs.get(addr).unwrap(), KnownAddressState::Tried);
    }
}

fn new_addr_table<S>(peerdb: &PeerDb<S>) -> &Table {
    peerdb.address_tables.new_addr_table()
}

fn tried_addr_table<S>(peerdb: &PeerDb<S>) -> &Table {
    peerdb.address_tables.tried_addr_table()
}
