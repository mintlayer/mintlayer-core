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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use common::{
    chain::config::create_unit_test_config, primitives::user_agent::mintlayer_core_user_agent,
};
use p2p_test_utils::P2pBasicTestTimeGetter;

use crate::{
    config::P2pConfig,
    error::{DialError, P2pError},
    peer_manager::{peerdb::storage::PeerDbStorageRead, peerdb_common::Transactional},
    testing_utils::{peerdb_inmemory_store, test_p2p_config, TestAddressMaker},
};

use super::PeerDb;

#[tracing::instrument]
#[test]
fn unban_peer() {
    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(P2pConfig {
            ban_duration: Duration::from_secs(60).into(),

            bind_addresses: Default::default(),
            socks5_proxy: None,
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            ban_threshold: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            enable_block_relay_peers: Default::default(),
            connection_count_limits: Default::default(),
            protocol_config: Default::default(),
        }),
        time_getter.get_time_getter(),
        db_store,
    )
    .unwrap();

    let address = TestAddressMaker::new_random_address();
    peerdb.ban(address.as_bannable());

    assert!(peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 1);

    time_getter.advance_time(Duration::from_secs(120));

    // Banned addresses updated in the `heartbeat` function
    peerdb.heartbeat();

    assert!(!peerdb.is_address_banned(&address.as_bannable()));
    let banned_addresses = peerdb.storage.transaction_ro().unwrap().get_banned_addresses().unwrap();
    assert_eq!(banned_addresses.len(), 0);
}

#[tracing::instrument]
#[test]
fn connected_unreachable() {
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

    let address = TestAddressMaker::new_random_address();
    peerdb.peer_discovered(address);
    peerdb.report_outbound_failure(
        address,
        &P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
    );
    assert!(peerdb.addresses.get(&address).unwrap().is_unreachable());

    // User requests connection to the currently unreachable node via RPC and connection succeeds.
    // PeerDb should process that normally.
    peerdb.outbound_peer_connected(address);
    assert!(peerdb.addresses.get(&address).unwrap().is_connected());
}

#[tracing::instrument]
#[test]
fn connected_unknown() {
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

    let address = TestAddressMaker::new_random_address();

    // User requests connection to some unknown node via RPC and connection succeeds.
    // PeerDb should process that normally.
    peerdb.outbound_peer_connected(address);
    assert!(peerdb.addresses.get(&address).unwrap().is_connected());
}

#[tracing::instrument]
#[test]
fn anchor_peers() {
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

    let mut anchors =
        [TestAddressMaker::new_random_address(), TestAddressMaker::new_random_address()]
            .into_iter()
            .collect::<BTreeSet<_>>();

    peerdb.set_anchors(anchors.clone());
    assert_eq!(*peerdb.anchors(), anchors);

    let new_address = TestAddressMaker::new_random_address();
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
}
