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

use std::{sync::Arc, time::Duration};

use common::{
    chain::config::create_unit_test_config, primitives::user_agent::mintlayer_core_user_agent,
};
use p2p_test_utils::P2pBasicTestTimeGetter;

use crate::{
    config::P2pConfig,
    error::{DialError, P2pError},
    peer_manager::peerdb::storage::{PeerDbStorageRead, PeerDbTransactional},
    testing_utils::{peerdb_inmemory_store, test_p2p_config, TestAddressMaker},
};

use super::PeerDb;

#[test]
fn unban_peer() {
    let db_store = peerdb_inmemory_store();
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = create_unit_test_config();
    let mut peerdb = PeerDb::<_>::new(
        &chain_config,
        Arc::new(P2pConfig {
            bind_addresses: Default::default(),
            socks5_proxy: None,
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            max_inbound_connections: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Duration::from_secs(60).into(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            msg_header_count_limit: Default::default(),
            msg_max_locator_count: Default::default(),
            max_request_blocks_count: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
            sync_stalling_timeout: Default::default(),
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
