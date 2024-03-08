// Copyright (c) 2021-2024 RBB S.r.l
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

use p2p_test_utils::{run_with_timeout, P2pBasicTestTimeGetter};

use crate::{
    error::{DialError, P2pError},
    peer_manager,
    testing_utils::{
        make_transport_with_local_addr_in_group, test_p2p_config, TestTransportChannel,
        TestTransportMaker, TEST_PROTOCOL_VERSION,
    },
    tests::helpers::{node_wait_for_connection_to, node_wait_for_disconnection, TestNode},
};

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disable_networking() {
    run_with_timeout(disable_networking_impl()).await;
}

async fn disable_networking_impl() {
    type Transport = <TestTransportChannel as TestTransportMaker>::Transport;

    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    // Start test_node with networking disabled.
    let mut test_node = TestNode::<Transport>::start(
        false,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        make_transport_with_local_addr_in_group(0),
        TestTransportChannel::make_address(),
        TEST_PROTOCOL_VERSION.into(),
        Some("test_node"),
    )
    .await;

    let other_node1 = TestNode::<Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        make_transport_with_local_addr_in_group(1),
        TestTransportChannel::make_address(),
        TEST_PROTOCOL_VERSION.into(),
        Some("other_node1"),
    )
    .await;

    let other_node2 = TestNode::<Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        make_transport_with_local_addr_in_group(2),
        TestTransportChannel::make_address(),
        TEST_PROTOCOL_VERSION.into(),
        Some("other_node2"),
    )
    .await;

    let other_node1_addr = *other_node1.local_address();
    let other_node2_addr = *other_node2.local_address();

    // Make test_node discover other_node1
    test_node.discover_peer(other_node1_addr).await;

    // Advance time
    time_getter.advance_time(peer_manager::HEARTBEAT_INTERVAL_MAX);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // No connection is established
    let peer_addresses = test_node.get_peer_ip_addresses().await;
    assert_eq!(peer_addresses, BTreeSet::new());

    // Make other_node2 try connecting to test_node; the connection attempt fails.
    let connect_result_receiver = other_node2.start_connecting(*test_node.local_address());
    let connect_result = connect_result_receiver.await.unwrap();
    assert_eq!(
        connect_result,
        Err(P2pError::DialError(DialError::ConnectionRefusedOrTimedOut))
    );
    // For completeness, check that test_node still has no connections.
    let peer_addresses = test_node.get_peer_ip_addresses().await;
    assert_eq!(peer_addresses, BTreeSet::new());

    // Now enable networking
    test_node.enable_networking(true).await;

    // test_node automatically establishes a connection to other_node1
    node_wait_for_connection_to(&test_node, other_node1_addr, None, None).await;

    let peer_addresses = test_node.get_peer_ip_addresses().await;
    assert_eq!(peer_addresses, [other_node1_addr.ip_addr()].into());

    // Make other_node2 try connecting to test_node; the connection attempt succeeds.
    let connect_result_receiver = other_node2.start_connecting(*test_node.local_address());
    let connect_result = connect_result_receiver.await.unwrap();
    assert_eq!(connect_result, Ok(()));

    let peer_addresses = test_node.get_peer_ip_addresses().await;
    assert_eq!(
        peer_addresses,
        [other_node1_addr.ip_addr(), other_node2_addr.ip_addr()].into()
    );

    // Now disable networking again
    test_node.enable_networking(false).await;

    // The previously connected nodes are disconnected.
    node_wait_for_disconnection(&test_node, other_node1_addr, None, None).await;
    node_wait_for_disconnection(&test_node, other_node2_addr, None, None).await;

    let peer_addresses = test_node.get_peer_ip_addresses().await;
    assert_eq!(peer_addresses, BTreeSet::new());

    test_node.join().await;
    other_node1.join().await;
    other_node2.join().await;
}
