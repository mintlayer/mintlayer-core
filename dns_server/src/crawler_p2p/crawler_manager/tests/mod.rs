// Copyright (c) 2023 RBB S.r.l
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

mod mock_manager;

use std::time::Duration;

use chainstate::ban_score::BanScore;
use p2p::{
    config::{BanDuration, BanThreshold},
    types::socket_address::SocketAddress,
};
use p2p_test_utils::{assert_no_value_in_channel, get_value_from_channel};

use crate::{
    crawler_p2p::crawler_manager::tests::mock_manager::{
        advance_time, assert_banned_addresses, assert_known_addresses,
        erratic_node_connection_error, test_crawler,
    },
    dns_server::DnsServerCommand,
};

#[tokio::test]
async fn basic() {
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    // Node goes online, DNS record added
    state.node_online(node1);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );

    // Node goes offline, DNS record removed
    state.node_offline(node1);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::DelAddress(node1.socket_addr().ip())
    );
}

#[tokio::test]
async fn long_offline() {
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    // Two weeks passed
    advance_time(
        &mut crawler,
        &time_getter,
        Duration::from_secs(3600),
        14 * 24,
    )
    .await;

    // Node goes online, DNS record is added in 24 hours
    state.node_online(node1);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );
}

#[tokio::test]
async fn announced_online() {
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node2: SocketAddress = "1.2.3.5:3031".parse().unwrap();
    let node3: SocketAddress = "[2a00::1]:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    state.node_online(node1);
    state.node_online(node2);
    state.node_online(node3);

    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );

    state.announce_address(node1, node2);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node2.socket_addr().ip())
    );

    state.announce_address(node2, node3);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node3.socket_addr().ip())
    );

    assert_known_addresses(&crawler, &[node1, node2, node3]);
}

#[tokio::test]
async fn announced_offline() {
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node2: SocketAddress = "1.2.3.5:3031".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1]);

    state.node_online(node1);

    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 1);

    // Check that the crawler tries to connect to an offline node just once
    state.announce_address(node1, node2);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 2);

    // Check that the crawler tries to connect if the same address is announced later
    state.node_online(node2);
    state.announce_address(node1, node2);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node2.socket_addr().ip())
    );
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn private_ip() {
    let node1: SocketAddress = "1.0.0.1:3031".parse().unwrap();
    let node2: SocketAddress = "[2a00::1]:3031".parse().unwrap();
    let node3: SocketAddress = "192.168.0.1:3031".parse().unwrap();
    let node4: SocketAddress = "[fe80::1]:3031".parse().unwrap();
    let node5: SocketAddress = "1.0.0.2:12345".parse().unwrap();
    let node6: SocketAddress = "[2a00::2]:12345".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) =
        test_crawler(vec![node1, node2, node3, node4, node5, node6]);

    state.node_online(node1);
    state.node_online(node2);
    state.node_online(node3);
    state.node_online(node4);
    state.node_online(node5);
    state.node_online(node6);

    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;

    // Check that only nodes with public addresses and on the default port are added to DNS
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node2.socket_addr().ip())
    );
    assert_no_value_in_channel(&mut command_rx).await;

    // Check that all reachable nodes are stored in the DB
    assert_known_addresses(&crawler, &[node1, node2, node3, node4, node5, node6]);
}

#[tokio::test]
async fn ban_unban() {
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node2: SocketAddress = "2.3.4.5:3031".parse().unwrap();
    let node3: SocketAddress = "3.4.5.6:3031".parse().unwrap();

    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node1, node2, node3]);

    // Sanity check
    assert!(erratic_node_connection_error().ban_score() >= *BanThreshold::default());

    let ban_duration = *BanDuration::default();

    state.node_online(node1);
    state.erratic_node_online(node2);
    state.node_online(node3);

    let time_step = Duration::from_secs(60);

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    let node2_ban_end_time = (time_getter.get_time_getter().get_time() + ban_duration).unwrap();

    // Only normal nodes are added to DNS
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node3.socket_addr().ip())
    );
    assert_no_value_in_channel(&mut command_rx).await;

    // node2 is banned
    assert_banned_addresses(&crawler, &[(node2.as_bannable(), node2_ban_end_time)]);

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    // Report misbehavior for node1; the passed error has big enough ban score, so the node should
    // be banned immediately.
    state.report_misbehavior(node1, erratic_node_connection_error());

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    let node1_ban_end_time = (time_getter.get_time_getter().get_time() + ban_duration).unwrap();

    // Check that it's been removed from DNS.
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::DelAddress(node1.socket_addr().ip())
    );

    // Both bad nodes are now banned.
    assert_banned_addresses(
        &crawler,
        &[
            (node1.as_bannable(), node1_ban_end_time),
            (node2.as_bannable(), node2_ban_end_time),
        ],
    );

    // Node 2 comes online again and now it'll behave correctly. This shouldn't have any immediate effect though.
    state.node_offline(node2);
    state.node_online(node2);

    // Wait some more time, the nodes should still be banned.
    advance_time(&mut crawler, &time_getter, time_step, 1).await;
    assert_banned_addresses(
        &crawler,
        &[
            (node1.as_bannable(), node1_ban_end_time),
            (node2.as_bannable(), node2_ban_end_time),
        ],
    );
    assert_no_value_in_channel(&mut command_rx).await;

    // Wait enough time for node2 to be unbanned.
    let time_until_node2_unban =
        (node2_ban_end_time - time_getter.get_time_getter().get_time()).unwrap();
    advance_time(&mut crawler, &time_getter, time_until_node2_unban, 1).await;

    // node2 is no longer banned; its address has been added to DNS.
    assert_banned_addresses(&crawler, &[(node1.as_bannable(), node1_ban_end_time)]);
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node2.socket_addr().ip())
    );

    // Wait enough time for node1 to be unbanned.
    let time_until_node1_unban =
        (node1_ban_end_time - time_getter.get_time_getter().get_time()).unwrap();
    advance_time(&mut crawler, &time_getter, time_until_node1_unban, 1).await;

    // node1 is no longer banned; its address has been added to DNS.
    assert_banned_addresses(&crawler, &[]);
    assert_eq!(
        get_value_from_channel(&mut command_rx).await.unwrap(),
        DnsServerCommand::AddAddress(node1.socket_addr().ip())
    );
}
