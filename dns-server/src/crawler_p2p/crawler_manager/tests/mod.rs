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
use common::primitives::semver::SemVer;
use p2p::{
    error::{P2pError, ProtocolError},
    types::socket_address::SocketAddress,
};
use p2p_test_utils::{expect_no_recv, expect_recv};
use rstest::rstest;
use test_utils::random::{Seed, make_seedable_rng};

use crate::{
    crawler_p2p::{
        crawler::{address_data::SoftwareInfo, BanDuration, BanThreshold},
        crawler_manager::tests::mock_manager::{
            advance_time, assert_banned_addresses, assert_known_addresses, test_crawler,
            ErraticNodeConnectError,
        },
    },
    dns_server::DnsServerCommand,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn basic(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node_soft_info = SoftwareInfo {
        user_agent: "foo".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node_addr], &mut rng);

    // Node goes online, DNS record added
    state.node_online(node_addr, node_soft_info.clone());
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node_addr.socket_addr().ip(), node_soft_info.clone())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info.clone())]);

    // Node goes offline, DNS record removed
    state.node_offline(node_addr);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::DelAddress(node_addr.socket_addr().ip())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info.clone())]);

    // Node goes online again, DNS record added
    state.node_online(node_addr, node_soft_info.clone());
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node_addr.socket_addr().ip(), node_soft_info.clone())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info)]);
}

// Node comes offline and back online, but with different software info.
// The new info should be stored in the db.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn software_info_update(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node_soft_info1 = SoftwareInfo {
        user_agent: "foo1".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };
    let node_soft_info2 = SoftwareInfo {
        user_agent: "foo2".try_into().unwrap(),
        version: SemVer::new(2, 3, 4),
    };

    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node_addr], &mut rng);

    // Node goes online.
    state.node_online(node_addr, node_soft_info1.clone());
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node_addr.socket_addr().ip(), node_soft_info1.clone())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info1.clone())]);

    // Node goes offline.
    state.node_offline(node_addr);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::DelAddress(node_addr.socket_addr().ip())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info1)]);

    // Node goes online again with a different software info.
    state.node_online(node_addr, node_soft_info2.clone());
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node_addr.socket_addr().ip(), node_soft_info2.clone())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info2)]);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn long_offline(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node_soft_info = SoftwareInfo {
        user_agent: "foo".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(vec![node_addr], &mut rng);

    // Two weeks passed
    advance_time(
        &mut crawler,
        &time_getter,
        Duration::from_secs(3600),
        14 * 24,
    )
    .await;

    // Node goes online, DNS record is added in 24 hours
    state.node_online(node_addr, node_soft_info.clone());
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node_addr.socket_addr().ip(), node_soft_info.clone())
    );

    assert_known_addresses(&crawler, &[(node_addr, node_soft_info)]);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn announced_online(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node1_soft_info = SoftwareInfo {
        user_agent: "foo1".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };
    let node2_addr: SocketAddress = "1.2.3.5:3031".parse().unwrap();
    let node2_soft_info = SoftwareInfo {
        user_agent: "foo2".try_into().unwrap(),
        version: SemVer::new(2, 3, 4),
    };
    let node3_addr: SocketAddress = "[2a00::1]:3031".parse().unwrap();
    let node3_soft_info = SoftwareInfo {
        user_agent: "foo3".try_into().unwrap(),
        version: SemVer::new(3, 4, 5),
    };
    let (mut crawler, state, mut command_rx, time_getter) =
        test_crawler(vec![node1_addr], &mut rng);

    state.node_online(node1_addr, node1_soft_info.clone());
    state.node_online(node2_addr, node2_soft_info.clone());
    state.node_online(node3_addr, node3_soft_info.clone());

    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node1_addr.socket_addr().ip(), node1_soft_info.clone())
    );

    state.announce_address(node1_addr, node2_addr);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node2_addr.socket_addr().ip(), node2_soft_info.clone())
    );

    state.announce_address(node2_addr, node3_addr);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node3_addr.socket_addr().ip(), node3_soft_info.clone())
    );

    assert_known_addresses(
        &crawler,
        &[
            (node1_addr, node1_soft_info),
            (node2_addr, node2_soft_info),
            (node3_addr, node3_soft_info),
        ],
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn announced_offline(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node1_soft_info = SoftwareInfo {
        user_agent: "foo1".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };
    let node2_addr: SocketAddress = "1.2.3.5:3031".parse().unwrap();
    let node2_soft_info = SoftwareInfo {
        user_agent: "foo2".try_into().unwrap(),
        version: SemVer::new(2, 3, 4),
    };
    let (mut crawler, state, mut command_rx, time_getter) =
        test_crawler(vec![node1_addr], &mut rng);

    state.node_online(node1_addr, node1_soft_info.clone());

    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node1_addr.socket_addr().ip(), node1_soft_info.clone())
    );
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 1);

    // Check that the crawler tries to connect to an offline node just once
    state.announce_address(node1_addr, node2_addr);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 2);

    // Check that the crawler tries to connect if the same address is announced later
    state.node_online(node2_addr, node2_soft_info.clone());
    state.announce_address(node1_addr, node2_addr);
    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node2_addr.socket_addr().ip(), node2_soft_info.clone())
    );
    assert_eq!(state.connection_attempts.lock().unwrap().len(), 3);

    assert_known_addresses(
        &crawler,
        &[(node1_addr, node1_soft_info), (node2_addr, node2_soft_info)],
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn private_ip(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1_addr: SocketAddress = "1.0.0.1:3031".parse().unwrap();
    let node2_addr: SocketAddress = "[2a00::1]:3031".parse().unwrap();
    let node3_addr: SocketAddress = "192.168.0.1:3031".parse().unwrap();
    let node4_addr: SocketAddress = "[fe80::1]:3031".parse().unwrap();
    let node5_addr: SocketAddress = "1.0.0.2:12345".parse().unwrap();
    let node6_addr: SocketAddress = "[2a00::2]:12345".parse().unwrap();
    let (mut crawler, state, mut command_rx, time_getter) = test_crawler(
        vec![node1_addr, node2_addr, node3_addr, node4_addr, node5_addr, node6_addr],
        &mut rng,
    );

    let node_soft_info = SoftwareInfo {
        user_agent: "foo".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    state.node_online(node1_addr, node_soft_info.clone());
    state.node_online(node2_addr, node_soft_info.clone());
    state.node_online(node3_addr, node_soft_info.clone());
    state.node_online(node4_addr, node_soft_info.clone());
    state.node_online(node5_addr, node_soft_info.clone());
    state.node_online(node6_addr, node_soft_info.clone());

    advance_time(&mut crawler, &time_getter, Duration::from_secs(60), 24 * 60).await;

    // Check that only nodes with public addresses and on the default port are added to DNS
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node1_addr.socket_addr().ip(), node_soft_info.clone())
    );
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node2_addr.socket_addr().ip(), node_soft_info.clone())
    );
    expect_no_recv!(command_rx);

    // Check that all reachable nodes are stored in the DB
    assert_known_addresses(
        &crawler,
        &[
            (node1_addr, node_soft_info.clone()),
            (node2_addr, node_soft_info.clone()),
            (node3_addr, node_soft_info.clone()),
            (node4_addr, node_soft_info.clone()),
            (node5_addr, node_soft_info.clone()),
            (node6_addr, node_soft_info.clone()),
        ],
    );
}

// 1) Create an erratic node, such that connecting to it produces
// ConnectivityEvent::MisbehavedOnHandshake, and check that it is banned by normal nodes.
// 2) Report one of the connected node as Misbehaved; check that it is banned by normal nodes.
// 3) Bring the previously erratic node from (1) back online again, wait for its ban time to expire,
// check that it's no longer banned and that its address is added to DNS.
// 4) Wait for the misbehaved node's (i.e the one from (2)) ban time to expire, check that it's
// no longer banned and that its address is added to DNS.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn ban_unban(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node2_addr: SocketAddress = "2.3.4.5:3031".parse().unwrap();
    let node3_addr: SocketAddress = "3.4.5.6:3031".parse().unwrap();

    let node_soft_info = SoftwareInfo {
        user_agent: "foo".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    let (mut crawler, state, mut command_rx, time_getter) =
        test_crawler(vec![node1_addr, node2_addr, node3_addr], &mut rng);

    let erratic_node_conn_error = P2pError::ProtocolError(ProtocolError::HandshakeExpected);
    // Sanity check
    assert!(erratic_node_conn_error.ban_score() >= *BanThreshold::default());

    let ban_duration = *BanDuration::default();

    state.node_online(node1_addr, node_soft_info.clone());
    state.erratic_node_online(
        node2_addr,
        node_soft_info.clone(),
        vec![
            ErraticNodeConnectError::MisbehavedOnHandshake(erratic_node_conn_error.clone()),
            // Note: ConnectionError is still expected and is needed for the peer to become disconnected.
            // Moreover, we want to check that sending both MisbehavedOnHandshake and ConnectionError
            // won't cause any problems (e.g. won't lead to a crash).
            ErraticNodeConnectError::ConnectionError(erratic_node_conn_error.clone()),
        ],
    );
    state.node_online(node3_addr, node_soft_info.clone());

    let time_step = Duration::from_secs(60);

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    let node2_ban_end_time = (time_getter.get_time_getter().get_time() + ban_duration).unwrap();

    // Only normal nodes are added to DNS
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node1_addr.socket_addr().ip(), node_soft_info.clone())
    );
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node3_addr.socket_addr().ip(), node_soft_info.clone())
    );
    expect_no_recv!(command_rx);

    // node2 is banned
    assert_banned_addresses(&crawler, &[(node2_addr.as_bannable(), node2_ban_end_time)]);

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    // Report misbehavior for node1; the passed error has big enough ban score, so the node should
    // be banned immediately.
    state.report_misbehavior(node1_addr, erratic_node_conn_error);

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    let node1_ban_end_time = (time_getter.get_time_getter().get_time() + ban_duration).unwrap();

    // Check that it's been removed from DNS.
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::DelAddress(node1_addr.socket_addr().ip())
    );

    // Both bad nodes are now banned.
    assert_banned_addresses(
        &crawler,
        &[
            (node1_addr.as_bannable(), node1_ban_end_time),
            (node2_addr.as_bannable(), node2_ban_end_time),
        ],
    );

    // Node 2 comes online again and now it'll behave correctly. This shouldn't have any immediate effect though.
    state.node_offline(node2_addr);
    state.node_online(node2_addr, node_soft_info.clone());

    // Wait some more time, the nodes should still be banned.
    advance_time(&mut crawler, &time_getter, time_step, 1).await;
    assert_banned_addresses(
        &crawler,
        &[
            (node1_addr.as_bannable(), node1_ban_end_time),
            (node2_addr.as_bannable(), node2_ban_end_time),
        ],
    );
    expect_no_recv!(command_rx);

    // Wait enough time for node2 to be unbanned.
    let time_until_node2_unban =
        (node2_ban_end_time - time_getter.get_time_getter().get_time()).unwrap();
    advance_time(&mut crawler, &time_getter, time_until_node2_unban, 1).await;

    // node2 is no longer banned; its address has been added to DNS.
    assert_banned_addresses(&crawler, &[(node1_addr.as_bannable(), node1_ban_end_time)]);
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node2_addr.socket_addr().ip(), node_soft_info.clone())
    );

    // Wait enough time for node1 to be unbanned.
    let time_until_node1_unban =
        (node1_ban_end_time - time_getter.get_time_getter().get_time()).unwrap();
    advance_time(&mut crawler, &time_getter, time_until_node1_unban, 1).await;

    // node1 is no longer banned; its address has been added to DNS.
    assert_banned_addresses(&crawler, &[]);
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node1_addr.socket_addr().ip(), node_soft_info.clone())
    );
}

// Check that a ConnectivityEvent::ConnectionError that is not accompanied by MisbehavedOnHandshake
// doesn't result in a ban even if the error has a non-zero ban score.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn no_ban_on_connection_error(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1_addr: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let node2_addr: SocketAddress = "2.3.4.5:3031".parse().unwrap();
    let node3_addr: SocketAddress = "3.4.5.6:3031".parse().unwrap();

    let node_soft_info = SoftwareInfo {
        user_agent: "foo".try_into().unwrap(),
        version: SemVer::new(1, 2, 3),
    };

    let (mut crawler, state, mut command_rx, time_getter) =
        test_crawler(vec![node1_addr, node2_addr, node3_addr], &mut rng);

    // Note: this error won't normally appear inside ConnectivityEvent::ConnectionError, we use
    // it just because it's known to have a non-zero ban score.
    let erratic_node_conn_error = P2pError::ProtocolError(ProtocolError::HandshakeExpected);
    // Sanity check
    assert!(erratic_node_conn_error.ban_score() >= *BanThreshold::default());

    state.node_online(node1_addr, node_soft_info.clone());
    state.erratic_node_online(
        node2_addr,
        node_soft_info.clone(),
        vec![ErraticNodeConnectError::ConnectionError(erratic_node_conn_error)],
    );
    state.node_online(node3_addr, node_soft_info.clone());

    let time_step = Duration::from_secs(60);

    advance_time(&mut crawler, &time_getter, time_step, 1).await;

    // Only normal nodes are added to DNS
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node1_addr.socket_addr().ip(), node_soft_info.clone())
    );
    assert_eq!(
        expect_recv!(command_rx),
        DnsServerCommand::AddAddress(node3_addr.socket_addr().ip(), node_soft_info)
    );
    expect_no_recv!(command_rx);

    // But node2 is still not banned
    assert_banned_addresses(&crawler, &[]);
}
