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

mod mock_crawler;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use chainstate::ban_score::BanScore;
use common::{
    chain::ChainConfig,
    primitives::{time::Time, user_agent::mintlayer_core_user_agent},
};
use p2p::{
    config::{BanDuration, BanThreshold, NodeType},
    error::{DialError, P2pError, ProtocolError},
    net::types::PeerInfo,
    testing_utils::TEST_PROTOCOL_VERSION,
    types::{peer_id::PeerId, socket_address::SocketAddress},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crypto::random::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};

use mock_crawler::test_crawler;

use crate::crawler_p2p::crawler::CrawlerEvent;

use super::CrawlerConfig;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn basic(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let peer1 = PeerId::new();
    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(
        make_config(),
        BTreeSet::new(),
        BTreeMap::new(),
        [node1].into_iter().collect(),
    );

    crawler.timer(Duration::from_secs(100), &mut rng);
    assert_eq!(crawler.pending_connects.len(), 1);
    assert!(crawler.pending_connects.contains(&node1));

    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: make_peer_info(peer1, &chain_config),
        },
        &mut rng,
    );

    assert!(crawler.persistent.contains(&node1));
    assert!(crawler.reachable.contains(&node1));

    let node2: SocketAddress = "4.3.2.1:12345".parse().unwrap();
    let peer2 = PeerId::new();

    crawler.step(
        CrawlerEvent::NewAddress {
            address: node2,
            sender: peer1,
        },
        &mut rng,
    );

    crawler.timer(Duration::from_secs(100), &mut rng);
    assert!(crawler.pending_connects.contains(&node2));

    crawler.step(
        CrawlerEvent::Connected {
            address: node2,
            peer_info: make_peer_info(peer2, &chain_config),
        },
        &mut rng,
    );
    assert!(crawler.persistent.contains(&node2));
    assert!(crawler.reachable.contains(&node2));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = common::chain::config::create_mainnet();

    let nodes = (0..rng.gen_range(0..200))
        .map(|_| {
            if rng.gen_bool(0.8) {
                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen()),
                    chain_config.p2p_port(),
                ))
            } else {
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(
                        rng.gen(),
                        rng.gen(),
                        rng.gen(),
                        rng.gen(),
                        rng.gen(),
                        rng.gen(),
                        rng.gen(),
                        rng.gen(),
                    ),
                    chain_config.p2p_port(),
                    0,
                    0,
                ))
            }
        })
        .map(SocketAddress::new)
        .collect::<Vec<_>>();

    let reserved_count = rng.gen_range(0..5);
    let reserved_nodes = nodes.choose_multiple(&mut rng, reserved_count).cloned().collect();

    let loaded_count = rng.gen_range(0..10);
    let loaded_nodes = nodes.choose_multiple(&mut rng, loaded_count).cloned().collect();

    let mut crawler = test_crawler(make_config(), loaded_nodes, BTreeMap::new(), reserved_nodes);

    for _ in 0..rng.gen_range(0..100000) {
        crawler.timer(Duration::from_secs(rng.gen_range(0..100)), &mut rng);

        // Randomly report a pending outbound connections as failed
        if !crawler.pending_connects.is_empty() && rng.gen_bool(0.5) {
            let address = crawler.pending_connects.iter().choose(&mut rng).cloned().unwrap();
            crawler.step(
                CrawlerEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                },
                &mut rng,
            )
        }

        // Randomly report a pending outbound connection as successful
        if !crawler.pending_connects.is_empty() && rng.gen_bool(0.01) {
            let address = crawler.pending_connects.iter().choose(&mut rng).cloned().unwrap();
            crawler.step(
                CrawlerEvent::Connected {
                    address,
                    peer_info: make_peer_info(PeerId::new(), &chain_config),
                },
                &mut rng,
            )
        }

        // Randomly report a pending outbound connection as successful to an incompatible node
        if !crawler.pending_connects.is_empty() && rng.gen_bool(0.001) {
            let address = crawler.pending_connects.iter().choose(&mut rng).cloned().unwrap();
            crawler.step(
                CrawlerEvent::Connected {
                    address,
                    peer_info: make_peer_info(PeerId::new(), &chain_config),
                },
                &mut rng,
            )
        }

        // Randomly report a pending disconnect request as complete
        if !crawler.pending_disconnects.is_empty() && rng.gen_bool(0.1) {
            let peer_id = crawler.pending_disconnects.iter().choose(&mut rng).cloned().unwrap();
            crawler.step(CrawlerEvent::Disconnected { peer_id }, &mut rng)
        }

        // Randomly send an address announcement request
        if !crawler.peers.is_empty() && rng.gen_bool(0.01) {
            let address = nodes.iter().choose(&mut rng).cloned().unwrap();
            let sender = crawler.peers.keys().choose(&mut rng).cloned().unwrap();
            crawler.step(CrawlerEvent::NewAddress { address, sender }, &mut rng)
        }

        if !crawler.peers.is_empty() && rng.gen_bool(0.001) {
            let peer_id = crawler.peers.keys().choose(&mut rng).cloned().unwrap();
            crawler.step(CrawlerEvent::Disconnected { peer_id }, &mut rng)
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn incompatible_node(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node1: SocketAddress = "1.2.3.4:3031".parse().unwrap();
    let peer1 = PeerId::new();
    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(
        make_config(),
        BTreeSet::new(),
        BTreeMap::new(),
        [node1].into_iter().collect(),
    );

    // Crawler attempts to connect to the specified node
    crawler.timer(Duration::from_secs(100), &mut rng);
    assert!(crawler.pending_connects.contains(&node1));

    // Connection to the node is successful
    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: PeerInfo {
                peer_id: peer1,
                protocol_version: TEST_PROTOCOL_VERSION,
                network: [255, 255, 255, 255],
                software_version: *chain_config.software_version(),
                user_agent: mintlayer_core_user_agent(),
                common_services: NodeType::DnsServer.into(),
            },
        },
        &mut rng,
    );

    // Connection to incompatible node is closed
    assert!(crawler.pending_disconnects.contains(&peer1));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn long_offline(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let loaded_node: SocketAddress = "1.0.0.0:3031".parse().unwrap();
    let added_node: SocketAddress = "2.0.0.0:3031".parse().unwrap();
    let mut crawler = test_crawler(
        make_config(),
        [loaded_node].into_iter().collect(),
        BTreeMap::new(),
        [added_node].into_iter().collect(),
    );
    assert!(crawler.persistent.contains(&loaded_node));

    // Reachable and reserved nodes are offline for two month
    for _ in 0..24 * 60 {
        crawler.timer(Duration::from_secs(3600), &mut rng);
        for address in crawler.pending_connects.clone() {
            crawler.step(
                CrawlerEvent::ConnectionError {
                    address,
                    error: P2pError::DialError(DialError::ConnectionRefusedOrTimedOut),
                },
                &mut rng,
            );
        }
    }
    // Check that there were `PURGE_REACHABLE_FAIL_COUNT` connection attempts
    assert_eq!(
        crawler.connect_requests.iter().filter(|addr| **addr == loaded_node).count() as u32,
        crate::crawler_p2p::crawler::address_data::PURGE_REACHABLE_FAIL_COUNT
    );
    crawler.connect_requests.clear();
    // Old reachable node is removed
    assert!(!crawler.persistent.contains(&loaded_node));

    // Check that the crawler still tries to connect to the added node, but not to the now unreachable node
    for _ in 0..24 * 7 {
        crawler.timer(Duration::from_secs(3600), &mut rng);
    }
    assert!(!crawler.connect_requests.iter().any(|addr| *addr == loaded_node));
    assert!(crawler.connect_requests.iter().any(|addr| *addr == added_node));
    crawler.connect_requests.clear();
}

// Connect to two peers and then send CrawlerEvent::Misbehaved for one of them several times,
// making sure that the ban score is updated accordingly and that eventually the peer is banned.
// Also check that we don't reconnect to the banned peer until the ban end is reached.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ban_misbehaved_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1: SocketAddress = "1.2.3.4:1234".parse().unwrap();
    let peer1 = PeerId::new();
    let node2: SocketAddress = "2.3.4.5:2345".parse().unwrap();
    let peer2 = PeerId::new();

    let test_error = P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned()));
    let test_error_ban_score = test_error.ban_score();
    assert!(test_error_ban_score > 0);
    let ban_threshold = test_error_ban_score * 2;

    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(
        CrawlerConfig {
            ban_duration: BanDuration::new(BAN_DURATION),
            ban_threshold: BanThreshold::new(ban_threshold),
        },
        BTreeSet::new(),
        BTreeMap::new(),
        [node1, node2].into_iter().collect(),
    );

    let times_step = Duration::from_secs(100);

    crawler.timer(times_step, &mut rng);

    crawler.assert_pending_connects(&[node1, node2]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);

    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: make_peer_info(peer1, &chain_config),
        },
        &mut rng,
    );

    crawler.step(
        CrawlerEvent::Connected {
            address: node2,
            peer_info: make_peer_info(peer2, &chain_config),
        },
        &mut rng,
    );

    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer1, peer2]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);

    crawler.step(
        CrawlerEvent::Misbehaved {
            peer_id: peer1,
            error: test_error.clone(),
        },
        &mut rng,
    );

    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer1, peer2]);
    crawler.assert_ban_scores(&[(peer1, test_error_ban_score)]);
    crawler.assert_banned_addresses(&[]);

    let ban_start_time = crawler.now();
    let ban_end_time = (ban_start_time + BAN_DURATION).unwrap();

    crawler.step(
        CrawlerEvent::Misbehaved {
            peer_id: peer1,
            error: test_error,
        },
        &mut rng,
    );

    // The peer is banned.
    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[peer1]);
    crawler.assert_connected_peers(&[peer1, peer2]);
    crawler.assert_ban_scores(&[(peer1, test_error_ban_score * 2)]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);

    crawler.step(CrawlerEvent::Disconnected { peer_id: peer1 }, &mut rng);

    // The peer has become disconnected and its ban score was lost. But it's still banned.
    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer2]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);

    // Wait some (small) time, the peer should still be banned.
    crawler.timer(times_step, &mut rng);

    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer2]);
    crawler.assert_ban_scores(&[(peer1, test_error_ban_score * 10)]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);

    // Sanity check
    assert!(crawler.now() < ban_end_time);

    // Wait for the remaining ban time.
    crawler.timer((ban_end_time - crawler.now()).unwrap(), &mut rng);

    // The peer is no longer banned; instead, it is being connected to.
    crawler.assert_pending_connects(&[node1]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer2]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);
}

// Connect to three peers, where two of them share the same ip address, and then send
// CrawlerEvent::Misbehaved for one of those. Make sure that both peers get disconnected and
// no connect attempts are made until the ban end is reached.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ban_misbehaved_peers_with_same_address(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1: SocketAddress = "1.2.3.4:1234".parse().unwrap();
    let peer1 = PeerId::new();
    let node2: SocketAddress = "2.3.4.5:2345".parse().unwrap();
    let peer2 = PeerId::new();
    let node3: SocketAddress = "1.2.3.4:4321".parse().unwrap();
    let peer3 = PeerId::new();

    assert_eq!(node3.as_bannable(), node1.as_bannable());

    let test_error = P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned()));
    let test_error_ban_score = test_error.ban_score();
    assert!(test_error_ban_score > 0);
    let ban_threshold = test_error_ban_score;

    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(
        CrawlerConfig {
            ban_duration: BanDuration::new(BAN_DURATION),
            ban_threshold: BanThreshold::new(ban_threshold),
        },
        BTreeSet::new(),
        BTreeMap::new(),
        [node1, node2, node3].into_iter().collect(),
    );

    let times_step = Duration::from_secs(100);

    crawler.timer(times_step, &mut rng);

    crawler.assert_pending_connects(&[node1, node2, node3]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);

    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: make_peer_info(peer1, &chain_config),
        },
        &mut rng,
    );

    crawler.step(
        CrawlerEvent::Connected {
            address: node2,
            peer_info: make_peer_info(peer2, &chain_config),
        },
        &mut rng,
    );

    crawler.step(
        CrawlerEvent::Connected {
            address: node3,
            peer_info: make_peer_info(peer3, &chain_config),
        },
        &mut rng,
    );

    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer1, peer2, peer3]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);

    let ban_start_time = crawler.now();
    let ban_end_time = (ban_start_time + BAN_DURATION).unwrap();

    crawler.step(
        CrawlerEvent::Misbehaved {
            peer_id: peer1,
            error: test_error.clone(),
        },
        &mut rng,
    );

    // The peer1's address is banned; peer1 and peer3 are being disconnected.
    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[peer1, peer3]);
    crawler.assert_connected_peers(&[peer1, peer2, peer3]);
    crawler.assert_ban_scores(&[(peer1, test_error_ban_score)]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);

    crawler.step(CrawlerEvent::Disconnected { peer_id: peer1 }, &mut rng);
    crawler.step(CrawlerEvent::Disconnected { peer_id: peer3 }, &mut rng);

    // peer1 and peer3 are now disconnected; the ban score was lost, but the address is still banned.
    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer2]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);

    // Wait some (small) time, the address should still be banned.
    crawler.timer(times_step, &mut rng);

    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer2]);
    crawler.assert_ban_scores(&[(peer1, test_error_ban_score * 10)]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);

    // Sanity check
    assert!(crawler.now() < ban_end_time);

    // Wait for the remaining ban time.
    crawler.timer((ban_end_time - crawler.now()).unwrap(), &mut rng);

    // The address is no longer banned; instead, both peer1 and peer3 are being connected to.
    crawler.assert_pending_connects(&[node1, node3]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer2]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);
}

// Create a crawler with 2 addresses and mark one of them as banned.
// Make sure it doesn't try to connect to the banned address.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn dont_connect_to_initially_banned_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1: SocketAddress = "1.2.3.4:1234".parse().unwrap();
    let node2: SocketAddress = "2.3.4.5:2345".parse().unwrap();

    let ban_end_time = Time::from_duration_since_epoch(BAN_DURATION);

    let mut crawler = test_crawler(
        make_config(),
        BTreeSet::new(),
        [(node1.as_bannable(), ban_end_time)].into_iter().collect(),
        [node1, node2].into_iter().collect(),
    );

    crawler.timer(Duration::from_secs(100), &mut rng);

    crawler.assert_pending_connects(&[node2]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[(node1.as_bannable(), ban_end_time)]);
}

// Check that a peer is banned on CrawlerEvent::HandshakeFailed.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn ban_on_handshake_failure(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1: SocketAddress = "1.2.3.4:1234".parse().unwrap();
    let peer1 = PeerId::new();
    let node2: SocketAddress = "2.3.4.5:2345".parse().unwrap();

    let test_error = P2pError::ProtocolError(ProtocolError::HandshakeExpected);
    let test_error_ban_score = test_error.ban_score();
    assert!(test_error_ban_score > 0);
    let ban_threshold = test_error_ban_score;

    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(
        CrawlerConfig {
            ban_duration: BanDuration::new(BAN_DURATION),
            ban_threshold: BanThreshold::new(ban_threshold),
        },
        BTreeSet::new(),
        BTreeMap::new(),
        [node1, node2].into_iter().collect(),
    );

    let times_step = Duration::from_secs(100);

    crawler.timer(times_step, &mut rng);

    crawler.assert_pending_connects(&[node1, node2]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);

    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: make_peer_info(peer1, &chain_config),
        },
        &mut rng,
    );

    crawler.step(
        CrawlerEvent::HandshakeFailed {
            address: node2,
            error: test_error.clone(),
        },
        &mut rng,
    );

    // Note: ConnectionError is still expected and is needed for the peer to become disconnected.
    // Moreover, we want to check that sending both HandshakeFailed and ConnectionError won't
    // cause any problems (e.g. won't lead to a crash).
    crawler.step(
        CrawlerEvent::ConnectionError {
            address: node2,
            error: test_error,
        },
        &mut rng,
    );

    let ban_start_time = crawler.now();
    let ban_end_time = (ban_start_time + BAN_DURATION).unwrap();

    // The ban score is not recorded, but the peer is banned.
    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer1]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[(node2.as_bannable(), ban_end_time)]);
}

// Check that a peer is not banned on CrawlerEvent::ConnectionError if it's not accompanied
// by CrawlerEvent::HandshakeFailed.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn no_ban_on_connection_error(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let node1: SocketAddress = "1.2.3.4:1234".parse().unwrap();
    let peer1 = PeerId::new();
    let node2: SocketAddress = "2.3.4.5:2345".parse().unwrap();

    let test_error = P2pError::ProtocolError(ProtocolError::HandshakeExpected);
    let test_error_ban_score = test_error.ban_score();
    assert!(test_error_ban_score > 0);
    let ban_threshold = test_error_ban_score;

    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(
        CrawlerConfig {
            ban_duration: BanDuration::new(BAN_DURATION),
            ban_threshold: BanThreshold::new(ban_threshold),
        },
        BTreeSet::new(),
        BTreeMap::new(),
        [node1, node2].into_iter().collect(),
    );

    let times_step = Duration::from_secs(100);

    crawler.timer(times_step, &mut rng);

    crawler.assert_pending_connects(&[node1, node2]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);

    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: make_peer_info(peer1, &chain_config),
        },
        &mut rng,
    );

    crawler.step(
        CrawlerEvent::ConnectionError {
            address: node2,
            error: test_error,
        },
        &mut rng,
    );

    // The peer is not banned.
    crawler.assert_pending_connects(&[]);
    crawler.assert_pending_disconnects(&[]);
    crawler.assert_connected_peers(&[peer1]);
    crawler.assert_ban_scores(&[]);
    crawler.assert_banned_addresses(&[]);
}

const BAN_DURATION: Duration = Duration::from_secs(1000);
const BAN_THRESHOLD: u32 = 100;

fn make_config() -> CrawlerConfig {
    CrawlerConfig {
        ban_duration: BanDuration::new(BAN_DURATION),
        ban_threshold: BanThreshold::new(BAN_THRESHOLD),
    }
}

fn make_peer_info(peer_id: PeerId, chain_config: &ChainConfig) -> PeerInfo {
    PeerInfo {
        peer_id,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::DnsServer.into(),
    }
}
