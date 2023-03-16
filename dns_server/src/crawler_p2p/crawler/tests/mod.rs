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
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use common::primitives::user_agent::mintlayer_core_user_agent;
use p2p::{
    error::{DialError, P2pError},
    net::types::PeerInfo,
    types::peer_id::PeerId,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crypto::random::{
    seq::{IteratorRandom, SliceRandom},
    Rng,
};

use mock_crawler::test_crawler;

use crate::crawler_p2p::crawler::CrawlerEvent;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn basic(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node1: SocketAddr = "1.2.3.4:3031".parse().unwrap();
    let peer1 = PeerId::new();
    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(BTreeSet::new(), [node1].into_iter().collect());

    crawler.timer(Duration::from_secs(100), &mut rng);
    assert_eq!(crawler.pending_connects.len(), 1);
    assert!(crawler.pending_connects.contains(&node1));

    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: PeerInfo {
                peer_id: peer1,
                network: *chain_config.magic_bytes(),
                version: *chain_config.version(),
                user_agent: mintlayer_core_user_agent(),
                subscriptions: Default::default(),
            },
        },
        &mut rng,
    );

    assert!(crawler.persistent.contains(&node1));
    assert!(crawler.reachable.contains(&node1));

    let node2: SocketAddr = "4.3.2.1:12345".parse().unwrap();
    let peer2 = PeerId::new();

    crawler.step(CrawlerEvent::NewAddress { address: node2 }, &mut rng);

    crawler.timer(Duration::from_secs(100), &mut rng);
    assert!(crawler.pending_connects.contains(&node2));

    crawler.step(
        CrawlerEvent::Connected {
            address: node2,
            peer_info: PeerInfo {
                peer_id: peer2,
                network: *chain_config.magic_bytes(),
                version: *chain_config.version(),
                user_agent: mintlayer_core_user_agent(),
                subscriptions: Default::default(),
            },
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
        .collect::<Vec<_>>();

    let reserved_count = rng.gen_range(0..5);
    let reserved_nodes = nodes.choose_multiple(&mut rng, reserved_count).cloned().collect();

    let loaded_count = rng.gen_range(0..10);
    let loaded_nodes = nodes.choose_multiple(&mut rng, loaded_count).cloned().collect();

    let mut crawler = test_crawler(loaded_nodes, reserved_nodes);

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
                    peer_info: PeerInfo {
                        peer_id: PeerId::new(),
                        network: *chain_config.magic_bytes(),
                        version: *chain_config.version(),
                        user_agent: mintlayer_core_user_agent(),
                        subscriptions: Default::default(),
                    },
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
                    peer_info: PeerInfo {
                        peer_id: PeerId::new(),
                        network: [255, 255, 255, 255],
                        version: *chain_config.version(),
                        user_agent: mintlayer_core_user_agent(),
                        subscriptions: Default::default(),
                    },
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
            crawler.step(CrawlerEvent::NewAddress { address }, &mut rng)
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
    let node1: SocketAddr = "1.2.3.4:3031".parse().unwrap();
    let peer1 = PeerId::new();
    let chain_config = common::chain::config::create_mainnet();
    let mut crawler = test_crawler(BTreeSet::new(), [node1].into_iter().collect());

    // // Crawler attempts to connect to the specified node
    crawler.timer(Duration::from_secs(100), &mut rng);
    assert!(crawler.pending_connects.contains(&node1));

    // // Connection to the node is successful
    crawler.step(
        CrawlerEvent::Connected {
            address: node1,
            peer_info: PeerInfo {
                peer_id: peer1,
                network: [255, 255, 255, 255],
                version: *chain_config.version(),
                user_agent: mintlayer_core_user_agent(),
                subscriptions: Default::default(),
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
    let loaded_node: SocketAddr = "1.0.0.0:3031".parse().unwrap();
    let added_node: SocketAddr = "2.0.0.0:3031".parse().unwrap();
    let mut crawler = test_crawler(
        [loaded_node].into_iter().collect(),
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
