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

use std::collections::BTreeSet;

use crypto::random::{make_pseudo_rng, SliceRandom};
use rstest::rstest;
use test_utils::random::Seed;

use super::*;

fn shuffle_vec<T>(mut vec: Vec<T>) -> Vec<T> {
    vec.shuffle(&mut make_pseudo_rng());
    vec
}

#[tracing::instrument]
#[test]
fn test_filter_peer_role() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    assert_eq!(
        filter_peer_role(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(123),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(123),
                    ping_min: 0,
                    peer_role: PeerRole::OutboundFullRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                }
            ]),
            PeerRole::Inbound
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(123),
            ping_min: 0,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );
}

#[tracing::instrument]
#[test]
fn test_filter_address_group() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(
        filter_address_group(
            vec![EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 0,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },],
            1
        ),
        vec![]
    );

    assert_eq!(
        filter_address_group(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            1
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 0,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );

    assert_eq!(
        filter_address_group(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            1
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 0,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );

    assert_eq!(
        filter_address_group(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            2
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 0,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );
}

#[tracing::instrument]
#[test]
fn test_ping() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(
        filter_fast_ping(
            vec![EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },],
            1
        ),
        vec![]
    );

    assert_eq!(
        filter_fast_ping(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 234,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            1
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 234,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );

    assert_eq!(
        filter_fast_ping(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 234,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            2
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 234,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );
}

#[tracing::instrument]
#[test]
fn test_filter_by_last_block_time() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(
        filter_by_last_tip_block_time(
            vec![EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },],
            1
        ),
        vec![]
    );

    assert_eq!(
        filter_by_last_tip_block_time(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: Some(Time::from_duration_since_epoch(
                        Duration::from_secs(10000000)
                    )),
                    last_tx_time: None,
                },
            ]),
            1
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 123,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );

    assert_eq!(
        filter_by_last_tip_block_time(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: Some(Time::from_duration_since_epoch(
                        Duration::from_secs(10000000)
                    )),
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: Some(Time::from_duration_since_epoch(
                        Duration::from_secs(10000001)
                    )),
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: Some(Time::from_duration_since_epoch(
                        Duration::from_secs(10000002)
                    )),
                    last_tx_time: None,
                },
            ]),
            2
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 123,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: Some(Time::from_secs_since_epoch(10000000)),
            last_tx_time: None,
        },]
    );
}

#[tracing::instrument]
#[test]
fn test_filter_by_last_transaction_time() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(
        filter_by_last_transaction_time(
            vec![EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },],
            1
        ),
        vec![]
    );

    assert_eq!(
        filter_by_last_transaction_time(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: Some(Time::from_secs_since_epoch(1000000)),
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            1
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 123,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        },]
    );

    assert_eq!(
        filter_by_last_transaction_time(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: Some(Time::from_secs_since_epoch(10000000)),
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: Some(Time::from_secs_since_epoch(10000001)),
                },
                EvictionCandidate {
                    age: Duration::ZERO,
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::Inbound,
                    last_tip_block_time: None,
                    last_tx_time: Some(Time::from_secs_since_epoch(10000002)),
                },
            ]),
            2
        ),
        vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 123,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: Some(Time::from_secs_since_epoch(10000000)),
        },]
    );
}

#[tracing::instrument]
#[test]
fn test_find_group_most_connections() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(find_group_most_connections(vec![]), None);

    assert_eq!(
        find_group_most_connections(vec![EvictionCandidate {
            age: Duration::ZERO,
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 123,
            peer_role: PeerRole::Inbound,
            last_tip_block_time: None,
            last_tx_time: None,
        }]),
        Some(peer1)
    );

    // The youngest peer is selected (with the latest id)
    assert_eq!(
        find_group_most_connections(shuffle_vec(vec![
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer2,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            }
        ])),
        Some(peer2)
    );

    assert_eq!(
        find_group_most_connections(shuffle_vec(vec![
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer2,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id: peer3,
                net_group_keyed: NetGroupKeyed(2),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
            },
        ])),
        Some(peer2)
    );
}

fn random_eviction_candidate(rng: &mut impl Rng) -> EvictionCandidate {
    EvictionCandidate {
        age: Duration::ZERO,
        peer_id: PeerId::new(),
        net_group_keyed: NetGroupKeyed(rng.gen()),
        ping_min: rng.gen_range(0..100),
        peer_role: PeerRole::Inbound,
        last_tip_block_time: None,
        last_tx_time: None,
    }
}

fn test_preserved_by_ping(
    index: usize,
    candidate: &mut EvictionCandidate,
    limits: &ConnectionCountLimits,
) -> bool {
    // Check that `PRESERVED_COUNT_PING` peers with the lowest ping times are preserved
    candidate.ping_min = index as i64;
    index < *limits.preserved_inbound_count_ping
}

fn test_preserved_by_address_group(
    index: usize,
    candidate: &mut EvictionCandidate,
    limits: &ConnectionCountLimits,
) -> bool {
    // Check that `PRESERVED_COUNT_ADDRESS_GROUP` peers with the highest net_group_keyed values are preserved
    candidate.net_group_keyed = NetGroupKeyed(u64::MAX - index as u64);
    index < *limits.preserved_inbound_count_address_group
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn test_randomized(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let limits: ConnectionCountLimits = Default::default();
    let tests = [test_preserved_by_ping, test_preserved_by_address_group];

    for _ in 0..10 {
        for test in tests {
            let count = rng.gen_range(0..150usize);
            let mut candidates =
                (0..count).map(|_| random_eviction_candidate(&mut rng)).collect::<Vec<_>>();
            candidates.shuffle(&mut rng);

            let mut preserved = BTreeSet::new();
            for (index, candidate) in candidates.iter_mut().enumerate() {
                let is_preserved = test(index, candidate, &limits);
                if is_preserved {
                    preserved.insert(candidate.peer_id);
                }
            }

            candidates.shuffle(&mut rng);
            let peer_id = select_for_eviction_inbound(candidates.clone(), &limits);
            assert_eq!(
                count > limits.total_preserved_inbound_count(),
                peer_id.is_some(),
                "unexpected result, candidates: {candidates:?}, peer_id: {peer_id:?}"
            );
            if let Some(peer_id) = peer_id {
                assert!(!preserved.contains(&peer_id));
            }
        }
    }
}

#[tracing::instrument]
#[test]
fn test_block_relay_eviction_young_old_peers() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    let limits: ConnectionCountLimits = Default::default();

    // Young peers should not be disconnected
    assert_eq!(
        select_for_eviction_block_relay(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::from_secs(20000),
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(100),
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            &limits
        ),
        None
    );

    // Older peer can be disconnected
    assert_eq!(
        select_for_eviction_block_relay(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::from_secs(20000),
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(130),
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            &limits
        ),
        Some(peer3)
    );
}

#[tracing::instrument]
#[test]
fn test_block_relay_eviction_no_blocks() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    let limits: ConnectionCountLimits = Default::default();

    // The peer that never sent us new blocks is disconnected
    assert_eq!(
        select_for_eviction_block_relay(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: Some(Time::from_secs_since_epoch(10000)),
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: Some(Time::from_secs_since_epoch(20000)),
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: None,
                    last_tx_time: None,
                },
            ]),
            &limits
        ),
        Some(peer3)
    );
}

#[tracing::instrument]
#[test]
fn test_block_relay_eviction_old_blocks() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    let limits: ConnectionCountLimits = Default::default();

    // The peer that sent blocks a long time ago is disconnected
    assert_eq!(
        select_for_eviction_block_relay(
            shuffle_vec(vec![
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: Some(Time::from_secs_since_epoch(10000)),
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: Some(Time::from_secs_since_epoch(20000)),
                    last_tx_time: None,
                },
                EvictionCandidate {
                    age: Duration::from_secs(10000),
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    peer_role: PeerRole::OutboundBlockRelay,
                    last_tip_block_time: Some(Time::from_secs_since_epoch(30000)),
                    last_tx_time: None,
                },
            ]),
            &limits
        ),
        Some(peer1)
    );
}
