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

use crypto::random::SliceRandom;
use rstest::rstest;
use test_utils::random::Seed;

use super::*;

#[test]
fn test_filter_inbound() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    assert_eq!(
        filter_inbound(vec![
            EvictionCandidate {
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(123),
                ping_min: 0,
                role: Role::Inbound
            },
            EvictionCandidate {
                peer_id: peer2,
                net_group_keyed: NetGroupKeyed(123),
                ping_min: 0,
                role: Role::Outbound
            }
        ]),
        vec![EvictionCandidate {
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(123),
            ping_min: 0,
            role: Role::Inbound
        },]
    );
}

#[test]
fn test_filter_address_group() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(
        filter_address_group(
            vec![EvictionCandidate {
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 0,
                role: Role::Inbound
            },],
            1
        ),
        vec![]
    );

    assert_eq!(
        filter_address_group(
            vec![
                EvictionCandidate {
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 0,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    role: Role::Inbound
                },
            ],
            1
        ),
        vec![EvictionCandidate {
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 0,
            role: Role::Inbound
        },]
    );

    assert_eq!(
        filter_address_group(
            vec![
                EvictionCandidate {
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 0,
                    role: Role::Inbound
                },
            ],
            1
        ),
        vec![EvictionCandidate {
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 0,
            role: Role::Inbound
        },]
    );

    assert_eq!(
        filter_address_group(
            vec![
                EvictionCandidate {
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 0,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(2),
                    ping_min: 0,
                    role: Role::Inbound
                },
            ],
            2
        ),
        vec![EvictionCandidate {
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 0,
            role: Role::Inbound
        },]
    );
}

#[test]
fn test_ping() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(
        filter_fast_ping(
            vec![EvictionCandidate {
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                role: Role::Inbound
            },],
            1
        ),
        vec![]
    );

    assert_eq!(
        filter_fast_ping(
            vec![
                EvictionCandidate {
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 234,
                    role: Role::Inbound
                },
            ],
            1
        ),
        vec![EvictionCandidate {
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 234,
            role: Role::Inbound
        },]
    );

    assert_eq!(
        filter_fast_ping(
            vec![
                EvictionCandidate {
                    peer_id: peer1,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer2,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 234,
                    role: Role::Inbound
                },
                EvictionCandidate {
                    peer_id: peer3,
                    net_group_keyed: NetGroupKeyed(1),
                    ping_min: 123,
                    role: Role::Inbound
                },
            ],
            2
        ),
        vec![EvictionCandidate {
            peer_id: peer2,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 234,
            role: Role::Inbound
        },]
    );
}

#[test]
fn test_find_group_most_connections() {
    let peer1 = PeerId::new();
    let peer2 = PeerId::new();
    let peer3 = PeerId::new();

    assert_eq!(find_group_most_connections(vec![]), None);

    assert_eq!(
        find_group_most_connections(vec![EvictionCandidate {
            peer_id: peer1,
            net_group_keyed: NetGroupKeyed(1),
            ping_min: 123,
            role: Role::Inbound
        }]),
        Some(peer1)
    );

    // The youngest peer is selected (with the latest id)
    assert_eq!(
        find_group_most_connections(vec![
            EvictionCandidate {
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                role: Role::Inbound
            },
            EvictionCandidate {
                peer_id: peer2,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                role: Role::Inbound
            }
        ]),
        Some(peer2)
    );

    assert_eq!(
        find_group_most_connections(vec![
            EvictionCandidate {
                peer_id: peer1,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                role: Role::Inbound
            },
            EvictionCandidate {
                peer_id: peer2,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                role: Role::Inbound
            },
            EvictionCandidate {
                peer_id: peer3,
                net_group_keyed: NetGroupKeyed(2),
                ping_min: 123,
                role: Role::Inbound
            },
        ]),
        Some(peer2)
    );
}

fn random_eviction_candidate(rng: &mut impl Rng) -> EvictionCandidate {
    EvictionCandidate {
        peer_id: PeerId::new(),
        net_group_keyed: NetGroupKeyed(rng.gen()),
        ping_min: rng.gen_range(0..100),
        role: Role::Inbound,
    }
}

fn test_protected_ping(index: usize, candidate: &mut EvictionCandidate) -> bool {
    // Check that `PROTECTED_COUNT_PING` peers with the lowest ping times are protected
    candidate.ping_min = index as i64;
    index < PROTECTED_COUNT_PING
}

fn test_protected_address_group(index: usize, candidate: &mut EvictionCandidate) -> bool {
    // Check that `PROTECTED_COUNT_ADDRESS_GROUP` peers with the highest net_group_keyed values are protected
    candidate.net_group_keyed = NetGroupKeyed(u64::MAX - index as u64);
    index < PROTECTED_COUNT_ADDRESS_GROUP
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn test_randomized(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let tests = [test_protected_ping, test_protected_address_group];

    for _ in 0..10 {
        for test in tests {
            let count = rng.gen_range(0..150usize);
            let mut candidates =
                (0..count).map(|_| random_eviction_candidate(&mut rng)).collect::<Vec<_>>();
            candidates.shuffle(&mut rng);

            let mut protected = BTreeSet::new();
            for (index, candidate) in candidates.iter_mut().enumerate() {
                let is_protected = test(index, candidate);
                if is_protected {
                    protected.insert(candidate.peer_id);
                }
            }

            candidates.shuffle(&mut rng);
            let peer_id = select_for_eviction(candidates.clone());
            assert_eq!(
                count > PROTECTED_COUNT_TOTAL,
                peer_id.is_some(),
                "unexpected result, candidates: {candidates:?}, peer_id: {peer_id:?}"
            );
            if let Some(peer_id) = peer_id {
                assert!(!protected.contains(&peer_id));
            }
        }
    }
}
