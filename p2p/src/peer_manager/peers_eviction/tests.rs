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

    // The yungest peer is selected (with the latest id)
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
