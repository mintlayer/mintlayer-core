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

use randomness::SliceRandom;
use rstest::rstest;
use test_utils::random::Seed;

use super::*;

fn shuffle_vec<T>(mut vec: Vec<T>, rng: &mut impl Rng) -> Vec<T> {
    vec.shuffle(rng);
    vec
}

// Make a random non-banned-or-discouraged candidate.
fn random_candidate(peer_role: PeerRole, rng: &mut impl Rng) -> EvictionCandidate {
    EvictionCandidate {
        age: Duration::from_secs(rng.gen_range(0..10000)),
        peer_id: PeerId::new(),
        net_group_keyed: NetGroupKeyed(rng.gen()),
        ping_min: rng.gen_range(0..100),
        peer_role,
        last_tip_block_time: Some(Time::from_secs_since_epoch(rng.gen_range(0..10000))),
        last_tx_time: Some(Time::from_secs_since_epoch(rng.gen_range(0..10000))),
        expecting_blocks_since: Some(Time::from_secs_since_epoch(rng.gen_range(0..10000))),
        is_banned_or_discouraged: false,
    }
}

mod inbound {
    use super::*;

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_filter_address_group(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        fn make_candidate(peer_id: PeerId, net_group_keyed: NetGroupKeyed) -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id,
                net_group_keyed,
                ping_min: 0,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
                expecting_blocks_since: None,
                is_banned_or_discouraged: false,
            }
        }

        assert_eq!(
            filter_address_group(vec![make_candidate(peer1, NetGroupKeyed(1))], 1),
            vec![]
        );

        assert_eq!(
            filter_address_group(
                shuffle_vec(
                    vec![
                        make_candidate(peer1, NetGroupKeyed(1)),
                        make_candidate(peer2, NetGroupKeyed(2))
                    ],
                    &mut rng
                ),
                1
            ),
            vec![make_candidate(peer1, NetGroupKeyed(1))]
        );

        assert_eq!(
            filter_address_group(
                shuffle_vec(
                    vec![
                        make_candidate(peer1, NetGroupKeyed(2)),
                        make_candidate(peer2, NetGroupKeyed(1)),
                        make_candidate(peer3, NetGroupKeyed(2)),
                    ],
                    &mut rng
                ),
                2
            ),
            vec![make_candidate(peer2, NetGroupKeyed(1))]
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_ping(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        fn make_candidate(peer_id: PeerId, ping_min: i64) -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id,
                net_group_keyed: NetGroupKeyed(1),
                ping_min,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
                expecting_blocks_since: None,
                is_banned_or_discouraged: false,
            }
        }

        assert_eq!(
            filter_fast_ping(vec![make_candidate(peer1, 123)], 1),
            vec![]
        );

        assert_eq!(
            filter_fast_ping(
                shuffle_vec(
                    vec![make_candidate(peer1, 123), make_candidate(peer2, 234)],
                    &mut rng
                ),
                1
            ),
            vec![make_candidate(peer2, 234)]
        );

        assert_eq!(
            filter_fast_ping(
                shuffle_vec(
                    vec![
                        make_candidate(peer1, 123),
                        make_candidate(peer2, 234),
                        make_candidate(peer3, 123)
                    ],
                    &mut rng
                ),
                2
            ),
            vec![make_candidate(peer2, 234)]
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_filter_by_last_block_time(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        fn make_candidate(
            peer_id: PeerId,
            last_tip_block_time_secs: Option<u64>,
        ) -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: last_tip_block_time_secs.map(Time::from_secs_since_epoch),
                last_tx_time: None,
                expecting_blocks_since: None,
                is_banned_or_discouraged: false,
            }
        }

        assert_eq!(
            filter_by_last_tip_block_time(vec![make_candidate(peer1, None)], 1),
            vec![]
        );

        assert_eq!(
            filter_by_last_tip_block_time(
                shuffle_vec(
                    vec![make_candidate(peer1, None), make_candidate(peer2, Some(10000000))],
                    &mut rng
                ),
                1
            ),
            vec![make_candidate(peer1, None)]
        );

        assert_eq!(
            filter_by_last_tip_block_time(
                shuffle_vec(
                    vec![
                        make_candidate(peer1, Some(10000000)),
                        make_candidate(peer2, Some(10000001)),
                        make_candidate(peer3, Some(10000002)),
                    ],
                    &mut rng
                ),
                2
            ),
            vec![make_candidate(peer1, Some(10000000))]
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_filter_by_last_transaction_time(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        fn make_candidate(peer_id: PeerId, last_tx_time_secs: Option<u64>) -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: last_tx_time_secs.map(Time::from_secs_since_epoch),
                expecting_blocks_since: None,
                is_banned_or_discouraged: false,
            }
        }

        assert_eq!(
            filter_by_last_transaction_time(vec![make_candidate(peer1, None)], 1),
            vec![]
        );

        assert_eq!(
            filter_by_last_transaction_time(
                shuffle_vec(
                    vec![make_candidate(peer1, Some(1000000)), make_candidate(peer2, None)],
                    &mut rng
                ),
                1
            ),
            vec![make_candidate(peer2, None)]
        );

        assert_eq!(
            filter_by_last_transaction_time(
                shuffle_vec(
                    vec![
                        make_candidate(peer1, Some(1000000)),
                        make_candidate(peer2, Some(1000001)),
                        make_candidate(peer3, Some(1000002))
                    ],
                    &mut rng
                ),
                2
            ),
            vec![make_candidate(peer1, Some(1000000)),]
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_find_group_most_connections(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        fn make_candidate(peer_id: PeerId, net_group_keyed: NetGroupKeyed) -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::ZERO,
                peer_id,
                net_group_keyed,
                ping_min: 123,
                peer_role: PeerRole::Inbound,
                last_tip_block_time: None,
                last_tx_time: None,
                expecting_blocks_since: None,
                is_banned_or_discouraged: false,
            }
        }

        assert_eq!(find_group_most_connections(vec![]), None);

        assert_eq!(
            find_group_most_connections(vec![make_candidate(peer1, NetGroupKeyed(1))]),
            Some(peer1)
        );

        // The youngest peer is selected (with the latest id)
        assert_eq!(
            find_group_most_connections(shuffle_vec(
                vec![
                    make_candidate(peer1, NetGroupKeyed(1)),
                    make_candidate(peer2, NetGroupKeyed(1))
                ],
                &mut rng
            )),
            Some(peer2)
        );

        assert_eq!(
            find_group_most_connections(shuffle_vec(
                vec![
                    make_candidate(peer1, NetGroupKeyed(1)),
                    make_candidate(peer2, NetGroupKeyed(1)),
                    make_candidate(peer3, NetGroupKeyed(2)),
                ],
                &mut rng
            )),
            Some(peer2)
        );
    }

    fn test_preserved_by_ping(
        index: usize,
        candidate: &mut EvictionCandidate,
        config: &PeerManagerConfig,
    ) -> bool {
        // Check that `preserved_inbound_count_ping` peers with the lowest ping times are preserved
        candidate.ping_min = index as i64;
        index < *config.preserved_inbound_count_ping
    }

    fn test_preserved_by_address_group(
        index: usize,
        candidate: &mut EvictionCandidate,
        config: &PeerManagerConfig,
    ) -> bool {
        // Check that `preserved_inbound_count_address_group` peers with the highest net_group_keyed values are preserved
        candidate.net_group_keyed = NetGroupKeyed(u64::MAX - index as u64);
        index < *config.preserved_inbound_count_address_group
    }

    fn test_preserved_by_last_block_time(
        index: usize,
        candidate: &mut EvictionCandidate,
        config: &PeerManagerConfig,
    ) -> bool {
        // Check that `preserved_inbound_count_new_blocks` peers with the latest last_tip_block_time are preserved
        candidate.last_tip_block_time = Some(Time::from_secs_since_epoch(u64::MAX - index as u64));
        index < *config.preserved_inbound_count_new_blocks
    }

    fn test_preserved_by_last_tx_time(
        index: usize,
        candidate: &mut EvictionCandidate,
        config: &PeerManagerConfig,
    ) -> bool {
        // Check that `preserved_inbound_count_new_transactions` peers with the latest last_tip_block_time are preserved
        candidate.last_tx_time = Some(Time::from_secs_since_epoch(u64::MAX - index as u64));
        index < *config.preserved_inbound_count_new_transactions
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(test_utils::random::Seed::from_entropy())]
    fn test_randomized(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let config: PeerManagerConfig = Default::default();
        let tests = [
            test_preserved_by_ping,
            test_preserved_by_address_group,
            test_preserved_by_last_block_time,
            test_preserved_by_last_tx_time,
        ];

        for _ in 0..10 {
            for test in tests {
                let count = rng.gen_range(0..150usize);
                let mut candidates = (0..count)
                    .map(|_| random_candidate(PeerRole::Inbound, &mut rng))
                    .collect::<Vec<_>>();
                candidates.shuffle(&mut rng);

                let mut preserved = BTreeSet::new();
                for (index, candidate) in candidates.iter_mut().enumerate() {
                    let is_preserved = test(index, candidate, &config);
                    if is_preserved {
                        preserved.insert(candidate.peer_id);
                    }
                }

                candidates.shuffle(&mut rng);
                let peer_id = select_for_eviction_inbound(candidates.clone(), &config, &mut rng);
                assert_eq!(
                    count > config.total_preserved_inbound_count(),
                    peer_id.is_some(),
                    "unexpected result, candidates: {candidates:?}, peer_id: {peer_id:?}"
                );
                if let Some(peer_id) = peer_id {
                    assert!(!preserved.contains(&peer_id));
                }
            }
        }
    }
}

mod outbound {
    use super::*;

    #[derive(Debug, Copy, Clone)]
    enum OutboundConnType {
        BlockRelay,
        FullRelay,
    }

    impl From<OutboundConnType> for PeerRole {
        fn from(value: OutboundConnType) -> Self {
            match value {
                OutboundConnType::BlockRelay => PeerRole::OutboundBlockRelay,
                OutboundConnType::FullRelay => PeerRole::OutboundFullRelay,
            }
        }
    }

    fn config_with_conn_limits(
        conn_type: OutboundConnType,
        max_connections: usize,
        min_age: Duration,
    ) -> PeerManagerConfig {
        let func = match conn_type {
            OutboundConnType::BlockRelay => config_with_block_relay_conn_limits,
            OutboundConnType::FullRelay => config_with_full_relay_conn_limits,
        };
        func(max_connections, min_age)
    }

    fn select_for_eviction(
        conn_type: OutboundConnType,
        candidates: Vec<EvictionCandidate>,
        config: &PeerManagerConfig,
        now: Time,
        rng: &mut impl Rng,
    ) -> Option<PeerId> {
        let func = match conn_type {
            OutboundConnType::BlockRelay => select_for_eviction_block_relay,
            OutboundConnType::FullRelay => select_for_eviction_full_relay,
        };
        func(candidates, config, now, rng)
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_young_old_peers(
        #[case] seed: Seed,
        #[values(OutboundConnType::BlockRelay, OutboundConnType::FullRelay)]
        conn_type: OutboundConnType,
    ) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        let now = Time::from_secs_since_epoch(100000);
        let min_age = Duration::from_secs(5000);
        let config = config_with_conn_limits(conn_type, 2, min_age);

        let make_candidate = |peer_id: PeerId, age: Duration| -> EvictionCandidate {
            EvictionCandidate {
                age,
                peer_id,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: conn_type.into(),
                last_tip_block_time: None,
                last_tx_time: None,
                expecting_blocks_since: None,
                is_banned_or_discouraged: false,
            }
        };

        // Young peers should not be evicted
        let candidates = vec![
            make_candidate(peer1, Duration::from_secs(20000)),
            make_candidate(peer2, Duration::from_secs(10000)),
            make_candidate(peer3, min_age - Duration::from_secs(1)),
        ];
        assert_eq!(
            select_for_eviction(
                conn_type,
                shuffle_vec(candidates, &mut rng),
                &config,
                now,
                &mut rng
            ),
            None
        );

        // Older peer can be evicted
        let candidates = vec![
            make_candidate(peer1, Duration::from_secs(20000)),
            make_candidate(peer2, Duration::from_secs(10000)),
            make_candidate(peer3, min_age + Duration::from_secs(1)),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer3)
        );

        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_no_blocks(
        #[case] seed: Seed,
        #[values(OutboundConnType::BlockRelay, OutboundConnType::FullRelay)]
        conn_type: OutboundConnType,
    ) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        let now_as_secs = 100000;
        let now = Time::from_secs_since_epoch(now_as_secs);
        let min_age = Duration::from_secs(5000);
        let config = config_with_conn_limits(conn_type, 2, min_age);

        let make_candidate = |peer_id: PeerId,
                              last_tip_block_time_secs: Option<u64>,
                              expecting_blocks_since_secs: Option<u64>|
         -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::from_secs(10000),
                peer_id,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: conn_type.into(),
                last_tip_block_time: last_tip_block_time_secs.map(Time::from_secs_since_epoch),
                last_tx_time: None,
                expecting_blocks_since: expecting_blocks_since_secs
                    .map(Time::from_secs_since_epoch),
                is_banned_or_discouraged: false,
            }
        };

        // The peer that never sent us new blocks is evicted.
        let candidates = vec![
            make_candidate(peer1, Some(10000), None),
            make_candidate(peer2, Some(20000), None),
            make_candidate(peer3, None, None),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer3)
        );
        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );

        // The previously evicted peer now has `expecting_blocks_since` within the limit;
        // the next worst peer should be evicted instead.
        let candidates = vec![
            make_candidate(peer1, Some(10000), None),
            make_candidate(peer2, Some(20000), None),
            make_candidate(
                peer3,
                None,
                Some(now_as_secs - BLOCK_EXPECTATION_MAX_DURATION.as_secs()),
            ),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer1)
        );
        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );

        // The same peer now has `expecting_blocks_since` below the limit;
        // this time it should be evicted.
        let candidates = vec![
            make_candidate(peer1, Some(10000), None),
            make_candidate(peer2, Some(20000), None),
            make_candidate(
                peer3,
                None,
                Some(now_as_secs - BLOCK_EXPECTATION_MAX_DURATION.as_secs() - 1),
            ),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer3)
        );
        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_old_blocks(
        #[case] seed: Seed,
        #[values(OutboundConnType::BlockRelay, OutboundConnType::FullRelay)]
        conn_type: OutboundConnType,
    ) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let peer1 = PeerId::new();
        let peer2 = PeerId::new();
        let peer3 = PeerId::new();

        let now_as_secs = 100000;
        let now = Time::from_secs_since_epoch(now_as_secs);
        let min_age = Duration::from_secs(5000);
        let config = config_with_conn_limits(conn_type, 2, min_age);

        let make_candidate = |peer_id: PeerId,
                              last_tip_block_time_secs: u64,
                              expecting_blocks_since_secs: Option<u64>|
         -> EvictionCandidate {
            EvictionCandidate {
                age: Duration::from_secs(10000),
                peer_id,
                net_group_keyed: NetGroupKeyed(1),
                ping_min: 123,
                peer_role: conn_type.into(),
                last_tip_block_time: Some(Time::from_secs_since_epoch(last_tip_block_time_secs)),
                last_tx_time: None,
                expecting_blocks_since: expecting_blocks_since_secs
                    .map(Time::from_secs_since_epoch),
                is_banned_or_discouraged: false,
            }
        };

        // The peer that sent blocks a long time ago is evicted.
        let candidates = vec![
            make_candidate(peer1, 10000, None),
            make_candidate(peer2, 20000, None),
            make_candidate(peer3, 30000, None),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer1)
        );
        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );

        // The previously evicted peer now has `expecting_blocks_since` within the limit;
        // the next worst peer should be evicted instead.
        let candidates = vec![
            make_candidate(
                peer1,
                10000,
                Some(now_as_secs - BLOCK_EXPECTATION_MAX_DURATION.as_secs()),
            ),
            make_candidate(peer2, 20000, None),
            make_candidate(peer3, 30000, None),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer2)
        );
        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );

        // The same peer now has `expecting_blocks_since` below the limit;
        // this time it should be evicted.
        let candidates = vec![
            make_candidate(
                peer1,
                10000,
                Some(now_as_secs - BLOCK_EXPECTATION_MAX_DURATION.as_secs() - 1),
            ),
            make_candidate(peer2, 20000, None),
            make_candidate(peer3, 30000, None),
        ];
        let candidates = shuffle_vec(candidates, &mut rng);
        assert_eq!(
            select_for_eviction(conn_type, candidates.clone(), &config, now, &mut rng),
            Some(peer1)
        );
        // But if the limits are lifted, no eviction happens.
        assert_eq!(
            select_for_eviction(
                conn_type,
                candidates,
                &config_with_no_conn_limits(),
                now,
                &mut rng
            ),
            None
        );
    }

    fn config_with_block_relay_conn_limits(
        max_connections: usize,
        min_age: Duration,
    ) -> PeerManagerConfig {
        PeerManagerConfig {
            outbound_block_relay_count: max_connections.into(),
            outbound_block_relay_connection_min_age: min_age.into(),

            // Connection count limits that should not influence tests' behavior are set to MAX.
            max_inbound_connections: usize::MAX.into(),
            preserved_inbound_count_address_group: usize::MAX.into(),
            preserved_inbound_count_ping: usize::MAX.into(),
            preserved_inbound_count_new_blocks: usize::MAX.into(),
            preserved_inbound_count_new_transactions: usize::MAX.into(),
            outbound_full_relay_count: usize::MAX.into(),
            outbound_full_relay_extra_count: usize::MAX.into(),
            outbound_block_relay_extra_count: usize::MAX.into(),
            outbound_full_relay_connection_min_age: Duration::MAX.into(),

            // Other values are irrelevant
            stale_tip_time_diff: Default::default(),
            main_loop_tick_interval: Default::default(),
            enable_feeler_connections: Default::default(),
            feeler_connections_interval: Default::default(),
            force_dns_query_if_no_global_addresses_known: Default::default(),
            allow_same_ip_connections: Default::default(),
            peerdb_config: Default::default(),
        }
    }

    fn config_with_full_relay_conn_limits(
        max_connections: usize,
        min_age: Duration,
    ) -> PeerManagerConfig {
        PeerManagerConfig {
            outbound_full_relay_count: max_connections.into(),
            outbound_full_relay_connection_min_age: min_age.into(),

            // Connection count limits that should not influence tests' behavior are set to MAX.
            max_inbound_connections: usize::MAX.into(),
            preserved_inbound_count_address_group: usize::MAX.into(),
            preserved_inbound_count_ping: usize::MAX.into(),
            preserved_inbound_count_new_blocks: usize::MAX.into(),
            preserved_inbound_count_new_transactions: usize::MAX.into(),
            outbound_full_relay_extra_count: usize::MAX.into(),
            outbound_block_relay_count: usize::MAX.into(),
            outbound_block_relay_extra_count: usize::MAX.into(),
            outbound_block_relay_connection_min_age: Duration::MAX.into(),

            // Other values are irrelevant
            stale_tip_time_diff: Default::default(),
            main_loop_tick_interval: Default::default(),
            enable_feeler_connections: Default::default(),
            feeler_connections_interval: Default::default(),
            force_dns_query_if_no_global_addresses_known: Default::default(),
            allow_same_ip_connections: Default::default(),
            peerdb_config: Default::default(),
        }
    }

    fn config_with_no_conn_limits() -> PeerManagerConfig {
        PeerManagerConfig {
            outbound_block_relay_count: usize::MAX.into(),
            outbound_full_relay_count: usize::MAX.into(),
            outbound_full_relay_connection_min_age: Duration::MAX.into(),

            // Connection count limits that should not influence tests' behavior are set to 0.
            max_inbound_connections: 0.into(),
            preserved_inbound_count_address_group: 0.into(),
            preserved_inbound_count_ping: 0.into(),
            preserved_inbound_count_new_blocks: 0.into(),
            preserved_inbound_count_new_transactions: 0.into(),
            outbound_full_relay_extra_count: 0.into(),
            outbound_block_relay_extra_count: 0.into(),
            outbound_block_relay_connection_min_age: Duration::ZERO.into(),

            // Other values are irrelevant
            stale_tip_time_diff: Default::default(),
            main_loop_tick_interval: Default::default(),
            enable_feeler_connections: Default::default(),
            feeler_connections_interval: Default::default(),
            force_dns_query_if_no_global_addresses_known: Default::default(),
            allow_same_ip_connections: Default::default(),
            peerdb_config: Default::default(),
        }
    }
}

mod discouraged_candidate {
    use super::*;

    fn select_for_eviction(
        peer_role: PeerRole,
        candidates: Vec<EvictionCandidate>,
        config: &PeerManagerConfig,
        now: Time,
        rng: &mut impl Rng,
    ) -> Option<PeerId> {
        match peer_role {
            PeerRole::Inbound => select_for_eviction_inbound(candidates, config, rng),
            PeerRole::OutboundFullRelay => {
                select_for_eviction_full_relay(candidates, config, now, rng)
            }
            PeerRole::OutboundBlockRelay => {
                select_for_eviction_block_relay(candidates, config, now, rng)
            }
            PeerRole::OutboundReserved | PeerRole::OutboundManual | PeerRole::Feeler => {
                panic!("Unexpected peer role: {peer_role:?}");
            }
        }
    }

    fn max_preserve_count(peer_role: PeerRole, config: &PeerManagerConfig) -> usize {
        match peer_role {
            PeerRole::Inbound => config.total_preserved_inbound_count(),
            PeerRole::OutboundFullRelay => *config.outbound_full_relay_count,
            PeerRole::OutboundBlockRelay => *config.outbound_block_relay_count,
            PeerRole::OutboundReserved | PeerRole::OutboundManual | PeerRole::Feeler => {
                panic!("Unexpected peer role: {peer_role:?}");
            }
        }
    }

    fn random_mature_candidate(
        peer_role: PeerRole,
        config: &PeerManagerConfig,
        rng: &mut impl Rng,
    ) -> EvictionCandidate {
        let mut candidate = random_candidate(peer_role, rng);
        match peer_role {
            PeerRole::Inbound => {}
            PeerRole::OutboundFullRelay => {
                candidate.age = *config.outbound_full_relay_connection_min_age;
            }
            PeerRole::OutboundBlockRelay => {
                candidate.age = *config.outbound_block_relay_connection_min_age;
            }
            PeerRole::OutboundReserved | PeerRole::OutboundManual | PeerRole::Feeler => {
                panic!("Unexpected peer role: {peer_role:?}");
            }
        }

        candidate
    }

    #[tracing::instrument(skip(seed))]
    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test(
        #[case] seed: Seed,
        #[values(
            PeerRole::Inbound,
            PeerRole::OutboundFullRelay,
            PeerRole::OutboundBlockRelay
        )]
        peer_role: PeerRole,
    ) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let config: PeerManagerConfig = Default::default();
        let preserve_count = max_preserve_count(peer_role, &config);
        let now = Time::from_secs_since_epoch(rng.gen_range(0..10000));

        for _i in 0..5 {
            for candidates_count in [preserve_count - 1, preserve_count + 1] {
                let candidates = (0..candidates_count)
                    .map(|_| random_mature_candidate(peer_role, &config, &mut rng))
                    .collect::<Vec<_>>();

                let normally_evicted_peer_id =
                    select_for_eviction(peer_role, candidates.clone(), &config, now, &mut rng);

                let discouraged_candidate_idx = rng.gen_range(0..candidates_count);
                let discouraged_peer_id = candidates[discouraged_candidate_idx].peer_id;
                let candidates = {
                    let mut candidates = candidates;
                    candidates[discouraged_candidate_idx].is_banned_or_discouraged = true;
                    candidates
                };

                let evicted_peer_id =
                    select_for_eviction(peer_role, candidates.clone(), &config, now, &mut rng);

                assert_eq!(
                    evicted_peer_id.is_some(),
                    normally_evicted_peer_id.is_some()
                );

                if let Some(evicted_peer_id) = evicted_peer_id {
                    assert_eq!(evicted_peer_id, discouraged_peer_id);
                }
            }
        }
    }
}
