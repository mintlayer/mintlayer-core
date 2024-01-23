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

use logging::log;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use tokio::sync::mpsc;

use p2p_test_utils::{expect_no_recv, expect_recv, P2pBasicTestTimeGetter};
use test_utils::random::Seed;

use crate::{
    config::P2pConfig,
    net::{
        default_backend::{types::Command, ConnectivityHandle},
        types::ConnectivityEvent,
    },
    peer_manager::{
        dns_seed::DefaultDnsSeed,
        peerdb::{self, config::PeerDbConfig, salt::Salt},
        peers_eviction,
        tests::utils::{expect_connect_cmd, make_block_relay_peer_info},
        PeerManager, PeerManagerConfig,
    },
    sync::sync_status::PeerBlockSyncStatus,
    testing_utils::{peerdb_inmemory_store, TestTransportMaker, TestTransportTcp},
    tests::helpers::PeerManagerObserver,
    types::peer_id::PeerId,
};
use common::{
    chain::{config, Block},
    primitives::{user_agent::mintlayer_core_user_agent, Id},
    Uint256,
};

use crate::{
    net::default_backend::{transport::TcpTransportSocket, DefaultNetworkingService},
    peer_manager::{tests::utils::wait_for_heartbeat, HEARTBEAT_INTERVAL_MAX},
    PeerManagerEvent,
};

// 1) Setup the peer manager so that it must open 3 block relay connections, 1 of which is
// temporary; let it open the connections.
// 2) Simulate new tip arrival from each peer with 1st peer's tip being the oldest.
// 3) Based on the TestCase enum, make the peer manager expect (or not) a block from the 1st peer.
// 4) Advance the time, so that the connections are mature enough for eviction to be possible.
// The expected result depends on TestCase: if no block was expected from the 1st peer (NoBlocksInFlight),
// it must be evicted. Same should happen if a block is expected, but the timeout has elapsed (BlockInFlightOld).
// Otherwise (BlockInFlightRecent), the 2nd peer should be evicted instead.
mod dont_evict_if_blocks_in_flight {
    use super::*;

    #[derive(Debug)]
    enum TestCase {
        NoBlocksInFlight,
        BlockInFlightRecent,
        BlockInFlightOld,
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test(
        #[case] seed: Seed,
        #[values(
            TestCase::NoBlocksInFlight,
            TestCase::BlockInFlightRecent,
            TestCase::BlockInFlightOld
        )]
        test_case: TestCase,
    ) {
        type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(config::create_unit_test_config());
        // The age should be big enough to allow multiple heartbeats to pass before it may expire.
        let min_connection_age = Duration::from_secs(60 * 60);

        let p2p_config = Arc::new(P2pConfig {
            peer_manager_config: PeerManagerConfig {
                outbound_block_relay_count: 2.into(),
                outbound_block_relay_extra_count: 1.into(),
                outbound_block_relay_connection_min_age: min_connection_age.into(),

                outbound_full_relay_count: 0.into(),
                outbound_full_relay_extra_count: 0.into(),

                enable_feeler_connections: false.into(),

                peerdb_config: PeerDbConfig {
                    salt: Some(Salt::new_random_with_rng(&mut rng)),

                    new_addr_table_bucket_count: Default::default(),
                    tried_addr_table_bucket_count: Default::default(),
                    addr_tables_bucket_size: Default::default(),
                },

                preserved_inbound_count_address_group: Default::default(),
                preserved_inbound_count_ping: Default::default(),
                preserved_inbound_count_new_blocks: Default::default(),
                preserved_inbound_count_new_transactions: Default::default(),

                max_inbound_connections: Default::default(),

                outbound_full_relay_connection_min_age: Default::default(),
                stale_tip_time_diff: Default::default(),

                main_loop_tick_interval: Default::default(),
                feeler_connections_interval: Default::default(),
                force_dns_query_if_no_global_addresses_known: Default::default(),
                allow_same_ip_connections: Default::default(),
            },
            ping_check_period: Duration::ZERO.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            protocol_config: Default::default(),
        });

        let bind_address = TestTransportTcp::make_address();
        let (cmd_sender, mut cmd_receiver) = mpsc::unbounded_channel();
        let (conn_event_sender, conn_event_receiver) = mpsc::unbounded_channel();
        let (peer_mgr_event_sender, peer_mgr_event_receiver) =
            mpsc::unbounded_channel::<PeerManagerEvent>();
        let time_getter = P2pBasicTestTimeGetter::new();
        let connectivity_handle = ConnectivityHandle::<TestNetworkingService>::new(
            vec![],
            cmd_sender,
            conn_event_receiver,
        );
        let (peer_mgr_notification_sender, mut peer_mgr_notification_receiver) =
            mpsc::unbounded_channel();
        let peer_mgr_observer = Box::new(PeerManagerObserver::new(peer_mgr_notification_sender));

        let mut peer_mgr = PeerManager::<TestNetworkingService, _>::new_generic(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            connectivity_handle,
            peer_mgr_event_receiver,
            time_getter.get_time_getter(),
            peerdb_inmemory_store(),
            Some(peer_mgr_observer),
            Box::new(DefaultDnsSeed::new(
                Arc::clone(&chain_config),
                Arc::clone(&p2p_config),
            )),
        )
        .unwrap();

        let addr_count = 3;
        let addresses =
            peerdb::test_utils::make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups(
                &peer_mgr.peerdb,
                addr_count,
                &mut rng,
            );
        let mut addresses = BTreeSet::from_iter(addresses.into_iter());
        for addr in &addresses {
            peer_mgr.peerdb.peer_discovered(*addr);
        }
        let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
            let mut peer_mgr = peer_mgr;
            let _ = peer_mgr.run_internal(None).await;
            peer_mgr
        });

        let mut peer_ids = Vec::new();

        log::debug!("Expecting outbound connection attempt #1");
        let cmd = expect_recv!(cmd_receiver);
        let peer1_addr = expect_connect_cmd(&cmd, &mut addresses);

        log::debug!("Expecting outbound connection attempt #2");
        let cmd = expect_recv!(cmd_receiver);
        let peer2_addr = expect_connect_cmd(&cmd, &mut addresses);

        log::debug!("Expecting outbound connection attempt #3");
        let cmd = expect_recv!(cmd_receiver);
        let peer3_addr = expect_connect_cmd(&cmd, &mut addresses);

        for peer_addr in [peer1_addr, peer2_addr, peer3_addr] {
            let peer_id = PeerId::new();
            conn_event_sender
                .send(ConnectivityEvent::OutboundAccepted {
                    peer_address: peer_addr,
                    bind_address,
                    peer_info: make_block_relay_peer_info(peer_id, &chain_config),
                    node_address_as_seen_by_peer: None,
                })
                .unwrap();

            log::debug!("Expecting Command::Accept");
            let cmd = expect_recv!(cmd_receiver);
            assert_eq!(cmd, Command::Accept { peer_id });

            peer_ids.push(peer_id);
        }

        // One unconditional heartbeat must have occurred early, skip it.
        wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

        // No other commands are sent immediately.
        expect_no_recv!(cmd_receiver);

        peer_mgr_event_sender
            .send(PeerManagerEvent::NewTipReceived {
                peer_id: peer_ids[0],
                block_id: Id::<Block>::new(Uint256::from_u64(1).into()),
            })
            .unwrap();
        time_getter.advance_time(HEARTBEAT_INTERVAL_MAX);
        wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

        time_getter.advance_time(Duration::from_secs(1));

        peer_mgr_event_sender
            .send(PeerManagerEvent::NewTipReceived {
                peer_id: peer_ids[1],
                block_id: Id::<Block>::new(Uint256::from_u64(2).into()),
            })
            .unwrap();
        time_getter.advance_time(HEARTBEAT_INTERVAL_MAX);
        wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

        time_getter.advance_time(Duration::from_secs(1));

        peer_mgr_event_sender
            .send(PeerManagerEvent::NewTipReceived {
                peer_id: peer_ids[2],
                block_id: Id::<Block>::new(Uint256::from_u64(3).into()),
            })
            .unwrap();
        time_getter.advance_time(HEARTBEAT_INTERVAL_MAX);
        wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

        let next_time_advancement = min_connection_age + Duration::from_secs(1);

        let (expect_blocks_since, expected_peer_to_disconnect) = match test_case {
            TestCase::NoBlocksInFlight => (None, peer_ids[0]),
            TestCase::BlockInFlightRecent => {
                let expect_blocks_since = (time_getter.get_time_getter().get_time()
                    + (next_time_advancement - peers_eviction::BLOCK_EXPECTATION_MAX_DURATION
                        + Duration::from_secs(1)))
                .unwrap();

                (Some(expect_blocks_since), peer_ids[1])
            }
            TestCase::BlockInFlightOld => {
                let expect_blocks_since = (time_getter.get_time_getter().get_time()
                    + (next_time_advancement
                        - peers_eviction::BLOCK_EXPECTATION_MAX_DURATION
                        - Duration::from_secs(1)))
                .unwrap();

                (Some(expect_blocks_since), peer_ids[0])
            }
        };

        if let Some(expect_blocks_since) = expect_blocks_since {
            peer_mgr_event_sender
                .send(PeerManagerEvent::PeerBlockSyncStatusUpdate {
                    peer_id: peer_ids[0],
                    new_status: PeerBlockSyncStatus {
                        expecting_blocks_since: Some(expect_blocks_since),
                    },
                })
                .unwrap();
        }

        // Advance the time so that all connections become mature and can be evicted from now on.
        time_getter.advance_time(next_time_advancement);

        let cmd = expect_recv!(cmd_receiver);
        assert_eq!(
            cmd,
            Command::Disconnect {
                peer_id: expected_peer_to_disconnect
            }
        );

        drop(conn_event_sender);
        drop(peer_mgr_event_sender);

        let _peer_mgr = peer_mgr_join_handle.await.unwrap();
    }
}
