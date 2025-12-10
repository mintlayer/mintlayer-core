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

use rstest::rstest;

use common::{
    chain::{config, Block},
    primitives::{user_agent::mintlayer_core_user_agent, Id},
    Uint256,
};
use logging::log;
use networking::test_helpers::{TestTransportMaker, TestTransportTcp};
use p2p_test_utils::{expect_no_recv, expect_recv};
use test_utils::{
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    net::default_backend::types::Command,
    peer_manager::{
        config::PeerManagerConfig,
        peerdb::{self, config::PeerDbConfig, salt::Salt},
        peers_eviction,
        tests::{
            make_standalone_peer_manager,
            utils::{expect_cmd_connect_to_one_of, outbound_block_relay_peer_accepted_by_backend},
        },
        HEARTBEAT_INTERVAL_MAX,
    },
    sync::sync_status::PeerBlockSyncStatus,
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
        use crate::peer_manager::tests::utils::wait_for_heartbeat;

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
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            protocol_config: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let bind_address = TestTransportTcp::make_address().into();
        let time_getter = BasicTestTimeGetter::new();

        let (
            mut peer_mgr,
            conn_event_sender,
            peer_mgr_event_sender,
            mut cmd_receiver,
            mut peer_mgr_notification_receiver,
        ) = make_standalone_peer_manager(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            vec![bind_address],
            time_getter.get_time_getter(),
        );

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
        let peer1_addr = expect_cmd_connect_to_one_of(&cmd, &mut addresses);

        log::debug!("Expecting outbound connection attempt #2");
        let cmd = expect_recv!(cmd_receiver);
        let peer2_addr = expect_cmd_connect_to_one_of(&cmd, &mut addresses);

        log::debug!("Expecting outbound connection attempt #3");
        let cmd = expect_recv!(cmd_receiver);
        let peer3_addr = expect_cmd_connect_to_one_of(&cmd, &mut addresses);

        for peer_addr in [peer1_addr, peer2_addr, peer3_addr] {
            let peer_id = outbound_block_relay_peer_accepted_by_backend(
                &conn_event_sender,
                peer_addr,
                bind_address,
                &chain_config,
            );

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
                peer_id: expected_peer_to_disconnect,
                reason: Some(DisconnectionReason::PeerEvicted),
            }
        );

        drop(conn_event_sender);
        drop(peer_mgr_event_sender);

        let _peer_mgr = peer_mgr_join_handle.await.unwrap();
    }
}
