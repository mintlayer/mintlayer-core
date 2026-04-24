// Copyright (c) 2026 RBB S.r.l
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

//! These tests check that `AddressData`'s `fail_count` and `connections_without_activity_count`
//! are correctly updated after a failed connection or connection without peer activity, respectively.

use std::{sync::Arc, time::Duration};

use rstest::rstest;
use tokio::sync::mpsc;

use common::{
    chain::{
        config::{self},
        ChainConfig,
    },
    primitives::time::Time,
};
use logging::log;
use networking::test_helpers::{TestAddressMaker, TestTransportMaker, TestTransportTcp};
use p2p_test_utils::{expect_no_recv, expect_recv};
use p2p_types::socket_address::SocketAddress;
use randomness::RngExt;
use test_utils::{
    assert_matches, assert_matches_return_val,
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};
use utils::tokio_spawn_in_current_tracing_span;

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    error::{DialError, P2pError},
    net::{
        default_backend::types::{Command, Message},
        types::{ConnectivityEvent, PeerManagerMessageExt, PeerManagerMessageExtTag, PeerRole},
    },
    peer_manager::{
        self,
        config::PeerManagerConfig,
        peerdb::address_data::AddressState,
        test_utils::{add_reserved_peer, wait_for_heartbeat},
        tests::{
            make_standalone_peer_manager,
            utils::{
                connection_closed, expect_cmd_connect_to,
                inbound_full_relay_peer_accepted_by_backend, mutate_peer_manager,
                outbound_peer_accepted_by_backend, query_peer_manager, start_manually_connecting,
            },
        },
    },
    test_helpers::test_p2p_config_with_peer_mgr_config,
    tests::helpers::PeerManagerNotification,
    types::peer_id::PeerId,
    PeerManagerEvent,
};

// Check the case of an automatic connection failure when the peer address would end up in the
// `Disconnected` state.
// 1) Set up the peer manager so that the connection of the corresponding type would occur.
// 2) For non-reserved connections, force-set peer address's `was_reachable` field to true
//    (otherwise the address would be put into `Unreachable` state after the first unsuccessful
//    connection attempt). For reserved connections try both variants.
// 3) In a loop, advance the time so that the corresponding connection would be attempted;
//    make the connection fail; check that `fail_count` has been incremented.
// 4) Occasionally, accept an inbound connection from the peer address; expect that it doesn't
//    affect the current `fail_count`.
// 5) On the last iteration of the loop make the connection succeed; check that `fail_count` has been
//    set to zero.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn auto_connection_fails_peer_state_becomes_disconnected(
    #[case] seed: Seed,
    #[values(
        (AutoConnType::FullRelay, true),
        (AutoConnType::BlockRelay, true),
        (AutoConnType::Reserved, true),
        (AutoConnType::Reserved, false),
        (AutoConnType::Feeler, true),
    )]
    (conn_type, was_reachable): (AutoConnType, bool),
) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let feeler_connections_interval = Duration::from_secs(rng.random_range(1..100));
    let p2p_config = make_p2p_config_for_auto_connection(conn_type, feeler_connections_interval);
    let time_getter = BasicTestTimeGetter::new();

    let bind_address: SocketAddress = TestTransportTcp::make_address().into();
    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        mut peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_address],
        time_getter.get_time_getter(),
        make_seedable_rng(rng.random()),
    );

    let peer_address: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();

    let is_feeler_connection = matches!(conn_type, AutoConnType::Feeler);
    let is_reserved_connection = matches!(conn_type, AutoConnType::Reserved);
    let is_block_relay_connection = matches!(conn_type, AutoConnType::BlockRelay);

    let peer_mgr_join_handle = tokio_spawn_in_current_tracing_span(
        async move {
            let mut peer_mgr = peer_mgr;
            let _ = peer_mgr.run_internal(None).await;
            peer_mgr
        },
        "",
    );

    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let peer_discovery_time = time_getter.get_time_getter().get_time();
    discover_peer(&peer_mgr_event_sender, peer_address, was_reachable).await;

    let peer_addr_state =
        expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
    assert_eq!(
        peer_addr_state,
        AddressStateDisconnected {
            was_reachable,
            fail_count: 0,
            next_connect_after: peer_discovery_time,
            connections_without_activity_count: 0,
        }
    );

    if is_reserved_connection {
        add_reserved_peer(&peer_mgr_event_sender, peer_address.socket_addr().into()).await;
    }

    let num_iterations = rng.random_range(5..10);
    let mut last_connect_after = Time::from_duration_since_epoch(Duration::ZERO);

    for i in 0..num_iterations {
        log::debug!("Running iteration {i} out of {num_iterations}");

        let time_before_wait = time_getter.get_time_getter().get_time();
        let connect_after = if is_feeler_connection {
            let next_feeler_connection_time =
                query_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
                    peer_mgr.next_feeler_connection_time()
                })
                .await;

            std::cmp::max(last_connect_after, next_feeler_connection_time)
        } else {
            last_connect_after
        };

        let wait_duration = std::cmp::max(
            connect_after
                .as_duration_since_epoch()
                .checked_sub(time_before_wait.as_duration_since_epoch())
                .unwrap_or(Duration::ZERO),
            peer_manager::HEARTBEAT_INTERVAL_MAX,
        );

        time_getter.advance_time_rounded_up(wait_duration);
        wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

        let cmd = expect_recv!(cmd_receiver);
        expect_cmd_connect_to(&cmd, &peer_address);

        let is_last_iteration = i == num_iterations - 1;

        if is_last_iteration {
            let peer_id = outbound_peer_accepted_by_backend(
                &conn_event_sender,
                peer_address,
                bind_address,
                &chain_config,
                !is_block_relay_connection,
            );

            peer_accepted_by_peer_mgr(
                &mut cmd_receiver,
                &mut peer_mgr_notification_receiver,
                peer_id,
                peer_address,
                conn_type.to_peer_role(),
            )
            .await;

            close_connection(
                &conn_event_sender,
                &mut peer_mgr_notification_receiver,
                peer_id,
            )
            .await;
        } else {
            let connection_error = P2pError::DialError(DialError::ConnectionRefusedOrTimedOut);

            conn_event_sender
                .send(ConnectivityEvent::ConnectionError {
                    peer_address,
                    error: connection_error.clone(),
                })
                .unwrap();

            let peer_mgr_notification = expect_recv!(peer_mgr_notification_receiver);
            assert_eq!(
                peer_mgr_notification,
                PeerManagerNotification::OutboundError {
                    address: peer_address,
                    error: connection_error.clone()
                }
            );

            // An inbound connection shouldn't change the outcome even if it's successful.
            if rng.random_bool(0.5) {
                log::debug!("Accepting an extra inbound connection");

                inbound_full_relay_peer_connected_and_disconnected(
                    &conn_event_sender,
                    &mut cmd_receiver,
                    &mut peer_mgr_notification_receiver,
                    peer_address,
                    bind_address,
                    &chain_config,
                )
                .await;
            }
        }

        let expected_fail_count = if is_last_iteration { 0 } else { i + 1 };
        let expected_connections_without_activity_count =
            if is_last_iteration && !is_feeler_connection {
                1
            } else {
                0
            };

        let time_after_wait = time_getter.get_time_getter().get_time();

        let peer_addr_state =
            expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
        assert_eq!(
            peer_addr_state.was_reachable,
            was_reachable || is_last_iteration
        );
        assert_eq!(peer_addr_state.fail_count, expected_fail_count);
        assert!(peer_addr_state.next_connect_after > time_after_wait);
        assert_eq!(
            peer_addr_state.connections_without_activity_count,
            expected_connections_without_activity_count
        );

        last_connect_after = peer_addr_state.next_connect_after;
    }

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check the case of an automatic connection failure when the peer address would end up in the
// `Unreachable` state.
// 1) Set up the peer manager so that the connection of the corresponding type would occur.
//    Keep peer address's `was_reachable` field at false.
// 3) Advance the time so that the corresponding connection would be attempted; make the
//    connection fail; check that the peer address state is now `Unreachable`.
// 4) Optionally, accept an inbound connection from the peer address; expect that it doesn't
//    affect the current address state.
// 5) Check that no further connection attempts are made.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn auto_connection_fails_peer_state_becomes_unreachable(
    #[case] seed: Seed,
    #[values(
        AutoConnType::FullRelay,
        AutoConnType::BlockRelay,
        AutoConnType::Feeler
    )]
    conn_type: AutoConnType,
) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let feeler_connections_interval = Duration::from_secs(rng.random_range(1..100));
    let p2p_config = make_p2p_config_for_auto_connection(conn_type, feeler_connections_interval);
    let time_getter = BasicTestTimeGetter::new();

    let bind_address: SocketAddress = TestTransportTcp::make_address().into();
    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        mut peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_address],
        time_getter.get_time_getter(),
        make_seedable_rng(rng.random()),
    );

    let peer_address: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();

    let is_feeler_connection = matches!(conn_type, AutoConnType::Feeler);
    let is_reserved_connection = matches!(conn_type, AutoConnType::Reserved);

    let peer_mgr_join_handle = tokio_spawn_in_current_tracing_span(
        async move {
            let mut peer_mgr = peer_mgr;
            let _ = peer_mgr.run_internal(None).await;
            peer_mgr
        },
        "",
    );

    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let peer_discovery_time = time_getter.get_time_getter().get_time();
    discover_peer(&peer_mgr_event_sender, peer_address, false).await;

    let peer_addr_state =
        expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
    assert_eq!(
        peer_addr_state,
        AddressStateDisconnected {
            was_reachable: false,
            fail_count: 0,
            next_connect_after: peer_discovery_time,
            connections_without_activity_count: 0
        }
    );

    if is_reserved_connection {
        add_reserved_peer(&peer_mgr_event_sender, peer_address.socket_addr().into()).await;
    }

    let time_before_wait = time_getter.get_time_getter().get_time();
    let connect_after = if is_feeler_connection {
        query_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
            peer_mgr.next_feeler_connection_time()
        })
        .await
    } else {
        Time::from_duration_since_epoch(Duration::ZERO)
    };

    let wait_duration = std::cmp::max(
        connect_after
            .as_duration_since_epoch()
            .checked_sub(time_before_wait.as_duration_since_epoch())
            .unwrap_or(Duration::ZERO),
        peer_manager::HEARTBEAT_INTERVAL_MAX,
    );

    time_getter.advance_time_rounded_up(wait_duration);
    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &peer_address);

    let connection_error = P2pError::DialError(DialError::ConnectionRefusedOrTimedOut);

    conn_event_sender
        .send(ConnectivityEvent::ConnectionError {
            peer_address,
            error: connection_error.clone(),
        })
        .unwrap();

    let peer_mgr_notification = expect_recv!(peer_mgr_notification_receiver);
    assert_eq!(
        peer_mgr_notification,
        PeerManagerNotification::OutboundError {
            address: peer_address,
            error: connection_error.clone()
        }
    );

    // An inbound connection shouldn't change the outcome even if it's successful.
    if rng.random_bool(0.5) {
        log::debug!("Accepting an extra inbound connection");

        inbound_full_relay_peer_connected_and_disconnected(
            &conn_event_sender,
            &mut cmd_receiver,
            &mut peer_mgr_notification_receiver,
            peer_address,
            bind_address,
            &chain_config,
        )
        .await;
    }

    let time_after_wait = time_getter.get_time_getter().get_time();

    let peer_addr_state = expect_peer_state_unreachable(&peer_mgr_event_sender, peer_address).await;
    assert!(peer_addr_state.erase_after > time_after_wait);

    // No further connection attempts should be made.
    time_getter.advance_time(peer_manager::HEARTBEAT_INTERVAL_MAX * 1000);
    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;
    expect_no_recv!(cmd_receiver);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check the case of a manual connection failure.
// 1) Setup the peer manager, optionally force-setting the peer address's `was_reachable` field
//    to true.
// 2) In a loop, attempt a manual connection to the peer and make it fail. Check that:
//    a) if `was_reachable` was true, the resulting address state is `Disconnected` and `fail_count`
//       has been incremented;
//    b) otherwise the resulting address state is `Unreachable`.
// 3) Occasionally, accept an inbound connection from the peer address; expect that it doesn't
//    affect the current address state.
// 4) On the last iteration make the connection succeed. Check that the resulting address state is
//    now `Disconnected` with zero `fail_count`.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn manual_connection_fails(#[case] seed: Seed, #[values(false, true)] make_reachable: bool) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = {
        let peer_mgr_config = PeerManagerConfig {
            outbound_block_relay_count: 0.into(),
            outbound_block_relay_extra_count: 0.into(),
            outbound_full_relay_count: 0.into(),
            outbound_full_relay_extra_count: 0.into(),
            enable_feeler_connections: false.into(),

            max_inbound_connections: Default::default(),
            preserved_inbound_count_address_group: Default::default(),
            preserved_inbound_count_ping: Default::default(),
            preserved_inbound_count_new_blocks: Default::default(),
            preserved_inbound_count_new_transactions: Default::default(),
            outbound_block_relay_connection_min_age: Default::default(),
            outbound_full_relay_connection_min_age: Default::default(),
            stale_tip_time_diff: Default::default(),
            main_loop_tick_interval: Default::default(),
            feeler_connections_interval: Default::default(),
            force_dns_query_if_no_global_addresses_known: Default::default(),
            allow_same_ip_connections: Default::default(),
            peerdb_config: Default::default(),
            min_peer_software_version: Default::default(),
        };

        Arc::new(test_p2p_config_with_peer_mgr_config(peer_mgr_config))
    };

    let time_getter = BasicTestTimeGetter::new();

    let bind_address: SocketAddress = TestTransportTcp::make_address().into();
    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        mut peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_address],
        time_getter.get_time_getter(),
        make_seedable_rng(rng.random()),
    );

    let peer_address: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();

    let peer_mgr_join_handle = tokio_spawn_in_current_tracing_span(
        async move {
            let mut peer_mgr = peer_mgr;
            let _ = peer_mgr.run_internal(None).await;
            peer_mgr
        },
        "",
    );

    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    if make_reachable {
        let peer_discovery_time = time_getter.get_time_getter().get_time();
        discover_peer(&peer_mgr_event_sender, peer_address, true).await;

        let peer_addr_state =
            expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
        assert_eq!(
            peer_addr_state,
            AddressStateDisconnected {
                was_reachable: true,
                fail_count: 0,
                next_connect_after: peer_discovery_time,
                connections_without_activity_count: 0
            }
        );
    } else {
        expect_no_peer_state(&peer_mgr_event_sender, peer_address).await;
    }

    let num_iterations = rng.random_range(5..10);
    let mut erase_after = None;

    let now = time_getter.get_time_getter().get_time();

    for i in 0..num_iterations {
        log::debug!("Running iteration {i} out of {num_iterations}");

        let is_last_iteration = i == num_iterations - 1;

        if is_last_iteration {
            start_and_close_manual_connection(
                &conn_event_sender,
                &peer_mgr_event_sender,
                &mut cmd_receiver,
                &mut peer_mgr_notification_receiver,
                peer_address,
                bind_address,
                &chain_config,
            )
            .await;
        } else {
            attempt_and_fail_manual_connection(
                &conn_event_sender,
                &peer_mgr_event_sender,
                &mut cmd_receiver,
                &mut peer_mgr_notification_receiver,
                peer_address,
            )
            .await;

            // An inbound connection shouldn't change the outcome even if it's successful.
            if rng.random_bool(0.5) {
                log::debug!("Accepting an extra inbound connection");

                inbound_full_relay_peer_connected_and_disconnected(
                    &conn_event_sender,
                    &mut cmd_receiver,
                    &mut peer_mgr_notification_receiver,
                    peer_address,
                    bind_address,
                    &chain_config,
                )
                .await;
            }
        }

        if make_reachable || is_last_iteration {
            let fail_count = if is_last_iteration { 0 } else { i + 1 };
            let peer_addr_state =
                expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
            assert!(peer_addr_state.was_reachable);
            assert_eq!(peer_addr_state.fail_count, fail_count);
            assert!(peer_addr_state.next_connect_after > now);
            assert_eq!(peer_addr_state.connections_without_activity_count, 0);
        } else {
            let peer_addr_state =
                expect_peer_state_unreachable(&peer_mgr_event_sender, peer_address).await;

            if i == 0 {
                assert!(peer_addr_state.erase_after > now);
                erase_after = Some(peer_addr_state.erase_after);
            } else {
                // For unreachable addresses erase_after doesn't change on further unsuccessful connection attempts.
                assert_eq!(peer_addr_state.erase_after, erase_after.unwrap());
            }
        }
    }

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check the case of a successful automatic connection without any peer activity.
// 1) Set up the peer manager so that the connection of the corresponding type would occur.
// 2) In a loop, advance the time so that the corresponding connection would be attempted.
//    Make the connection succeed and close it immediately; check that `connections_without_activity_count`
//    has been incremented.
// 3) Occasionally, make a successful incoming or manual outgoing connection without peer activity, or an unsuccessful
//    manual outgoing connection. Expect that this doesn't affect `connections_without_activity_count`.
// 4) On the final iteration make the peer actually send a message. Check that `connections_without_activity_count` has
//    been reset to zero.
// Note that feeler connections are not checked in this test because once a feeler connection succeeds, it won't
// be attempted again.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn auto_connection_without_peer_activity(
    #[case] seed: Seed,
    #[values(
        AutoConnType::FullRelay,
        AutoConnType::BlockRelay,
        AutoConnType::Reserved
    )]
    conn_type: AutoConnType,
) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = make_p2p_config_for_auto_connection(conn_type, Duration::ZERO);
    let time_getter = BasicTestTimeGetter::new();

    let bind_address: SocketAddress = TestTransportTcp::make_address().into();
    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        mut peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_address],
        time_getter.get_time_getter(),
        make_seedable_rng(rng.random()),
    );

    let peer_address: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();

    let is_reserved_connection = matches!(conn_type, AutoConnType::Reserved);
    let is_block_relay_connection = matches!(conn_type, AutoConnType::BlockRelay);
    let is_full_relay_connection = matches!(conn_type, AutoConnType::FullRelay);

    let peer_mgr_join_handle = tokio_spawn_in_current_tracing_span(
        async move {
            let mut peer_mgr = peer_mgr;
            let _ = peer_mgr.run_internal(None).await;
            peer_mgr
        },
        "",
    );

    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let peer_discovery_time = time_getter.get_time_getter().get_time();
    discover_peer(&peer_mgr_event_sender, peer_address, false).await;

    let peer_addr_state =
        expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
    assert_eq!(
        peer_addr_state,
        AddressStateDisconnected {
            was_reachable: false,
            fail_count: 0,
            next_connect_after: peer_discovery_time,
            connections_without_activity_count: 0
        }
    );

    if is_reserved_connection {
        add_reserved_peer(&peer_mgr_event_sender, peer_address.socket_addr().into()).await;
    }

    let num_iterations = rng.random_range(5..10);
    let mut last_connect_after = Time::from_duration_since_epoch(Duration::ZERO);

    for i in 0..num_iterations {
        log::debug!("Running iteration {i} out of {num_iterations}");

        let time_before_wait = time_getter.get_time_getter().get_time();
        let wait_duration = std::cmp::max(
            last_connect_after
                .as_duration_since_epoch()
                .checked_sub(time_before_wait.as_duration_since_epoch())
                .unwrap_or(Duration::ZERO),
            peer_manager::HEARTBEAT_INTERVAL_MAX,
        );

        time_getter.advance_time_rounded_up(wait_duration);
        wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

        let cmd = expect_recv!(cmd_receiver);
        expect_cmd_connect_to(&cmd, &peer_address);

        let peer_id = outbound_peer_accepted_by_backend(
            &conn_event_sender,
            peer_address,
            bind_address,
            &chain_config,
            !is_block_relay_connection,
        );

        peer_accepted_by_peer_mgr(
            &mut cmd_receiver,
            &mut peer_mgr_notification_receiver,
            peer_id,
            peer_address,
            conn_type.to_peer_role(),
        )
        .await;

        if is_reserved_connection || is_full_relay_connection {
            // If the case of a reserved or full relay connection, the peer manager will send
            // AddrListRequest to the peer.
            let cmd = expect_recv!(cmd_receiver);
            let (peer_id_in_cmd, message) = assert_matches_return_val!(
                cmd,
                Command::SendMessage { peer_id, message },
                (peer_id, message)
            );
            assert_eq!(peer_id_in_cmd, peer_id);
            assert_matches!(message, Message::AddrListRequest(_));
        }

        let is_last_iteration = i == num_iterations - 1;

        if is_last_iteration {
            conn_event_sender
                .send(ConnectivityEvent::Message {
                    peer_id,
                    message: PeerManagerMessageExt::FirstSyncMessageReceived,
                })
                .unwrap();

            let peer_mgr_notification = expect_recv!(peer_mgr_notification_receiver);
            assert_eq!(
                peer_mgr_notification,
                PeerManagerNotification::MessageReceived {
                    peer_id,
                    message_tag: PeerManagerMessageExtTag::FirstSyncMessageReceived
                }
            );
        }

        close_connection(
            &conn_event_sender,
            &mut peer_mgr_notification_receiver,
            peer_id,
        )
        .await;

        // An inbound or manual connection without peer activity shouldn't affect connections_without_activity_count.
        // Same for a failed outbound connection.
        let extra_outbound_connection_failed = match rng.random_range(0..4) {
            0 => {
                log::debug!("Accepting an extra inbound connection");

                inbound_full_relay_peer_connected_and_disconnected(
                    &conn_event_sender,
                    &mut cmd_receiver,
                    &mut peer_mgr_notification_receiver,
                    peer_address,
                    bind_address,
                    &chain_config,
                )
                .await;

                false
            }
            1 => {
                log::debug!("Making an extra successful manual outbound connection");

                start_and_close_manual_connection(
                    &conn_event_sender,
                    &peer_mgr_event_sender,
                    &mut cmd_receiver,
                    &mut peer_mgr_notification_receiver,
                    peer_address,
                    bind_address,
                    &chain_config,
                )
                .await;

                false
            }
            2 => {
                log::debug!("Making an extra unsuccessful manual outbound connection");

                attempt_and_fail_manual_connection(
                    &conn_event_sender,
                    &peer_mgr_event_sender,
                    &mut cmd_receiver,
                    &mut peer_mgr_notification_receiver,
                    peer_address,
                )
                .await;

                true
            }

            _ => false,
        };

        let expected_connections_without_activity_count = if is_last_iteration { 0 } else { i + 1 };
        let expected_fail_count = if extra_outbound_connection_failed {
            1
        } else {
            0
        };

        let time_after_wait = time_getter.get_time_getter().get_time();

        let peer_addr_state =
            expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
        assert!(peer_addr_state.was_reachable);
        assert_eq!(peer_addr_state.fail_count, expected_fail_count);
        assert!(peer_addr_state.next_connect_after > time_after_wait);
        assert_eq!(
            peer_addr_state.connections_without_activity_count,
            expected_connections_without_activity_count
        );

        last_connect_after = peer_addr_state.next_connect_after;
    }

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check the case of a successful feeler connection without any peer activity.
// 1) Set up the peer manager so that a feeler connection would occur.
// 2) Advance the time so that the connection would be attempted.
//    Make it succeed and check that disconnection is initiated immediately. Close the connection.
// 3) `connections_without_activity_count` should remain zero.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn feeler_connection_without_peer_activity(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let feeler_connections_interval = Duration::from_secs(rng.random_range(1..100));
    let p2p_config =
        make_p2p_config_for_auto_connection(AutoConnType::Feeler, feeler_connections_interval);
    let time_getter = BasicTestTimeGetter::new();

    let bind_address: SocketAddress = TestTransportTcp::make_address().into();
    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        mut peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_address],
        time_getter.get_time_getter(),
        make_seedable_rng(rng.random()),
    );

    let peer_address: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();

    let peer_mgr_join_handle = tokio_spawn_in_current_tracing_span(
        async move {
            let mut peer_mgr = peer_mgr;
            let _ = peer_mgr.run_internal(None).await;
            peer_mgr
        },
        "",
    );

    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let peer_discovery_time = time_getter.get_time_getter().get_time();
    discover_peer(&peer_mgr_event_sender, peer_address, false).await;

    let peer_addr_state =
        expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
    assert_eq!(
        peer_addr_state,
        AddressStateDisconnected {
            was_reachable: false,
            fail_count: 0,
            next_connect_after: peer_discovery_time,
            connections_without_activity_count: 0
        }
    );

    let time_before_wait = time_getter.get_time_getter().get_time();
    let next_feeler_connection_time = query_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.next_feeler_connection_time()
    })
    .await;
    let wait_duration = std::cmp::max(
        next_feeler_connection_time
            .as_duration_since_epoch()
            .checked_sub(time_before_wait.as_duration_since_epoch())
            .unwrap_or(Duration::ZERO),
        peer_manager::HEARTBEAT_INTERVAL_MAX,
    );

    time_getter.advance_time_rounded_up(wait_duration);
    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &peer_address);

    let peer_id = outbound_peer_accepted_by_backend(
        &conn_event_sender,
        peer_address,
        bind_address,
        &chain_config,
        true,
    );

    peer_accepted_by_peer_mgr(
        &mut cmd_receiver,
        &mut peer_mgr_notification_receiver,
        peer_id,
        peer_address,
        PeerRole::Feeler,
    )
    .await;

    // Since it's a feeler connection, the peer manager will initiate disconnection right away.
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Disconnect {
            peer_id,
            reason: Some(DisconnectionReason::FeelerConnection)
        }
    );

    close_connection(
        &conn_event_sender,
        &mut peer_mgr_notification_receiver,
        peer_id,
    )
    .await;

    let time_after_wait = time_getter.get_time_getter().get_time();

    let peer_addr_state =
        expect_peer_state_disconnected(&peer_mgr_event_sender, peer_address).await;
    assert!(peer_addr_state.was_reachable);
    assert_eq!(peer_addr_state.fail_count, 0);
    assert!(peer_addr_state.next_connect_after > time_after_wait);
    assert_eq!(peer_addr_state.connections_without_activity_count, 0);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

#[derive(Debug, Copy, Clone)]
enum AutoConnType {
    FullRelay,
    BlockRelay,
    Reserved,
    Feeler,
}

impl AutoConnType {
    fn to_peer_role(self) -> PeerRole {
        match self {
            AutoConnType::FullRelay => PeerRole::OutboundFullRelay,
            AutoConnType::BlockRelay => PeerRole::OutboundBlockRelay,
            AutoConnType::Reserved => PeerRole::OutboundReserved,
            AutoConnType::Feeler => PeerRole::Feeler,
        }
    }
}

fn make_p2p_config_for_auto_connection(
    conn_type: AutoConnType,
    feeler_connections_interval: Duration,
) -> Arc<P2pConfig> {
    let mut outbound_block_relay_count = 0;
    let mut outbound_full_relay_count = 0;
    let mut enable_feeler_connections = false;

    match conn_type {
        AutoConnType::FullRelay => {
            outbound_full_relay_count = 1;
        }
        AutoConnType::BlockRelay => {
            outbound_block_relay_count = 1;
        }
        AutoConnType::Feeler => {
            enable_feeler_connections = true;
        }
        AutoConnType::Reserved => {}
    };

    let peer_mgr_config = PeerManagerConfig {
        outbound_block_relay_count: outbound_block_relay_count.into(),
        outbound_block_relay_extra_count: 0.into(),
        outbound_full_relay_count: outbound_full_relay_count.into(),
        outbound_full_relay_extra_count: 0.into(),
        enable_feeler_connections: enable_feeler_connections.into(),
        feeler_connections_interval: feeler_connections_interval.into(),

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
        peerdb_config: Default::default(),
        min_peer_software_version: Default::default(),
    };

    Arc::new(test_p2p_config_with_peer_mgr_config(peer_mgr_config))
}

async fn discover_peer(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    peer_address: SocketAddress,
    make_reachable: bool,
) {
    mutate_peer_manager(peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db_mut().peer_discovered(peer_address);

        if make_reachable {
            let addr_data = peer_mgr.peer_db_mut().address_data_mut(&peer_address).unwrap();

            let was_reachable = assert_matches_return_val!(
                addr_data.state_mut(),
                AddressState::Disconnected { was_reachable, .. },
                was_reachable
            );

            *was_reachable = true
        }
    })
    .await;
}

// Contents of AddressState::Disconnected and also the `connections_without_activity_count`
// field that is part of `AddressData`.
#[derive(Eq, PartialEq, Clone, Debug)]
struct AddressStateDisconnected {
    was_reachable: bool,
    fail_count: u32,
    next_connect_after: Time,
    connections_without_activity_count: u32,
}

// Contents of AddressState::Unreachable
#[derive(Eq, PartialEq, Clone, Debug)]
struct AddressStateUnreachable {
    erase_after: Time,
}

#[must_use]
async fn expect_peer_state_disconnected(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    peer_address: SocketAddress,
) -> AddressStateDisconnected {
    query_peer_manager(peer_mgr_event_sender, move |peer_mgr| {
        let addr_data = peer_mgr.peer_db().address_data(&peer_address).unwrap();
        assert_matches_return_val!(
            addr_data.state().clone(),
            AddressState::Disconnected {
                was_reachable,
                fail_count,
                next_connect_after
            },
            AddressStateDisconnected {
                was_reachable,
                fail_count,
                next_connect_after,
                connections_without_activity_count: addr_data.connections_without_activity_count()
            }
        )
    })
    .await
}

#[must_use]
async fn expect_peer_state_unreachable(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    peer_address: SocketAddress,
) -> AddressStateUnreachable {
    query_peer_manager(peer_mgr_event_sender, move |peer_mgr| {
        let addr_data = peer_mgr.peer_db().address_data(&peer_address).unwrap();
        assert_matches_return_val!(
            addr_data.state().clone(),
            AddressState::Unreachable { erase_after },
            AddressStateUnreachable { erase_after }
        )
    })
    .await
}

async fn expect_no_peer_state(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    peer_address: SocketAddress,
) {
    query_peer_manager(peer_mgr_event_sender, move |peer_mgr| {
        assert!(peer_mgr.peer_db().address_data(&peer_address).is_none());
    })
    .await
}

async fn peer_accepted_by_peer_mgr(
    cmd_receiver: &mut mpsc::UnboundedReceiver<Command>,
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
    peer_id: PeerId,
    peer_address: SocketAddress,
    peer_role: PeerRole,
) {
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id });

    let peer_mgr_notification = expect_recv!(peer_mgr_notification_receiver);
    assert_eq!(
        peer_mgr_notification,
        PeerManagerNotification::ConnectionAccepted {
            address: peer_address,
            peer_id,
            peer_role
        }
    );
}

async fn close_connection(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
    peer_id: PeerId,
) {
    connection_closed(conn_event_sender, peer_id);

    let peer_mgr_notification = expect_recv!(peer_mgr_notification_receiver);
    assert_eq!(
        peer_mgr_notification,
        PeerManagerNotification::ConnectionClosed { peer_id }
    );
}

async fn inbound_full_relay_peer_connected_and_disconnected(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    cmd_receiver: &mut mpsc::UnboundedReceiver<Command>,
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
    peer_address: SocketAddress,
    bind_address: SocketAddress,
    chain_config: &ChainConfig,
) {
    let peer_id = inbound_full_relay_peer_accepted_by_backend(
        conn_event_sender,
        peer_address,
        bind_address,
        chain_config,
    );
    peer_accepted_by_peer_mgr(
        cmd_receiver,
        peer_mgr_notification_receiver,
        peer_id,
        peer_address,
        PeerRole::Inbound,
    )
    .await;

    close_connection(conn_event_sender, peer_mgr_notification_receiver, peer_id).await;
}

async fn start_and_close_manual_connection(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    cmd_receiver: &mut mpsc::UnboundedReceiver<Command>,
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
    peer_address: SocketAddress,
    bind_address: SocketAddress,
    chain_config: &ChainConfig,
) {
    let result_recv = start_manually_connecting(peer_mgr_event_sender, peer_address);

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &peer_address);

    let peer_id = outbound_peer_accepted_by_backend(
        conn_event_sender,
        peer_address,
        bind_address,
        chain_config,
        true,
    );

    peer_accepted_by_peer_mgr(
        cmd_receiver,
        peer_mgr_notification_receiver,
        peer_id,
        peer_address,
        PeerRole::OutboundManual,
    )
    .await;

    result_recv.await.unwrap().unwrap();

    // Since it's a manual connection, the peer manager will send AddrListRequest to the peer.
    let cmd = expect_recv!(cmd_receiver);
    let (peer_id_in_cmd, message) = assert_matches_return_val!(
        cmd,
        Command::SendMessage { peer_id, message },
        (peer_id, message)
    );
    assert_eq!(peer_id_in_cmd, peer_id);
    assert_matches!(message, Message::AddrListRequest(_));

    close_connection(conn_event_sender, peer_mgr_notification_receiver, peer_id).await;
}

async fn attempt_and_fail_manual_connection(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    cmd_receiver: &mut mpsc::UnboundedReceiver<Command>,
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
    peer_address: SocketAddress,
) {
    let result_recv = start_manually_connecting(peer_mgr_event_sender, peer_address);

    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &peer_address);

    let connection_error = P2pError::DialError(DialError::ConnectionRefusedOrTimedOut);

    conn_event_sender
        .send(ConnectivityEvent::ConnectionError {
            peer_address,
            error: connection_error.clone(),
        })
        .unwrap();

    let peer_mgr_notification = expect_recv!(peer_mgr_notification_receiver);
    assert_eq!(
        peer_mgr_notification,
        PeerManagerNotification::OutboundError {
            address: peer_address,
            error: connection_error.clone()
        }
    );

    assert_eq!(result_recv.await.unwrap(), Err(connection_error));
}
