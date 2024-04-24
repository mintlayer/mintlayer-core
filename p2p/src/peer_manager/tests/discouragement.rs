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

use std::{sync::Arc, time::Duration};

use rstest::rstest;

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use networking::test_helpers::{TestAddressMaker, TestTransportMaker, TestTransportTcp};
use p2p_test_utils::{expect_no_recv, expect_recv, wait_for_no_recv};
use test_utils::{
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    ban_config::BanConfig,
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    message::{AddrListRequest, AddrListResponse, AnnounceAddrRequest, PeerManagerMessage},
    net::{
        default_backend::types::{Command, Message},
        types::ConnectivityEvent,
    },
    peer_manager::{
        config::PeerManagerConfig,
        peerdb::test_utils::make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups,
        tests::{
            make_standalone_peer_manager,
            utils::{
                adjust_peer_score, expect_cmd_connect_to,
                inbound_block_relay_peer_accepted_by_backend,
                inbound_full_relay_peer_accepted_by_backend,
                outbound_block_relay_peer_accepted_by_backend, query_peer_manager,
                wait_for_heartbeat,
            },
        },
        MAX_ADDR_RATE_PER_SECOND,
    },
    test_helpers::{
        test_p2p_config_with_ban_config, test_p2p_config_with_peer_mgr_config,
        test_peer_mgr_config_with_no_auto_outbound_connections,
    },
};

// Check that a peer is discouraged once the threshold is reached.
// Also check that
// 1) it's disconnected when becoming discouraged;
// 2) it's no longer discouraged once the duration has expired.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn discourage_connected_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let ban_config = BanConfig {
        discouragement_threshold: 100.into(),
        discouragement_duration: Duration::from_secs(60 * 60).into(),
    };
    let p2p_config = Arc::new(test_p2p_config_with_ban_config(ban_config.clone()));

    let time_getter = BasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address().into();

    let (
        peer_mgr,
        conn_event_sender,
        peer_mgr_event_sender,
        mut cmd_receiver,
        mut peer_mgr_notification_receiver,
    ) = make_standalone_peer_manager(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        vec![bind_addr],
        time_getter.get_time_getter(),
    );

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    let peer_addr = TestAddressMaker::new_random_address(&mut rng).into();
    let peer_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        peer_addr,
        bind_addr,
        &chain_config,
    );

    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id });

    // Increase the score by 1/2 of the threshold, check that the peer is not discouraged.
    adjust_peer_score(
        &peer_mgr_event_sender,
        peer_id,
        *ban_config.discouragement_threshold / 2,
    )
    .await;

    let is_discouraged = query_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db().is_address_discouraged(&peer_addr.as_bannable())
    })
    .await;
    assert!(!is_discouraged);

    expect_no_recv!(cmd_receiver);

    // Increase the score by 1/2 of the threshold again, check that the peer is discouraged now.
    adjust_peer_score(
        &peer_mgr_event_sender,
        peer_id,
        *ban_config.discouragement_threshold / 2,
    )
    .await;

    let is_discouraged = query_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db().is_address_discouraged(&peer_addr.as_bannable())
    })
    .await;
    assert!(is_discouraged);

    // The discouraged peer should be disconnected.
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Disconnect {
            peer_id,
            reason: Some(crate::disconnection_reason::DisconnectionReason::AddressDiscouraged)
        }
    );

    wait_for_no_recv(&mut peer_mgr_notification_receiver).await;

    // Wait for discouragement duration to pass; check that the peer is no longer discouraged.
    time_getter.advance_time(*ban_config.discouragement_duration);

    wait_for_heartbeat(&mut peer_mgr_notification_receiver).await;

    let is_discouraged = query_peer_manager(&peer_mgr_event_sender, move |peer_mgr| {
        peer_mgr.peer_db().is_address_discouraged(&peer_addr.as_bannable())
    })
    .await;
    assert!(!is_discouraged);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check that an incoming connection from a discouraged peer is NOT rejected if
// max_inbound_connections is not reached yet.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn dont_reject_incoming_connection_from_discouraged_peer_if_limit_not_reached(
    #[case] seed: Seed,
) {
    use p2p_types::socket_address::SocketAddress;

    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config_with_peer_mgr_config(PeerManagerConfig {
        max_inbound_connections: 1.into(),

        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
        peerdb_config: Default::default(),
    }));

    let time_getter = BasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address().into();

    let (mut peer_mgr, conn_event_sender, peer_mgr_event_sender, mut cmd_receiver, _) =
        make_standalone_peer_manager(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            vec![bind_addr],
            time_getter.get_time_getter(),
        );

    let peer_addr: SocketAddress = TestAddressMaker::new_random_address(&mut rng).into();

    peer_mgr.discourage(peer_addr.as_bannable());

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    // Connection from the discouraged peer is accepted.
    let peer_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        peer_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id });

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check that an incoming connection from a discouraged peer is rejected if max_inbound_connections
// is already reached, even if there are peers eligible for eviction.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn reject_incoming_connection_from_discouraged_peer_if_limit_reached(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config_with_peer_mgr_config(PeerManagerConfig {
        max_inbound_connections: 1.into(),

        // Allow evicting any inbound peer.
        preserved_inbound_count_address_group: 0.into(),
        preserved_inbound_count_ping: 0.into(),
        preserved_inbound_count_new_blocks: 0.into(),
        preserved_inbound_count_new_transactions: 0.into(),

        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
        peerdb_config: Default::default(),
    }));

    let time_getter = BasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address().into();

    let (mut peer_mgr, conn_event_sender, peer_mgr_event_sender, mut cmd_receiver, _) =
        make_standalone_peer_manager(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            vec![bind_addr],
            time_getter.get_time_getter(),
        );

    let peer_addrs = make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups(
        &peer_mgr.peerdb,
        3,
        &mut rng,
    );
    let [discouraged_addr, normal_addr1, normal_addr2]: [_; 3] = peer_addrs.try_into().unwrap();

    peer_mgr.discourage(discouraged_addr.as_bannable());

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    // Connection from a normal peer is accepted.
    let normal_peer1_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        normal_addr1,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: normal_peer1_id
        }
    );

    // Connection from the discouraged peer is rejected, because the limit is reached.
    let discouraged_peer_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        discouraged_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Disconnect {
            peer_id: discouraged_peer_id,
            reason: Some(DisconnectionReason::TooManyInboundPeersAndThisOneIsDiscouraged)
        }
    );

    // The previous normal peer gets evicted and the connection from another normal one is accepted.
    let normal_peer2_id = inbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        normal_addr2,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Disconnect {
            peer_id: normal_peer1_id,
            reason: Some(DisconnectionReason::PeerEvicted)
        }
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::Accept {
            peer_id: normal_peer2_id
        }
    );

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check that outgoing connections to discouraged peers are not established.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn no_outgoing_connection_to_discouraged_peer(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config_with_peer_mgr_config(PeerManagerConfig {
        outbound_block_relay_count: 2.into(),
        outbound_block_relay_extra_count: 0.into(),
        outbound_full_relay_count: 0.into(),
        outbound_full_relay_extra_count: 0.into(),

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
        peerdb_config: Default::default(),
    }));

    let time_getter = BasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address().into();

    let (mut peer_mgr, conn_event_sender, peer_mgr_event_sender, mut cmd_receiver, _) =
        make_standalone_peer_manager(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            vec![bind_addr],
            time_getter.get_time_getter(),
        );

    let peer_addrs = make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups(
        &peer_mgr.peerdb,
        2,
        &mut rng,
    );
    let [discouraged_addr, normal_addr]: [_; 2] = peer_addrs.try_into().unwrap();

    peer_mgr.peerdb.peer_discovered(discouraged_addr);
    peer_mgr.peerdb.peer_discovered(normal_addr);

    peer_mgr.discourage(discouraged_addr.as_bannable());

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    // Connection to the normal peer is established.
    let cmd = expect_recv!(cmd_receiver);
    expect_cmd_connect_to(&cmd, &normal_addr);
    let peer_id = outbound_block_relay_peer_accepted_by_backend(
        &conn_event_sender,
        normal_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id });

    // No other connection attempts are made.
    expect_no_recv!(cmd_receiver);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check that address announcements don't include discouraged addresses.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn discouraged_address_is_not_announced(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        allow_discover_private_ips: true.into(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    });

    let time_getter = BasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address().into();

    let (mut peer_mgr, conn_event_sender, peer_mgr_event_sender, mut cmd_receiver, _) =
        make_standalone_peer_manager(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            vec![bind_addr],
            time_getter.get_time_getter(),
        );

    let addrs = make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups(
        &peer_mgr.peerdb,
        4,
        &mut rng,
    );
    let [discouraged_addr, normal_addr, peer1_addr, peer2_addr]: [_; 4] = addrs.try_into().unwrap();

    peer_mgr.discourage(discouraged_addr.as_bannable());

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    let peer1_id = inbound_full_relay_peer_accepted_by_backend(
        &conn_event_sender,
        peer1_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id: peer1_id });

    let peer2_id = inbound_full_relay_peer_accepted_by_backend(
        &conn_event_sender,
        peer2_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id: peer2_id });

    conn_event_sender
        .send(ConnectivityEvent::Message {
            peer_id: peer1_id,
            message: PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                address: discouraged_addr.as_peer_address(),
            }),
        })
        .unwrap();

    // Prevent the address limiter from kicking in.
    time_getter.advance_time(Duration::from_secs((1.0 / MAX_ADDR_RATE_PER_SECOND) as u64));

    conn_event_sender
        .send(ConnectivityEvent::Message {
            peer_id: peer1_id,
            message: PeerManagerMessage::AnnounceAddrRequest(AnnounceAddrRequest {
                address: normal_addr.as_peer_address(),
            }),
        })
        .unwrap();

    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::SendMessage {
            peer_id: peer2_id,
            message: Message::AnnounceAddrRequest(AnnounceAddrRequest {
                address: normal_addr.as_peer_address(),
            })
        }
    );

    // No other announcements are made.
    expect_no_recv!(cmd_receiver);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}

// Check that address responses don't include discouraged addresses.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn discouraged_address_not_in_addr_response(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        allow_discover_private_ips: true.into(),
        // The test will start with a good address in the peer db; prevent the peer manager
        // from trying to establish a connection to it automatically.
        peer_manager_config: test_peer_mgr_config_with_no_auto_outbound_connections(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
    });

    let time_getter = BasicTestTimeGetter::new();
    let bind_addr = TestTransportTcp::make_address().into();

    let (mut peer_mgr, conn_event_sender, peer_mgr_event_sender, mut cmd_receiver, _) =
        make_standalone_peer_manager(
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            vec![bind_addr],
            time_getter.get_time_getter(),
        );

    let addrs = make_non_colliding_addresses_for_peer_db_in_distinct_addr_groups(
        &peer_mgr.peerdb,
        3,
        &mut rng,
    );
    let [discouraged_addr, normal_addr, peer_addr]: [_; 3] = addrs.try_into().unwrap();

    peer_mgr.peerdb.peer_discovered(discouraged_addr);
    peer_mgr.peerdb.peer_discovered(normal_addr);

    peer_mgr.discourage(discouraged_addr.as_bannable());

    let peer_mgr_join_handle = logging::spawn_in_current_span(async move {
        let mut peer_mgr = peer_mgr;
        let _ = peer_mgr.run_internal(None).await;
        peer_mgr
    });

    let peer_id = inbound_full_relay_peer_accepted_by_backend(
        &conn_event_sender,
        peer_addr,
        bind_addr,
        &chain_config,
    );
    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(cmd, Command::Accept { peer_id });

    conn_event_sender
        .send(ConnectivityEvent::Message {
            peer_id,
            message: PeerManagerMessage::AddrListRequest(AddrListRequest {}),
        })
        .unwrap();

    let cmd = expect_recv!(cmd_receiver);
    assert_eq!(
        cmd,
        Command::SendMessage {
            peer_id,
            message: Message::AddrListResponse(AddrListResponse {
                addresses: vec![normal_addr.as_peer_address()],
            })
        }
    );

    expect_no_recv!(cmd_receiver);

    drop(conn_event_sender);
    drop(peer_mgr_event_sender);

    let _peer_mgr = peer_mgr_join_handle.await.unwrap();
}
