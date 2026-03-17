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

use std::sync::Arc;

use itertools::Itertools as _;
use rstest::rstest;

use chainstate::ChainstateConfig;
use common::primitives::{
    semver::SemVer,
    user_agent::{mintlayer_core_user_agent, UserAgent},
};
use networking::{
    test_helpers::{TestTransportChannel, TestTransportMaker},
    transport::{new_message_stream, ConnectedSocketInfo as _, TransportListener, TransportSocket},
};
use p2p_test_utils::run_with_timeout;
use p2p_types::socket_address::SocketAddress;
use randomness::Rng as _;
use test_utils::{
    assert_matches,
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    config::P2pConfig,
    net::default_backend::types::{HandshakeMessage, Message, P2pTimestamp},
    peer_manager::{self, config::PeerManagerConfig, PeerManagerInterface},
    test_helpers::TEST_PROTOCOL_VERSION,
    tests::helpers::TestNode,
};

type Transport = <TestTransportChannel as TestTransportMaker>::Transport;

#[derive(Debug)]
struct TestParams {
    min_version: Option<SemVer>,
    peer_version: SemVer,
    peer_user_agent: UserAgent,
    node_user_agent: UserAgent,
    accept: bool,
}

#[rstest_reuse::template]
fn test_params_list(
    #[values(
        // No min version => the connection should be accepted no matter what.
        TestParams {
            min_version: None,
            peer_version: "0.0.0".parse().unwrap(),
            peer_user_agent: mintlayer_core_user_agent(),
            node_user_agent: mintlayer_core_user_agent(),
            accept: true
        },
        // If user agents differ, the min version doesn't matter.
        TestParams {
            min_version: Some("1.1.1".parse().unwrap()),
            peer_version: "0.0.0".parse().unwrap(),
            peer_user_agent: "Agent1".try_into().unwrap(),
            node_user_agent: "Agent2".try_into().unwrap(),
            accept: true
        },
        // Same agent, same version => accept
        TestParams {
            min_version: Some("12.34.56".parse().unwrap()),
            peer_version: "12.34.56".parse().unwrap(),
            peer_user_agent: "SameAgent".try_into().unwrap(),
            node_user_agent: "SameAgent".try_into().unwrap(),
            accept: true
        },
        // Same agent, bigger peer version => accept
        TestParams {
            min_version: Some("12.34.56".parse().unwrap()),
            peer_version: "12.34.57".parse().unwrap(),
            peer_user_agent: "SameAgent".try_into().unwrap(),
            node_user_agent: "SameAgent".try_into().unwrap(),
            accept: true
        },
        // Same agent, smaller peer version => reject
        TestParams {
            min_version: Some("12.34.56".parse().unwrap()),
            peer_version: "12.34.55".parse().unwrap(),
            peer_user_agent: "SameAgent".try_into().unwrap(),
            node_user_agent: "SameAgent".try_into().unwrap(),
            accept: false
        },
    )]
    test_params: TestParams,
) {
}

fn make_p2p_config(test_params: &TestParams) -> P2pConfig {
    let peer_manager_config = PeerManagerConfig {
        min_peer_software_version: test_params.min_version,

        max_inbound_connections: Default::default(),
        preserved_inbound_count_address_group: Default::default(),
        preserved_inbound_count_ping: Default::default(),
        preserved_inbound_count_new_blocks: Default::default(),
        preserved_inbound_count_new_transactions: Default::default(),
        outbound_full_relay_count: Default::default(),
        outbound_full_relay_extra_count: Default::default(),
        outbound_block_relay_count: Default::default(),
        outbound_block_relay_extra_count: Default::default(),
        outbound_block_relay_connection_min_age: Default::default(),
        outbound_full_relay_connection_min_age: Default::default(),
        stale_tip_time_diff: Default::default(),
        main_loop_tick_interval: Default::default(),
        enable_feeler_connections: Default::default(),
        feeler_connections_interval: Default::default(),
        force_dns_query_if_no_global_addresses_known: Default::default(),
        allow_same_ip_connections: Default::default(),
        peerdb_config: Default::default(),
    };

    P2pConfig {
        peer_manager_config,
        user_agent: test_params.node_user_agent.clone(),

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
        allow_discover_private_ips: Default::default(),
        sync_stalling_timeout: Default::default(),
        protocol_config: Default::default(),
        custom_disconnection_reason_for_banning: Default::default(),
    }
}

#[tracing::instrument(skip(seed))]
#[rstest_reuse::apply(test_params_list)]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_manual_connection(#[case] seed: Seed, test_params: TestParams) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let p2p_config = Arc::new(make_p2p_config(&test_params));

        let mut test_node = TestNode::<Transport>::start(
            true,
            time_getter.clone(),
            Arc::clone(&chain_config),
            ChainstateConfig::new(),
            Arc::clone(&p2p_config),
            TestTransportChannel::make_transport(),
            TestTransportChannel::make_address().into(),
            TEST_PROTOCOL_VERSION.into(),
            None,
            make_seedable_rng(rng.gen()),
        )
        .await;

        let transport = TestTransportChannel::make_transport();
        let mut listener =
            transport.bind(vec![TestTransportChannel::make_address()]).await.unwrap();

        let connect_result_receiver =
            test_node.start_connecting(listener.local_addresses().unwrap()[0].into());

        let (stream, _) = listener.accept().await.unwrap();

        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

        msg_writer
            .send(Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                network: *chain_config.magic_bytes(),
                user_agent: test_params.peer_user_agent,
                software_version: test_params.peer_version,
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
            }))
            .await
            .unwrap();

        // Note: since it's a manual outbound connection, the peer should not be discouraged even
        // if the connection has been rejected.

        let test_node_remnants = if test_params.accept {
            let connect_result = connect_result_receiver.await.unwrap();
            assert!(connect_result.is_ok());

            // Check that the connection is still up and we can receive the next message.
            let msg = msg_reader.recv().await.unwrap();
            assert_matches!(msg, Message::AddrListRequest(_));

            // This is mainly needed to ensure that the corresponding events, if any, reach
            // peer manager before we end the test.
            test_node.expect_no_punishment().await;

            let test_node_remnants = test_node.join().await;

            // PeerContext still exists and has zero score.
            assert_eq!(test_node_remnants.peer_mgr.peers().len(), 1);
            let peer_score = test_node_remnants.peer_mgr.peers().first_key_value().unwrap().1.score;
            assert_eq!(peer_score, 0);

            test_node_remnants
        } else {
            // connect_result should indicate a failed connection
            let connect_result = connect_result_receiver.await.unwrap();
            assert!(connect_result.is_err());

            // The node should have sent WillDisconnect.
            let msg = msg_reader.recv().await.unwrap();
            assert_matches!(msg, Message::WillDisconnect(_));

            // Then the connection should have been closed.
            msg_reader.recv().await.unwrap_err();

            // This is mainly needed to ensure that the corresponding events, if any, reach
            // peer manager before we end the test.
            test_node.expect_no_punishment().await;

            let test_node_remnants = test_node.join().await;

            // No PeerContext, since the connection has been closed.
            assert_eq!(test_node_remnants.peer_mgr.peers().len(), 0);

            test_node_remnants
        };

        // No discouragements in the peer db.
        let discouragements_count = test_node_remnants.peer_mgr.peerdb().list_discouraged().count();
        assert_eq!(discouragements_count, 0);

        // Just in case, also check that the peer hasn't been banned.
        let bans_count = test_node_remnants.peer_mgr.peerdb().list_banned().count();
        assert_eq!(bans_count, 0);
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest_reuse::apply(test_params_list)]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_auto_connection(#[case] seed: Seed, test_params: TestParams) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let p2p_config = Arc::new(make_p2p_config(&test_params));

        let mut test_node = TestNode::<Transport>::start(
            true,
            time_getter.clone(),
            Arc::clone(&chain_config),
            ChainstateConfig::new(),
            Arc::clone(&p2p_config),
            TestTransportChannel::make_transport(),
            TestTransportChannel::make_address().into(),
            TEST_PROTOCOL_VERSION.into(),
            None,
            make_seedable_rng(rng.gen()),
        )
        .await;

        let transport = TestTransportChannel::make_transport();
        let mut listener =
            transport.bind(vec![TestTransportChannel::make_address()]).await.unwrap();

        let peer_address = listener.local_addresses().unwrap()[0].into();
        test_node.discover_peer(peer_address).await;
        // Advance time to allow a heartbeat to happen, where the new connection will be attempted.
        time_getter.advance_time(peer_manager::HEARTBEAT_INTERVAL_MAX);

        let (stream, _) = listener.accept().await.unwrap();

        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

        msg_writer
            .send(Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                network: *chain_config.magic_bytes(),
                user_agent: test_params.peer_user_agent,
                software_version: test_params.peer_version,
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
            }))
            .await
            .unwrap();

        let test_node_remnants = if test_params.accept {
            // Check that the connection is still up and we can receive the next message.
            let msg = msg_reader.recv().await.unwrap();
            assert_matches!(msg, Message::AddrListRequest(_));

            // This is mainly needed to ensure that the corresponding events, if any, reach
            // peer manager before we end the test.
            test_node.expect_no_punishment().await;

            let test_node_remnants = test_node.join().await;

            // No discouragements in the peer db.
            let discouragements_count =
                test_node_remnants.peer_mgr.peerdb().list_discouraged().count();
            assert_eq!(discouragements_count, 0);

            // PeerContext still exists and has zero score.
            assert_eq!(test_node_remnants.peer_mgr.peers().len(), 1);
            let peer_score = test_node_remnants.peer_mgr.peers().first_key_value().unwrap().1.score;
            assert_eq!(peer_score, 0);

            test_node_remnants
        } else {
            // The node should have sent WillDisconnect.

            let msg = msg_reader.recv().await.unwrap();
            assert_matches!(msg, Message::WillDisconnect(_));

            // Then the connection should have been closed.
            msg_reader.recv().await.unwrap_err();

            // Unlike in the outbound manual connection case, here the peer score should be adjusted
            // and the peer discouraged.

            // Note: not using wait_for_ban_score_adjustment, because the score adjustment is
            // initiated in the peer manager directly in this case, so it should happen immediately.

            let test_node_remnants = test_node.join().await;

            // The peer address should be discouraged.
            let discouraged_addrs = test_node_remnants
                .peer_mgr
                .peerdb()
                .list_discouraged()
                .map(|(addr, _)| addr)
                .collect_vec();
            assert_eq!(&discouraged_addrs, &[peer_address.as_bannable()]);

            // No PeerContext, since the connection has been closed.
            assert_eq!(test_node_remnants.peer_mgr.peers().len(), 0);

            test_node_remnants
        };

        // Just in case, check that the peer hasn't been banned.
        let bans_count = test_node_remnants.peer_mgr.peerdb().list_banned().count();
        assert_eq!(bans_count, 0);
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest_reuse::apply(test_params_list)]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_connection(#[case] seed: Seed, test_params: TestParams) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let p2p_config = Arc::new(make_p2p_config(&test_params));

        let mut test_node = TestNode::<Transport>::start(
            true,
            time_getter.clone(),
            Arc::clone(&chain_config),
            ChainstateConfig::new(),
            Arc::clone(&p2p_config),
            TestTransportChannel::make_transport(),
            TestTransportChannel::make_address().into(),
            TEST_PROTOCOL_VERSION.into(),
            None,
            make_seedable_rng(rng.gen()),
        )
        .await;

        let transport = TestTransportChannel::make_transport();

        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let peer_address = SocketAddress::new(stream.local_address().unwrap());

        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        msg_writer
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                network: *chain_config.magic_bytes(),
                user_agent: test_params.peer_user_agent,
                software_version: test_params.peer_version,
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
                handshake_nonce: 0,
            }))
            .await
            .unwrap();

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

        let test_node_remnants = if test_params.accept {
            // Check that the connection is still up and we can receive the next message.
            let msg = msg_reader.recv().await.unwrap();
            assert_matches!(msg, Message::HeaderListRequest(_));

            // This is mainly needed to ensure that the corresponding events, if any, reach
            // peer manager before we end the test.
            test_node.expect_no_punishment().await;

            let test_node_remnants = test_node.join().await;

            // No discouragements in the peer db.
            let discouragements_count =
                test_node_remnants.peer_mgr.peerdb().list_discouraged().count();
            assert_eq!(discouragements_count, 0);

            // PeerContext still exists and has zero score.
            assert_eq!(test_node_remnants.peer_mgr.peers().len(), 1);
            let peer_score = test_node_remnants.peer_mgr.peers().first_key_value().unwrap().1.score;
            assert_eq!(peer_score, 0);

            test_node_remnants
        } else {
            // The node should have sent WillDisconnect.
            let msg = msg_reader.recv().await.unwrap();
            assert_matches!(msg, Message::WillDisconnect(_));

            // Then the connection should have been closed.
            msg_reader.recv().await.unwrap_err();

            // Note: not using wait_for_ban_score_adjustment, because the score adjustment is
            // initiated in the peer manager directly in this case, so it should happen immediately.

            let test_node_remnants = test_node.join().await;

            // The peer address should be discouraged.
            let discouraged_addrs = test_node_remnants
                .peer_mgr
                .peerdb()
                .list_discouraged()
                .map(|(addr, _)| addr)
                .collect_vec();
            assert_eq!(&discouraged_addrs, &[peer_address.as_bannable()]);

            // No PeerContext, since the connection has been closed.
            assert_eq!(test_node_remnants.peer_mgr.peers().len(), 0);

            test_node_remnants
        };

        // Just in case, check that the peer hasn't been banned.
        let bans_count = test_node_remnants.peer_mgr.peerdb().list_banned().count();
        assert_eq!(bans_count, 0);
    })
    .await;
}
