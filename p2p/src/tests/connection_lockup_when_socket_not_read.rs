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

use std::{sync::Arc, time::Duration};

use itertools::Itertools as _;
use rstest::rstest;

use chainstate::{BlockSource, ChainstateConfig, Locator};
use common::{
    chain,
    primitives::{user_agent::mintlayer_core_user_agent, Id, Idable as _},
};
use logging::log;
use networking::{
    test_helpers::{TestTransportChannel, TestTransportMaker},
    transport::{new_message_stream, TransportSocket},
};
use p2p_test_utils::run_with_timeout;
use randomness::Rng;
use serialization::Encode as _;
use test_utils::{
    assert_matches, assert_matches_return_val,
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    config::{BackendTimeoutsConfig, P2pConfig},
    message::{HeaderList, HeaderListRequest},
    net::{
        default_backend::types::{HandshakeMessage, Message, MessageTag, P2pTimestamp},
        types::PeerManagerMessageExtTag,
    },
    sync::test_helpers::make_new_blocks,
    test_helpers::{test_p2p_config, TEST_PROTOCOL_VERSION},
    tests::helpers::{PeerManagerNotification, TestNode},
};

type Transport = <TestTransportChannel as TestTransportMaker>::Transport;

// Original bug description:
//   When two nodes are on diverged chains, the size of the HeaderList messages that they'll send each
//   other after establishing the connection can be pretty large (800Kb for 2k headers) and it may
//   exceed the size of the socket receive buffer. In the original implementation of the Peer task,
//   writing to the socket would block the entire task until the write is finished.
//   In such a situation, both nodes would start writing at the same time, filling each other's
//   receive buffer. Then, on each side, completing the write would require the other side to start
//   reading, but it couldn't do that until it itself finished writing, which wouldn't happen until
//   the first side started reading, but it couldn't start reading while it was writing.
//   As a result, the whole Peer task would get locked up, not being able to do anything, including
//   the processing of Disconnect requests from the peer manager.
// In this test:
// 1) We use channels-based transport with artificially small buffer, so that the HeaderList message
//    sent by the node wouldn't fit.
// 2) The node accepts an incoming connection from a peer, they complete the handshake and send
//    HeaderListRequest messages to each other.
// 3) The node sends its large HeaderList to the peer.
// 4) The peer sends its own HeaderList; the size of this one is chosen such that it's bigger than
//    the reorg limit, so that the peer will become discouraged by the node.
// 5) The peer stops reading from the socket.
// Expected result: the node successfully receives the HeaderList message from the peer, determines
// that the header list is bad (due to reorg limit violation), discourages the peer and disconnects
// it.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_connection_lockup_when_socket_not_read(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        // Note: this is in bytes; this size should be less than the encoded size of `node_headers_count` headers.
        let channel_max_buf_size = 1000;
        let node_headers_count = 100;

        // `other_headers_count` is bigger than `max_depth_for_reorg`, so that the peer would become
        // discouraged by the node.
        let max_depth_for_reorg = 10;
        let other_headers_count = max_depth_for_reorg + 1;

        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(
            chain::config::create_unit_test_config_builder()
                .max_depth_for_reorg(max_depth_for_reorg.into())
                .build(),
        );
        let p2p_config = Arc::new(test_p2p_config());

        log::debug!("Generating blocks");

        let node_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            node_headers_count as usize,
            &mut rng,
        );
        let node_headers = node_blocks.iter().map(|blk| blk.header().clone()).collect_vec();
        let node_headers_encoded_size = node_headers.encoded_size();
        log::debug!(
            "node_headers_encoded_size = {}, channel_max_buf_size = {}",
            node_headers_encoded_size,
            channel_max_buf_size
        );
        assert!(node_headers_encoded_size > channel_max_buf_size);

        let other_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            other_headers_count as usize,
            &mut rng,
        );
        // Sanity check - the headers are different.
        assert_ne!(node_blocks[0].get_id(), other_blocks[0].get_id());
        let other_headers = other_blocks.iter().map(|blk| blk.header().clone()).collect_vec();

        log::debug!("Creating test node");

        let mut test_node = TestNode::<Transport>::start(
            true,
            time_getter.clone(),
            Arc::clone(&chain_config),
            ChainstateConfig::new().with_heavy_checks_enabled(false),
            Arc::clone(&p2p_config),
            TestTransportChannel::make_transport_with_max_buf_size(channel_max_buf_size),
            TestTransportChannel::make_address().into(),
            TEST_PROTOCOL_VERSION.into(),
            None,
            make_seedable_rng(rng.gen()),
        )
        .await;

        log::debug!("Processing blocks");

        test_node
            .chainstate()
            .call_mut(move |cs| {
                for block in node_blocks {
                    cs.process_block(block, BlockSource::Local).unwrap();
                }
            })
            .await
            .unwrap();

        log::debug!("Connecting");

        let transport =
            TestTransportChannel::make_transport_with_max_buf_size(channel_max_buf_size);

        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        msg_writer
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
                handshake_nonce: 0,
            }))
            .await
            .unwrap();

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

        msg_writer
            .send(Message::HeaderListRequest(HeaderListRequest::new(
                Locator::new(vec![Id::random_using(&mut rng)]),
            )))
            .await
            .unwrap();

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::HeaderListRequest(_));

        msg_writer
            .send(Message::HeaderList(HeaderList::new(other_headers)))
            .await
            .unwrap();

        log::debug!("Expecting PeerManagerNotification::Heartbeat");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(peer_mgr_notif, PeerManagerNotification::Heartbeat);

        log::debug!("Expecting PeerManagerNotification::ConnectionAccepted");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(
            peer_mgr_notif,
            PeerManagerNotification::ConnectionAccepted { .. }
        );

        log::debug!("Expecting PeerManagerNotification::FirstSyncMessageReceived");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(
            peer_mgr_notif,
            PeerManagerNotification::MessageReceived {
                message_tag: PeerManagerMessageExtTag::FirstSyncMessageReceived,
                ..
            }
        );

        log::debug!("Expecting PeerManagerNotification::BanScoreAdjustment");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(
            peer_mgr_notif,
            PeerManagerNotification::BanScoreAdjustment { new_score, .. } if new_score == 100
        );

        log::debug!("Expecting PeerManagerNotification::Discourage");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(peer_mgr_notif, PeerManagerNotification::Discourage { .. });

        log::debug!("Expecting PeerManagerNotification::ConnectionClosed");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(
            peer_mgr_notif,
            PeerManagerNotification::ConnectionClosed { .. }
        );

        test_node.join().await;
    })
    .await;
}

#[derive(Debug)]
enum TimeoutTestType {
    SocketWrite,
    Disconnect,
}

// Here the peer also stops reading from the socket, but doesn't do any discourageable actions.
// Two cases exist:
// 1) Socket write timeout is small, disconnection timeout is artificially large (just in case).
//    The expected result is that the connection should be terminated, though not immediately.
//    I.e. this checks that there is a timeout on socket write attempts.
// 2) Disconnection timeout is small, socket write timeout is artificially large.
//    We wait until the HeaderList message has been sent by the node and then initiate manual
//    disconnection. The expected result is the same - the connection should be terminated,
//    but not immediately.
//    I.e. this checks that there is a timeout on disconnection attempts.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeout_when_socket_not_read(
    #[case] seed: Seed,
    #[values(TimeoutTestType::SocketWrite, TimeoutTestType::Disconnect)] test_type: TimeoutTestType,
) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        // Note: this is in bytes; this size should be less than the encoded size of `node_headers_count` headers.
        let channel_max_buf_size = 1000;
        let node_headers_count = 100;

        let timeout = Duration::from_secs(3);
        let large_timeout = Duration::from_secs(3600);
        let no_disconnection_after = Duration::from_secs(1);

        let (socket_write_timeout, disconnection_timeout) = match test_type {
            TimeoutTestType::SocketWrite => (timeout, large_timeout),
            TimeoutTestType::Disconnect => (large_timeout, timeout),
        };

        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(chain::config::create_unit_test_config());
        let p2p_config = Arc::new(P2pConfig {
            backend_timeouts: BackendTimeoutsConfig {
                socket_write_timeout: socket_write_timeout.into(),
                disconnection_timeout: disconnection_timeout.into(),

                outbound_connection_timeout: Default::default(),
                peer_handshake_timeout: Default::default(),
            },

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        log::debug!("Generating blocks");

        let node_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            node_headers_count as usize,
            &mut rng,
        );
        let node_headers = node_blocks.iter().map(|blk| blk.header().clone()).collect_vec();
        let node_headers_encoded_size = node_headers.encoded_size();
        log::debug!(
            "node_headers_encoded_size = {}, channel_max_buf_size = {}",
            node_headers_encoded_size,
            channel_max_buf_size
        );
        assert!(node_headers_encoded_size > channel_max_buf_size);

        log::debug!("Creating test node");

        let mut test_node = TestNode::<Transport>::start(
            true,
            time_getter.clone(),
            Arc::clone(&chain_config),
            ChainstateConfig::new().with_heavy_checks_enabled(false),
            Arc::clone(&p2p_config),
            TestTransportChannel::make_transport_with_max_buf_size(channel_max_buf_size),
            TestTransportChannel::make_address().into(),
            TEST_PROTOCOL_VERSION.into(),
            None,
            make_seedable_rng(rng.gen()),
        )
        .await;

        log::debug!("Processing blocks");

        test_node
            .chainstate()
            .call_mut(move |cs| {
                for block in node_blocks {
                    cs.process_block(block, BlockSource::Local).unwrap();
                }
            })
            .await
            .unwrap();

        log::debug!("Connecting");

        let transport =
            TestTransportChannel::make_transport_with_max_buf_size(channel_max_buf_size);

        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        msg_writer
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
                handshake_nonce: 0,
            }))
            .await
            .unwrap();

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

        msg_writer
            .send(Message::HeaderListRequest(HeaderListRequest::new(
                Locator::new(vec![Id::random_using(&mut rng)]),
            )))
            .await
            .unwrap();

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::HeaderListRequest(_));

        msg_writer.send(Message::HeaderList(HeaderList::new(Vec::new()))).await.unwrap();

        log::debug!("Expecting PeerManagerNotification::Heartbeat");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(peer_mgr_notif, PeerManagerNotification::Heartbeat);

        log::debug!("Expecting PeerManagerNotification::ConnectionAccepted");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        let peer_id = assert_matches_return_val!(
            peer_mgr_notif,
            PeerManagerNotification::ConnectionAccepted { peer_id, .. },
            peer_id
        );

        log::debug!("Expecting PeerManagerNotification::FirstSyncMessageReceived");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(
            peer_mgr_notif,
            PeerManagerNotification::MessageReceived {
                message_tag: PeerManagerMessageExtTag::FirstSyncMessageReceived,
                ..
            }
        );

        let manual_disconnect_result_receiver = match test_type {
            TimeoutTestType::SocketWrite => None,
            TimeoutTestType::Disconnect => {
                test_node
                    .wait_for_next_backend_socket_write(peer_id, MessageTag::HeaderList)
                    .await;
                Some(test_node.start_disconnecting(peer_id))
            }
        };

        // Wait for a short period of time, there should be no disconnection.
        tokio::time::timeout(
            no_disconnection_after,
            test_node.peer_mgr_notification_receiver().recv(),
        )
        .await
        .unwrap_err();

        // But eventually the disconnection should happen when the socket write timeout expires.
        log::debug!("Expecting PeerManagerNotification::ConnectionClosed");
        let peer_mgr_notif = test_node.peer_mgr_notification_receiver().recv().await.unwrap();
        assert_matches!(
            peer_mgr_notif,
            PeerManagerNotification::ConnectionClosed { .. }
        );

        if let Some(manual_disconnect_result_receiver) = manual_disconnect_result_receiver {
            manual_disconnect_result_receiver.await.unwrap().unwrap();
        }

        test_node.join().await;
    })
    .await;
}
