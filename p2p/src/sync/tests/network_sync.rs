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

use std::{sync::Arc, time::Duration};

use chainstate::ChainstateConfig;
use chainstate_test_framework::TestFramework;
use common::{
    chain::block::timestamp::BlockTimestamp,
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use logging::log;
use p2p_types::PeerId;
use randomness::Rng;
use test_utils::{
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    config::P2pConfig,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList},
    protocol::ProtocolConfig,
    sync::tests::helpers::{
        make_new_block, make_new_blocks, make_new_top_blocks,
        test_node_group::{MsgAction, TestNodeGroup},
        TestNode,
    },
    test_helpers::for_each_protocol_version,
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let p2p_config = Arc::new(P2pConfig {
            protocol_config: ProtocolConfig {
                msg_header_count_limit: 10.into(),
                max_request_blocks_count: 5.into(),

                max_addr_list_response_address_count: Default::default(),
                msg_max_locator_count: Default::default(),
                max_message_size: Default::default(),
                max_peer_tx_announcements: Default::default(),
            },

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
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            13,
            &mut rng,
        );
        let top_block_id = blocks.last().unwrap().get_id();

        // Start `node1` with some fresh blocks (timestamp less than 24 hours old) to make `is_initial_block_download` false there
        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks)
            .build()
            .await;
        let chainstate1 = node1.chainstate().clone();

        // A new node is joining the network
        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        nodes.sync_all(&top_block_id.into(), &mut rng).await;

        let top_block_id =
            make_new_top_blocks(&chainstate1, time_getter.get_time_getter(), &mut rng, 0, 1).await;
        nodes.sync_all(&top_block_id.into(), &mut rng).await;

        for _ in 0..15 {
            let mut top_block_id = None;
            for _ in 0..rng.gen_range(1..2) {
                top_block_id = Some(
                    make_new_top_blocks(
                        &chainstate1,
                        time_getter.get_time_getter(),
                        &mut rng,
                        0,
                        1,
                    )
                    .await,
                );
            }
            nodes.sync_all(&top_block_id.unwrap().into(), &mut rng).await;
        }

        nodes.join_subsystem_managers().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_unexpected_disconnects_in_ibd(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        // With the heavy checks enabled, this test takes over a minute to complete in debug builds.
        let chainstate_config = ChainstateConfig::new().with_heavy_checks_enabled(false);
        let time_getter = BasicTestTimeGetter::new();

        let mut blocks = Vec::new();
        for _ in 0..1000 {
            let block = make_new_block(
                &chain_config,
                blocks.last(),
                &time_getter.get_time_getter(),
                &mut rng,
            );
            time_getter.advance_time(Duration::from_secs(600));
            blocks.push(block.clone());
        }
        let top_block_id = blocks.last().unwrap().get_id();

        // Start `node1` with up-to-date blockchain
        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_chainstate_config(chainstate_config.clone())
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks)
            .build()
            .await;

        // A new node is joining the network
        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_chainstate_config(chainstate_config)
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        // Simulate a normal block sync process.
        // There should be no unexpected disconnects.
        while !nodes.all_in_sync(&top_block_id.into()).await {
            nodes.exchange_block_sync_messages(&mut rng).await;
            time_getter.advance_time(Duration::from_millis(10));
        }

        nodes.join_subsystem_managers().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reorg(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let mut blocks = Vec::new();
        for _ in 0..10 {
            let block = make_new_block(
                &chain_config,
                blocks.last(),
                &time_getter.get_time_getter(),
                &mut rng,
            );
            time_getter.advance_time(Duration::from_secs(60));
            blocks.push(block.clone());
        }
        let top_block_id = blocks.last().unwrap().get_id();

        // Start `node1` with up-to-date blockchain
        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks.clone())
            .build()
            .await;
        let chainstate1 = node1.chainstate().clone();

        // Start `node2` with up-to-date blockchain
        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks)
            .build()
            .await;

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        nodes.sync_all(&top_block_id.into(), &mut rng).await;

        // First blockchain reorg
        let top_block_id =
            make_new_top_blocks(&chainstate1, time_getter.get_time_getter(), &mut rng, 1, 2).await;

        nodes.sync_all(&top_block_id.into(), &mut rng).await;

        // Second blockchain reorg
        let top_block_id =
            make_new_top_blocks(&chainstate1, time_getter.get_time_getter(), &mut rng, 1, 2).await;

        nodes.sync_all(&top_block_id.into(), &mut rng).await;

        nodes.join_subsystem_managers().await;
    })
    .await;
}

// A test for incorrect historical behavior, where a node would send disconnected headers
// during block announcement.
// The test scenario:
// 1) A peer has requested the last portion of initially existing blocks from the node.
// 2) The request is delayed.
// 3) The node starts producing new blocks and sending updates to the peer.
// 4) The peer would see all new headers as disconnected (due to peculiarities of the
// old implementation and because of the state that the peer is in, i.e. it has already requested
// blocks for all headers that it knew about).
// Because of this, a variety of situations could happen, depending on the number of blocks
// produced at each stage (which influences delays during message passing):
// a) At a certain point, the number of disconnected headers would reach the maximum amount and
// the peer would produce 'ProtocolError::DisconnectedHeaders'.
// b) The peer, having received a disconnected header, would ignore it send a proper header request.
// After doing that multiple times, it would get multiple header responses, which it may not expect,
// depending on certain conditions, so it would produce 'ProtocolError(UnexpectedMessage("Headers list"))'.
// c) Sometimes, in the case b the peer would actually send multiple block requests in that case
// exceeding the node's requested block limit, so that it would produce ProtocolError(BlocksRequestLimitExceeded).
// All of the above would increase the ban score of the other side.
// Expected result: the ban score should not be increased.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_announcement_disconnected_headers(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        const MAX_REQUEST_BLOCKS_COUNT: usize = 5;

        let p2p_config = Arc::new(P2pConfig {
            protocol_config: ProtocolConfig {
                msg_header_count_limit: (MAX_REQUEST_BLOCKS_COUNT * 2).into(),
                max_request_blocks_count: MAX_REQUEST_BLOCKS_COUNT.into(),

                max_addr_list_response_address_count: Default::default(),
                msg_max_locator_count: Default::default(),
                max_message_size: Default::default(),
                max_peer_tx_announcements: Default::default(),
            },

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
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let initial_block_count = rng.gen_range(1..=MAX_REQUEST_BLOCKS_COUNT);

        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            initial_block_count,
            &mut rng,
        );

        // Start `node1` with some fresh blocks (timestamp less than 24 hours old) to make `is_initial_block_download` false there
        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(initial_blocks)
            .build()
            .await;

        // A new node is joining the network
        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        let chainstate1 = node1.chainstate().clone();

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        let mut delayed_msgs = Vec::new();

        nodes
            .exchange_block_sync_messages_while(&mut delayed_msgs, |_, delayed_msgs, msg| {
                if msg.sender_node_idx == 1 {
                    if let BlockSyncMessage::BlockListRequest(req) = &msg.message {
                        assert_eq!(req.block_ids().len(), initial_block_count);
                        log::debug!(
                            "Got block list request from node idx {}, delaying it",
                            msg.sender_node_idx
                        );
                        delayed_msgs.push(msg.clone());
                        return MsgAction::Break;
                    }
                }

                MsgAction::SendAndContinue
            })
            .await;

        nodes.delay_block_sync_messages_from_node(1, true);

        let new_block_count =
            rng.gen_range(MAX_REQUEST_BLOCKS_COUNT..=MAX_REQUEST_BLOCKS_COUNT * 4);

        log::debug!("Starting to produce new blocks");
        let mut best_block_id = None;
        for _ in 0..new_block_count {
            best_block_id = Some(
                make_new_top_blocks(&chainstate1, time_getter.get_time_getter(), &mut rng, 0, 1)
                    .await,
            );
        }

        log::debug!("Final best block is {}", best_block_id.unwrap());
        nodes.exchange_block_sync_messages(&mut rng).await;

        log::debug!("Sending delayed messages");
        nodes.send_sync_messages(delayed_msgs).await;
        nodes.delay_block_sync_messages_from_node(1, false);

        log::debug!("Waiting until all is synced");
        nodes.sync_all(&best_block_id.unwrap().into(), &mut rng).await;

        log::debug!("Joining subsystem managers");
        nodes.join_subsystem_managers().await;
    })
    .await;
}

// 1) A peer sends a block with too big a timestamp; the block is rejected, the peer is discouraged.
// 2) Time passes, so that the previously invalid block is now valid.
// 3) Another peer sends the same block; the block must be accepted this time.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_block_from_the_future_again(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let time_getter = BasicTestTimeGetter::new();
        let start_time = time_getter.get_time_getter().get_time();

        let p2p_config = Arc::new(P2pConfig {
            // Minimize the time block sync manager spends in wait_for_clock_diff.
            max_clock_diff: Duration::from_secs(1).into(),
            peer_handshake_timeout: Duration::from_secs(1).into(),

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
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng)
            .with_time_getter(time_getter.get_time_getter())
            .build();

        let normal_block = tf
            .make_block_builder()
            .with_timestamp(BlockTimestamp::from_time(start_time))
            .build(&mut rng);
        let normal_block_id = normal_block.get_id();

        let future_block_delay = Duration::from_secs(60 * 60 * 24);
        let future_block_time = (start_time + future_block_delay).unwrap();
        let future_block = tf
            .make_block_builder()
            .with_parent(normal_block_id.into())
            .with_timestamp(BlockTimestamp::from_time(future_block_time))
            .build(&mut rng);
        let future_block_id = future_block.get_id();

        log::debug!("normal_block_id = {normal_block_id}, future_block_id = {future_block_id}");

        let mut node = TestNode::builder(protocol_version)
            .with_p2p_config(p2p_config)
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        let peer1 = node.connect_peer(PeerId::new(), protocol_version).await;

        // Announce both blocks in one HeaderList. This way, only the normal block's header
        // will be checked at this stage.
        peer1
            .send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![
                normal_block.header().clone(),
                future_block.header().clone(),
            ])))
            .await;

        log::debug!("Expecting block list request");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer1.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![
                normal_block_id,
                future_block_id
            ]))
        );

        peer1
            .send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                normal_block.clone(),
            )))
            .await;

        node.assert_no_peer_manager_event().await;

        peer1
            .send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                future_block.clone(),
            )))
            .await;

        log::debug!("Expecting score adjustment");
        let (adjusted_peer_id, ban_score_delta) = node.receive_adjust_peer_score_event().await;
        assert_eq!(adjusted_peer_id, peer1.get_id());
        assert_eq!(ban_score_delta, 100);

        {
            let (
                normal_block_idx_on_the_node,
                normal_block_on_the_node,
                future_block_idx_on_the_node,
                future_block_on_the_node,
            ) = node
                .chainstate()
                .call(move |cs| {
                    (
                        cs.get_block_index_for_any_block(&normal_block_id).unwrap(),
                        cs.get_block(normal_block_id).unwrap(),
                        cs.get_block_index_for_any_block(&future_block_id).unwrap(),
                        cs.get_block(future_block_id).unwrap(),
                    )
                })
                .await
                .unwrap();
            assert!(normal_block_idx_on_the_node.is_some());
            assert!(normal_block_on_the_node.is_some());
            // Note: both the index and the block itself are missing.
            assert!(future_block_idx_on_the_node.is_none());
            assert!(future_block_on_the_node.is_none());
        }

        time_getter.advance_time(future_block_delay);

        let peer2 = node.connect_peer(PeerId::new(), protocol_version).await;

        peer2
            .send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![
                future_block.header().clone(),
            ])))
            .await;

        log::debug!("Expecting block list request");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer2.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![future_block_id]))
        );

        peer2
            .send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                future_block.clone(),
            )))
            .await;

        node.assert_no_peer_manager_event().await;

        {
            let (future_block_idx_on_the_node, future_block_on_the_node) = node
                .chainstate()
                .call(move |cs| {
                    (
                        cs.get_block_index_for_persisted_block(&future_block_id).unwrap(),
                        cs.get_block(future_block_id).unwrap(),
                    )
                })
                .await
                .unwrap();
            // Both the index and the block are present now.
            assert!(future_block_idx_on_the_node.is_some());
            assert!(future_block_on_the_node.is_some());
        }

        node.join_subsystem_manager().await;
    })
    .await;
}
