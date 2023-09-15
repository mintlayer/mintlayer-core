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

use common::primitives::{user_agent::mintlayer_core_user_agent, Idable};
use crypto::random::Rng;
use logging::log;
use p2p_test_utils::P2pBasicTestTimeGetter;
use test_utils::random::Seed;

use crate::{
    config::P2pConfig,
    message::SyncMessage,
    sync::tests::helpers::{
        make_new_block, make_new_blocks, make_new_top_blocks,
        test_node_group::{MsgAction, TestNodeGroup},
        TestNode,
    },
    testing_utils::for_each_protocol_version,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = P2pBasicTestTimeGetter::new();

        let p2p_config = Arc::new(P2pConfig {
            msg_header_count_limit: 10.into(),
            max_request_blocks_count: 5.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            max_inbound_connections: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            msg_max_locator_count: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
            max_singular_unconnected_headers: Default::default(),
            sync_stalling_timeout: Default::default(),
            enable_block_relay_peers: Default::default(),
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

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_download_unexpected_disconnect(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = P2pBasicTestTimeGetter::new();

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
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks)
            .build()
            .await;

        // A new node is joining the network
        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        // Simulate a normal block sync process.
        // There should be no unexpected disconnects.
        while !nodes.all_in_sync(&top_block_id.into()).await {
            nodes.exchange_sync_messages(&mut rng).await;
            time_getter.advance_time(Duration::from_millis(10));
        }

        nodes.join_subsystem_managers().await;
    })
    .await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reorg(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = P2pBasicTestTimeGetter::new();

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
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_announcement_disconnected_headers(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = P2pBasicTestTimeGetter::new();

        const MAX_REQUEST_BLOCKS_COUNT: usize = 5;

        let p2p_config = Arc::new(P2pConfig {
            msg_header_count_limit: (MAX_REQUEST_BLOCKS_COUNT * 2).into(),
            max_request_blocks_count: MAX_REQUEST_BLOCKS_COUNT.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            max_inbound_connections: Default::default(),
            ban_threshold: Default::default(),
            ban_duration: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            msg_max_locator_count: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
            max_singular_unconnected_headers: Default::default(),
            sync_stalling_timeout: Default::default(),
            enable_block_relay_peers: Default::default(),
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
            .exchange_sync_messages_while(&mut delayed_msgs, |_, delayed_msgs, msg| {
                if msg.sender_node_idx == 1 {
                    if let SyncMessage::BlockListRequest(req) = &msg.message {
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

        nodes.delay_sync_messages_from_node(1, true);

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
        nodes.exchange_sync_messages(&mut rng).await;

        log::debug!("Sending delayed messages");
        nodes.send_sync_messages(delayed_msgs).await;
        nodes.delay_sync_messages_from_node(1, false);

        log::debug!("Waiting until all is synced");
        nodes.sync_all(&best_block_id.unwrap().into(), &mut rng).await;

        log::debug!("Joining subsystem managers");
        nodes.join_subsystem_managers().await;
    })
    .await;
}
