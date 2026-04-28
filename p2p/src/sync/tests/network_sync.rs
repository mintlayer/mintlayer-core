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

use itertools::Itertools;

use chainstate::{BlockSource, ChainstateConfig, ChainstateHandle, Locator};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{self, block::timestamp::BlockTimestamp},
    primitives::{BlockDistance, Idable, user_agent::mintlayer_core_user_agent},
};
use logging::log;
use p2p_test_utils::{MEDIUM_TIMEOUT, create_n_blocks, run_with_timeout};
use p2p_types::PeerId;
use randomness::RngExt;
use test_utils::{
    BasicTestTimeGetter,
    mock_time_getter::mocked_time_getter_seconds,
    random::{Seed, make_seedable_rng},
};
use utils::atomics::SeqCstAtomicU64;

use crate::{
    PeerManagerEvent,
    config::{BackendTimeoutsConfig, P2pConfig},
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest},
    protocol::ProtocolConfig,
    sync::tests::helpers::{
        TestNode, make_new_block, make_new_blocks, make_new_top_blocks,
        test_node_group::{
            BlockSyncMessageWithNodeIdx, MsgAction, PeerManagerEventWithNodeIdx, TestNodeGroup,
        },
    },
    test_helpers::{for_each_protocol_version, test_p2p_config_with_protocol_config},
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
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
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            backend_timeouts: Default::default(),
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
            for _ in 0..rng.random_range(1..2) {
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
        let mut rng = make_seedable_rng(seed);
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
        let mut rng = make_seedable_rng(seed);
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
        let mut rng = make_seedable_rng(seed);
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
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            backend_timeouts: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let initial_block_count = rng.random_range(1..=MAX_REQUEST_BLOCKS_COUNT);

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
            .exchange_block_sync_messages_while(&mut delayed_msgs, async |_, delayed_msgs, msg| {
                if msg.sender_node_idx == 1
                    && let BlockSyncMessage::BlockListRequest(req) = &msg.message
                {
                    assert_eq!(req.block_ids().len(), initial_block_count);
                    log::debug!(
                        "Got block list request from node idx {}, delaying it",
                        msg.sender_node_idx
                    );
                    delayed_msgs.push(msg.clone());
                    return MsgAction::Break;
                }

                MsgAction::SendAndContinue
            })
            .await;

        nodes.delay_block_sync_messages_from_node(1, true);

        let new_block_count =
            rng.random_range(MAX_REQUEST_BLOCKS_COUNT..=MAX_REQUEST_BLOCKS_COUNT * 4);

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
            backend_timeouts: BackendTimeoutsConfig {
                peer_handshake_timeout: Duration::from_secs(1).into(),
                outbound_connection_timeout: Default::default(),
                disconnection_timeout: Default::default(),
                socket_write_timeout: Default::default(),
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
                        cs.get_block(&normal_block_id).unwrap(),
                        cs.get_block_index_for_any_block(&future_block_id).unwrap(),
                        cs.get_block(&future_block_id).unwrap(),
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
                        cs.get_block(&future_block_id).unwrap(),
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

// Simulate a situation where when `PeerBlockSyncManager` is handling a block, the same block
// gets added to the chainstate via other means.
// Generate a large number of blocks (a few hundred) and then for each block:
// 1) the peer sends HeaderList with 1 header;
// 2) the node responds with BlockListRequest for 1 block;
// 3) the peer sends BlockResponse with the requested block; at the same time the block
// is added to the chainstate via an explicit call to `process_block`;
// 4) expected result: the interference has no effect, the node must send a new HeaderListRequest
// as usual.
// Note: a the moment of writing this, this basically ensures that when `PeerBlockSyncManager`
// calls chainstate's `process_block`, it first checks that the block is indeed new; if this is not
// done, `process_block` would fail and the rest of the block processing logic (i.e. requesting
// more headers) would be skipped.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_block_interference1(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        run_with_timeout(async {
            let mut rng = make_seedable_rng(seed);

            let chain_config = Arc::new(chain::config::create_unit_test_config());
            let mut tf = TestFramework::builder(&mut rng)
                .with_chain_config(chain_config.as_ref().clone())
                .build();
            let num_blocks = 200;
            let blocks = create_n_blocks(&mut rng, &mut tf, num_blocks);

            let mut node = TestNode::builder(protocol_version)
                .with_chain_config(chain_config)
                .with_chainstate(tf.into_chainstate())
                .build()
                .await;

            let peer = node.connect_peer(PeerId::new(), protocol_version).await;
            let peer_id = peer.get_id();
            let peer = Arc::new(tokio::sync::Mutex::new(peer));

            for block in blocks {
                let block_id = block.get_id();
                peer.lock()
                    .await
                    .send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![
                        block.header().clone(),
                    ])))
                    .await;

                let (sent_to, message) = node.get_sent_block_sync_message().await;
                assert_eq!(sent_to, peer_id);
                assert_eq!(
                    message,
                    BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![block_id]))
                );

                // Send block response and explicitly call process_block at the same time.
                // Run the 2 futures jointly to increase the likelihood of interference.
                {
                    let node_call = {
                        let block = block.clone();
                        async {
                            peer.lock()
                                .await
                                .send_block_sync_message(BlockSyncMessage::BlockResponse(
                                    BlockResponse::new(block),
                                ))
                                .await;

                            tokio::time::sleep(Duration::from_millis(rng.random_range(1..10)))
                                .await;
                        }
                    };

                    let chainstate_call = async {
                        node.chainstate()
                            .call_mut(move |cs| {
                                if cs
                                    .get_block_index_for_persisted_block(&block_id)
                                    .unwrap()
                                    .is_none()
                                {
                                    cs.process_block(block, BlockSource::Peer).unwrap();
                                } else {
                                    log::debug!("Block already processed by the node");
                                }
                            })
                            .await
                            .unwrap();
                    };

                    tokio::join!(node_call, chainstate_call);
                }

                // The node should request for more headers.
                // This is the place where we expect the failure to occur in a buggy implementation.
                let (sent_to, message) =
                    tokio::time::timeout(MEDIUM_TIMEOUT, node.get_sent_block_sync_message())
                        .await
                        .unwrap();
                assert_eq!(sent_to, peer_id);
                assert!(matches!(
                    message,
                    BlockSyncMessage::HeaderListRequest(HeaderListRequest { .. })
                ));
            }

            node.assert_no_error().await;
            node.join_subsystem_manager().await;
        })
        .await;
    })
    .await;
}

// Same as process_block_interference1, but with slightly different steps.
// Generate a large number of blocks (a few hundred) and then for each pair of blocks:
// 1) the peer sends HeaderList with the 2 headers;
// 2) the node responds with BlockListRequest for 1 block (enforced by `max_request_blocks_count`);
// 3) the peer sends BlockResponse with the requested block; at the same time the block
// is added to the chainstate via an explicit call to `process_block`;
// 4) expected result: the interference has no effect, the node must send a BlockListRequest for
// the 2nd block as usual.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_block_interference2(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        run_with_timeout(async {
            let mut rng = make_seedable_rng(seed);

            let chain_config = Arc::new(chain::config::create_unit_test_config());
            let mut tf = TestFramework::builder(&mut rng)
                .with_chain_config(chain_config.as_ref().clone())
                .build();
            let num_blocks = 200;
            let blocks = create_n_blocks(&mut rng, &mut tf, num_blocks);

            let p2p_config = Arc::new(test_p2p_config_with_protocol_config(ProtocolConfig {
                // Only 1 block in a BlockListRequest is allowed.
                max_request_blocks_count: 1.into(),

                msg_header_count_limit: Default::default(),
                max_addr_list_response_address_count: Default::default(),
                msg_max_locator_count: Default::default(),
                max_message_size: Default::default(),
                max_peer_tx_announcements: Default::default(),
            }));
            let mut node = TestNode::builder(protocol_version)
                .with_chain_config(chain_config)
                .with_chainstate(tf.into_chainstate())
                .with_p2p_config(p2p_config)
                .build()
                .await;

            let peer = node.connect_peer(PeerId::new(), protocol_version).await;
            let peer_id = peer.get_id();
            let peer = Arc::new(tokio::sync::Mutex::new(peer));

            for two_blocks in blocks.chunks(2) {
                let block1 = &two_blocks[0];
                let block2 = &two_blocks[1];
                let block1_id = block1.get_id();
                let block2_id = block2.get_id();

                // Send 2 headers in the HeaderList response.
                peer.lock()
                    .await
                    .send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![
                        block1.header().clone(),
                        block2.header().clone(),
                    ])))
                    .await;

                // The node requests only one block due to max_request_blocks_count.
                let (sent_to, message) = node.get_sent_block_sync_message().await;
                assert_eq!(sent_to, peer_id);
                assert_eq!(
                    message,
                    BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![block1_id]))
                );

                // Send block1 as a response and explicitly call process_block at the same time.
                // Run the 2 futures jointly to increase the likelihood of interference.
                {
                    let node_call = {
                        let block1 = block1.clone();
                        async {
                            peer.lock()
                                .await
                                .send_block_sync_message(BlockSyncMessage::BlockResponse(
                                    BlockResponse::new(block1),
                                ))
                                .await;

                            tokio::time::sleep(Duration::from_millis(rng.random_range(1..10)))
                                .await;
                        }
                    };

                    let chainstate_call = {
                        let block1 = block1.clone();
                        async {
                            node.chainstate()
                                .call_mut(move |cs| {
                                    if cs
                                        .get_block_index_for_persisted_block(&block1_id)
                                        .unwrap()
                                        .is_none()
                                    {
                                        cs.process_block(block1, BlockSource::Peer).unwrap();
                                    } else {
                                        log::debug!("Block already processed by the node");
                                    }
                                })
                                .await
                                .unwrap();
                        }
                    };

                    tokio::join!(node_call, chainstate_call);
                }

                // The node should request block2.
                // This is the place where we expect the failure to occur in a buggy implementation.
                let (sent_to, message) =
                    tokio::time::timeout(MEDIUM_TIMEOUT, node.get_sent_block_sync_message())
                        .await
                        .unwrap();
                assert_eq!(sent_to, peer_id);
                assert_eq!(
                    message,
                    BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![block2_id]))
                );

                // Send block2.
                peer.lock()
                    .await
                    .send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                        block2.clone(),
                    )))
                    .await;

                // The node requests for more headers.
                // Note that this is also a potential place for failure, though it's less likely
                // to happen in this test (as opposed to process_block_interference1)
                let (sent_to, message) =
                    tokio::time::timeout(MEDIUM_TIMEOUT, node.get_sent_block_sync_message())
                        .await
                        .unwrap();
                assert_eq!(sent_to, peer_id);
                assert!(matches!(
                    message,
                    BlockSyncMessage::HeaderListRequest(HeaderListRequest { .. })
                ));
            }

            node.assert_no_error().await;
            node.join_subsystem_manager().await;
        })
        .await;
    })
    .await;
}

// A test for the fix of an issue where peers who are on different forks would send each other
// the same header list requests and the same responses over and over again, unable to stop.
// 1) Create a forked chain, such that using a locator created from one of the tips won't be able
// to locate anything in the other chain.
// 2) Start 2 nodes using the different chains and make them communicate.
// Expected result: the nodes discourage each other with ban score of 100.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_infinite_stalling_when_first_locator_cant_locate(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        // Note: locator distances are 0, 1, 2, 4, 8, 16, 32 etc.
        // Here for each peer the total number of blocks will be less than 32 and the number of
        // peer-specific blocks will be bigger than 16; this means the first locators that the
        // peers will send each other won't be able to locate any blocks.
        let msg_header_count_limit: usize = 5;
        let common_blocks_count = rng.random_range(5..8);
        let node1_extra_blocks_count = rng.random_range(18..22);
        let node2_extra_blocks_count = rng.random_range(18..22);

        log::debug!(
            "common blocks: {}, node1 extra blocks: {}, node2 extra blocks: {}",
            common_blocks_count,
            node1_extra_blocks_count,
            node2_extra_blocks_count
        );

        // `max_depth_for_reorg` has to be smaller than `msg_header_count_limit`, same as in
        // production, otherwise the discouragement won't happen.
        let max_depth_for_reorg = msg_header_count_limit - 1;

        let chain_config = Arc::new(
            common::chain::config::create_unit_test_config_builder()
                .max_depth_for_reorg(BlockDistance::new(max_depth_for_reorg as i64))
                .build(),
        );
        let genesis_ts_secs = chain_config.genesis_block().timestamp().as_int_seconds();
        let cur_time = Arc::new(SeqCstAtomicU64::new(
            rng.random_range(genesis_ts_secs..genesis_ts_secs * 2),
        ));
        let time_getter = mocked_time_getter_seconds(cur_time);

        let p2p_config = Arc::new(test_p2p_config_with_protocol_config(ProtocolConfig {
            msg_header_count_limit: msg_header_count_limit.into(),

            max_request_blocks_count: Default::default(),
            max_addr_list_response_address_count: Default::default(),
            msg_max_locator_count: Default::default(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
        }));

        let common_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter,
            common_blocks_count,
            &mut rng,
        );
        let node1_specific_blocks = make_new_blocks(
            &chain_config,
            common_blocks.last(),
            &time_getter,
            node1_extra_blocks_count,
            &mut rng,
        );
        let node2_specific_blocks = make_new_blocks(
            &chain_config,
            common_blocks.last(),
            &time_getter,
            node2_extra_blocks_count,
            &mut rng,
        );
        assert_ne!(node1_specific_blocks, node2_specific_blocks);

        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.clone())
            .with_blocks([common_blocks.as_slice(), node1_specific_blocks.as_slice()].concat())
            .build()
            .await;
        let node1_expected_first_locator = node1.get_locator_from_best_block().await;

        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.clone())
            .with_blocks([common_blocks.as_slice(), node2_specific_blocks.as_slice()].concat())
            .build()
            .await;
        let node2_expected_first_locator = node2.get_locator_from_best_block().await;

        // Sanity check: node2's first locator can't "locate" anything in node1's chainstate and vice versa
        let node1_blocks_existence_for_node2_locator =
            blocks_existence_for_locator(node1.chainstate(), node2_expected_first_locator.clone())
                .await;
        assert_eq!(
            node1_blocks_existence_for_node2_locator,
            vec![false; node2_expected_first_locator.len()]
        );
        let node2_blocks_existence_for_node1_locator =
            blocks_existence_for_locator(node2.chainstate(), node1_expected_first_locator.clone())
                .await;
        assert_eq!(
            node2_blocks_existence_for_node1_locator,
            vec![false; node1_expected_first_locator.len()]
        );

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);

        let mut had_header_list_req_from_node1 = false;
        let mut had_header_list_req_from_node2 = false;
        let mut node1_score_adjusted = false;
        let mut node2_score_adjusted = false;

        log::debug!("Starting message exchange");

        type MsgOrEvent<'a> =
            itertools::Either<&'a BlockSyncMessageWithNodeIdx, PeerManagerEventWithNodeIdx>;
        nodes
            .exchange_block_sync_messages_while_generic(
                &mut (),
                async |nodes: &mut TestNodeGroup, _, msg_or_event: MsgOrEvent<'_>| {
                    log::debug!("Got activity: {msg_or_event:?}");

                    match msg_or_event {
                        itertools::Either::Left(msg) => match &msg.message {
                            BlockSyncMessage::HeaderListRequest(req) => match msg.sender_node_idx {
                                0 => {
                                    if !had_header_list_req_from_node1 {
                                        assert_eq!(req.locator(), &node1_expected_first_locator);
                                        log::debug!("Got expected HeaderListRequest from node1");
                                        had_header_list_req_from_node1 = true;
                                    }
                                }
                                1 => {
                                    if !had_header_list_req_from_node2 {
                                        assert_eq!(req.locator(), &node2_expected_first_locator);
                                        log::debug!("Got expected HeaderListRequest from node2");
                                        had_header_list_req_from_node2 = true;
                                    }
                                }
                                _ => unreachable!(),
                            },

                            BlockSyncMessage::HeaderList(_)
                            | BlockSyncMessage::BlockListRequest(_)
                            | BlockSyncMessage::BlockResponse(_)
                            | BlockSyncMessage::TestSentinel(_) => {}
                        },
                        itertools::Either::Right(event) => match event.event {
                            PeerManagerEvent::AdjustPeerScore {
                                peer_id,
                                adjust_by,
                                reason: _,
                                response_sender,
                            } => {
                                response_sender.send(Ok(()));

                                match event.sender_node_idx {
                                    0 => {
                                        assert_eq!(
                                            peer_id,
                                            nodes.node(1).peer_id_as_seen_by_others()
                                        );
                                        assert_eq!(adjust_by, 100);

                                        assert!(!node2_score_adjusted);
                                        node2_score_adjusted = true;
                                    }
                                    1 => {
                                        assert_eq!(
                                            peer_id,
                                            nodes.node(0).peer_id_as_seen_by_others()
                                        );
                                        assert_eq!(adjust_by, 100);

                                        assert!(!node1_score_adjusted);
                                        node1_score_adjusted = true;
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            e => {
                                panic!(
                                    "Unexpected peer manager event: {e:?} (sender node idx = {})",
                                    event.sender_node_idx
                                );
                            }
                        },
                    }

                    if node1_score_adjusted && node2_score_adjusted {
                        MsgAction::Break
                    } else {
                        MsgAction::SendAndContinue
                    }
                },
            )
            .await;

        nodes.node_mut(0).assert_no_peer_manager_event().await;
        nodes.node_mut(1).assert_no_peer_manager_event().await;

        nodes.join_subsystem_managers().await;
    })
    .await;
}

async fn blocks_existence_for_locator(cs: &ChainstateHandle, locator: Locator) -> Vec<bool> {
    cs.call({
        move |cs| {
            locator
                .iter()
                .map(|block_id| cs.get_gen_block_index_for_any_block(block_id).unwrap().is_some())
                .collect_vec()
        }
    })
    .await
    .unwrap()
}
