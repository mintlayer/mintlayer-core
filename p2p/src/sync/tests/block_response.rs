// Copyright (c) 2022 RBB S.r.l
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

use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{
    chain::config::create_unit_test_config,
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use logging::log;
use p2p_test_utils::{create_n_blocks, P2pBasicTestTimeGetter};
use randomness::Rng;
use test_utils::random::{shuffle_until_different, Seed};

use crate::{
    ban_config::BanConfig,
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest},
    sync::tests::helpers::{
        make_new_blocks, make_new_top_blocks_return_headers, PeerManagerEventDesc, TestNode,
    },
    testing_utils::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
    P2pConfig, P2pError, PeerManagerEvent,
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrequested_block(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block = tf.make_block_builder().build();
        let block_id = block.get_id();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(block)))
            .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::UnsolicitedBlockReceived(block_id)).ban_score()
        );
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_response(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let num_blocks = rng.gen_range(2..10);
        let blocks = create_n_blocks(&mut tf, num_blocks);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let headers = blocks.iter().map(|b| b.header().clone()).collect();
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers)))
            .await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        let ids = blocks.iter().map(|b| b.get_id()).collect();
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(ids))
        );

        for block in blocks.into_iter() {
            peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                block.clone(),
            )))
            .await;
        }

        // A peer would request headers after the last block.
        assert!(matches!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderListRequest(HeaderListRequest { .. })
        ));

        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_responses_in_wrong_order(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let p2p_config = Arc::new(P2pConfig {
            ban_config: BanConfig {
                // We want to count discourageable errors in this test, but don't want a disconnect
                // to happen because of them.
                discouragement_threshold: 1000.into(),
                discouragement_duration: Default::default(),
            },

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: "test".try_into().unwrap(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
        });

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let num_blocks = rng.gen_range(2..10);
        log::debug!("Generating {num_blocks} blocks");
        let blocks = create_n_blocks(&mut tf, num_blocks);

        let normal_indices: Vec<_> = (0..num_blocks).collect();
        let shuffled_indices = {
            let mut indices = normal_indices.clone();
            shuffle_until_different(&mut indices, &mut rng);
            indices
        };
        log::debug!("Shuffled indices are {shuffled_indices:?}");

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let headers = blocks.iter().map(|b| b.header().clone()).collect();
        peer.send_headers(headers).await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        let ids = blocks.iter().map(|b| b.get_id()).collect();
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(ids))
        );

        {
            let mut expected_indices = VecDeque::from_iter(&normal_indices);
            let mut shuffled_indices = VecDeque::from_iter(&shuffled_indices);
            for _ in 0..num_blocks {
                let shuffled_index = *shuffled_indices.pop_front().unwrap();
                let expected_index = *expected_indices[0];

                log::debug!("Expected index = {expected_index}, shuffled index = {shuffled_index}");

                peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                    blocks[shuffled_index].clone(),
                )))
                .await;

                if shuffled_index == expected_index {
                    expected_indices.pop_front();

                    let expected_block_id = blocks[shuffled_index].get_id();
                    node.receive_or_ignore_peer_manager_events(
                        BTreeSet::from_iter(
                            [
                                PeerManagerEventDesc::NewTipReceived {
                                    peer_id: peer.get_id(),
                                    block_id: expected_block_id,
                                },
                                PeerManagerEventDesc::NewChainstateTip(expected_block_id),
                            ]
                            .into_iter(),
                        ),
                        |event| matches!(event, PeerManagerEvent::PeerBlockSyncStatusUpdate { .. }),
                    )
                    .await;
                } else {
                    let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
                    assert_eq!(peer.get_id(), adjusted_peer);
                    assert_eq!(
                        score,
                        P2pError::ProtocolError(ProtocolError::BlocksReceivedInWrongOrder {
                            expected_block_id: blocks[expected_index].get_id(),
                            actual_block_id: blocks[shuffled_index].get_id(),
                        })
                        .ban_score()
                    );
                }
            }

            assert_ne!(expected_indices.len(), 0);
        }

        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block = tf.make_block_builder().build();

        let p2p_config = Arc::new(P2pConfig {
            sync_stalling_timeout: Duration::from_millis(100).into(),

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
            user_agent: "test".try_into().unwrap(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
        });
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![block
            .header()
            .clone()])))
            .await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        node.receive_disconnect_peer_event(peer.get_id()).await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Respond to a block request with a delay that is only slightly less than the timeout.
// Then respond to the following HeaderListRequest with the same delay.
// The peer should not be disconnected.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_response(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let time_getter = P2pBasicTestTimeGetter::new();

        const STALLING_TIMEOUT: Duration = Duration::from_millis(500);
        const DELAY: Duration = Duration::from_millis(400);

        let chain_config = Arc::new(create_unit_test_config());
        let p2p_config = Arc::new(P2pConfig {
            sync_stalling_timeout: STALLING_TIMEOUT.into(),

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
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
        });

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block = tf.make_block_builder().with_parent(chain_config.genesis_block_id()).build();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![block
            .header()
            .clone()])))
            .await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
        );

        time_getter.advance_time(DELAY);

        peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
            block.clone(),
        )))
        .await;

        assert!(matches!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderListRequest(HeaderListRequest { .. })
        ));

        time_getter.advance_time(DELAY);

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(Vec::new())))
            .await;

        node.assert_no_error().await;
        // Just in case, check that there were no peer manager events at all, not just disconnects.
        node.assert_no_peer_manager_event().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that requesting a previously invalidated block is handled correctly.
// The test scenario:
// 1) Send some blocks to the peer.
// This will set the node's best_send_block field for this peer.
// 2) Invalidate 2nd block from the top; add 1 new block instead.
// 3) Send the tip update for the new block; the peer will ask for the block.
// 4) Invalidate the newly added block.
// What happens: the peer asks for a block at height less than best_sent_block.block_height().
// The node's logic that checks for duplicate block requests will detect this and attempt
// to figure out if it's because of a reorg. To do so, it will compare the requested block
// id with the id of the mainchain block at the same height. But there is no mainchain block
// at that height anymore. The code should not panic.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidated_block(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let time_getter = P2pBasicTestTimeGetter::new();
        let chain_config = Arc::new(create_unit_test_config());
        let p2p_config = Arc::new(test_p2p_config());

        let num_initial_blocks = 2;
        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            num_initial_blocks,
            &mut rng,
        );

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(p2p_config)
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(initial_blocks.clone())
            .build()
            .await;

        // Connect to the peer and check that HeaderListRequest is sent to it.
        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        // Receive HeaderListRequest from the peer.
        let peers_locator = node.get_locator_from_height(0.into()).await;
        peer.send_block_sync_message(BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
            peers_locator,
        )))
        .await;

        // The node sends HeaderList.
        let initial_blocks_headers = initial_blocks.iter().map(|b| b.header().clone()).collect();
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderList(HeaderList::new(initial_blocks_headers))
        );

        // Receive BlockListRequest from the peer.
        let initial_blocks_ids = initial_blocks.iter().map(|b| b.get_id()).collect();
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            initial_blocks_ids,
        )))
        .await;

        // The node sends block responses.
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::BlockResponse(BlockResponse::new(initial_blocks[0].clone()))
        );
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::BlockResponse(BlockResponse::new(initial_blocks[1].clone()))
        );

        // After this, initial_blocks[1] is node's best_send_block for this peer.

        // Invalidate the previously sent blocks
        let initial_block_id_to_invalidate = initial_blocks[0].get_id();
        node.chainstate()
            .call_mut(move |cs| {
                cs.invalidate_block(&initial_block_id_to_invalidate).unwrap();
            })
            .await
            .unwrap();

        // Create 1 new block on top.
        let new_header = make_new_top_blocks_return_headers(
            node.chainstate(),
            time_getter.get_time_getter(),
            &mut rng,
            0,
            1,
        )
        .await[0]
            .clone();

        // The node should send the new tip update
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderList(HeaderList::new(vec![new_header.clone()]))
        );

        // Invalidate the newly created block
        let block_id_to_invalidate = new_header.block_id();
        node.chainstate()
            .call_mut(move |cs| {
                cs.invalidate_block(&block_id_to_invalidate).unwrap();
            })
            .await
            .unwrap();

        // The peer requests for the now invalidated block.
        // The node should handle this correctly.
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            vec![new_header.block_id()],
        )))
        .await;

        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}
