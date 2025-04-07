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

use std::{iter, sync::Arc};

use chainstate::{ban_score::BanScore, BlockSource};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{config::create_unit_test_config, Block},
    primitives::{Id, Idable},
};
use logging::log;
use p2p_test_utils::create_n_blocks;
use randomness::Rng;
use test_utils::{random::Seed, BasicTestTimeGetter};

use crate::{
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage},
    sync::tests::helpers::{make_new_blocks, TestNode},
    test_helpers::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
    P2pError,
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_block_count_in_request_exceeded(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        let block = tf.make_block_builder().build(&mut rng);
        tf.process_block(block.clone(), BlockSource::Local).unwrap().unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let blocks = iter::repeat_n(
            block.get_id(),
            *p2p_config.protocol_config.max_request_blocks_count + 1,
        )
        .collect();
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            blocks,
        )))
        .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::BlocksRequestLimitExceeded(0, 0)).ban_score()
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
async fn unknown_blocks(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();
        let unknown_blocks: Vec<Id<Block>> =
            create_n_blocks(&mut rng, &mut tf, 2).into_iter().map(|b| b.get_id()).collect();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let expected_score =
            P2pError::ProtocolError(ProtocolError::UnknownBlockRequested(unknown_blocks[0]))
                .ban_score();
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            unknown_blocks,
        )))
        .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(score, expected_score);
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
async fn valid_request(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Import several blocks.
        let num_blocks = rng.gen_range(2..10);
        let blocks = create_n_blocks(&mut rng, &mut tf, num_blocks);
        for block in blocks.clone() {
            tf.process_block(block, BlockSource::Local).unwrap().unwrap();
        }

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let ids = blocks.iter().map(|b| b.get_id()).collect();
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            ids,
        )))
        .await;

        for block in blocks {
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(peer.get_id(), sent_to);
            assert_eq!(
                message,
                BlockSyncMessage::BlockResponse(BlockResponse::new(block))
            );
        }

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// 1) The peer requests a block.
// 2) The node sends the block.
// 3) The peer requests the same block again.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_same_block_after_downloading(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        let block = tf.make_block_builder().build(&mut rng);
        tf.process_block(block.clone(), BlockSource::Local).unwrap().unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            vec![block.get_id()],
        )))
        .await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(
            message,
            BlockSyncMessage::BlockResponse(BlockResponse::new(block.clone()))
        );

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;

        // Request the same block twice.
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            vec![block.get_id()],
        )))
        .await;

        node.assert_peer_score_adjustment(
            peer.get_id(),
            P2pError::ProtocolError(ProtocolError::DuplicatedBlockRequest(block.get_id()))
                .ban_score(),
        )
        .await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// 1) The peer requests a bunch of blocks.
// 2) The node starts sending the blocks.
// 3) The peer requests the last requested block again, while earlier blocks are still being sent.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_same_block_while_downloading(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            10,
            &mut rng,
        );
        let initial_block_headers: Vec<_> =
            initial_blocks.iter().map(|blk| blk.header().clone()).collect();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_blocks(initial_blocks.clone())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        log::debug!("Sending block list request to the node");
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            initial_block_headers.iter().map(|hdr| hdr.block_id()).collect(),
        )))
        .await;

        log::debug!("Expecting block response #0");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockResponse(BlockResponse::new(initial_blocks[0].clone()))
        );

        let duplicate_block_id = initial_blocks.last().unwrap().get_id();

        log::debug!("Sending duplicate block request");
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            vec![duplicate_block_id],
        )))
        .await;

        node.assert_peer_score_adjustment(
            peer.get_id(),
            P2pError::ProtocolError(ProtocolError::DuplicatedBlockRequest(duplicate_block_id))
                .ban_score(),
        )
        .await;

        node.join_subsystem_manager().await;
    })
    .await;
}
