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

use std::{iter, sync::Arc, time::Duration};

use itertools::Itertools as _;

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{GenBlock, config::create_unit_test_config},
    primitives::{BlockHeight, Id, Idable},
};
use logging::log;
use p2p_test_utils::create_n_blocks;
use randomness::RngExt as _;
use test_utils::{
    BasicTestTimeGetter, assert_matches,
    random::{Seed, make_seedable_rng},
};

use crate::{
    P2pConfig, P2pError,
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList},
    sync::{test_helpers::make_new_blocks, tests::helpers::TestNode},
    test_helpers::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_count_limit_exceeded(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block = tf.make_block_builder().build(&mut rng);

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let headers = iter::repeat_n(
            block.header().clone(),
            *p2p_config.protocol_config.msg_header_count_limit + 1,
        )
        .collect();
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers)))
            .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::HeadersLimitExceeded(0, 0)).ban_score()
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
async fn unordered_headers(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Skip the header in the middle.
        let headers = create_n_blocks(&mut rng, &mut tf, 3)
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, b)| b.header().clone())
            .collect();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers)))
            .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
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
async fn disconnected_headers(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let headers = create_n_blocks(&mut rng, &mut tf, 3)
            .into_iter()
            .skip(1)
            .map(|b| b.header().clone())
            .collect();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers)))
            .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
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
async fn valid_headers(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let blocks = create_n_blocks(&mut rng, &mut tf, 3);

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
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(
                blocks.into_iter().map(|b| b.get_id()).collect()
            ))
        );

        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect() {
    for_each_protocol_version(|protocol_version| async move {
        let p2p_config = Arc::new(P2pConfig {
            sync_stalling_timeout: Duration::from_millis(100).into(),

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
            user_agent: "test".try_into().unwrap(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
            backend_timeouts: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });
        let mut node = TestNode::builder(protocol_version)
            .with_p2p_config(Arc::clone(&p2p_config))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        tokio::time::sleep(Duration::from_millis(300)).await;
        node.receive_disconnect_peer_event(peer.get_id()).await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// When handling a header list, the node must check headers' validity first, and only then check
// if some blocks have already been requested.
// The actual test happens with "make_branch2_invalid=true":
// 1) Make a forked chain with 2 branches; the 1st one is good, the 2nd one has an invalid header.
// 2) The peer sends a header list for the 1st branch; the node responds with a block list request.
// 3) The peer sends a header list for the 2nd branch.
// Expected result: the node sees that the new header list has an invalid header and adjusts
// the peer score immediately.
// The case "make_branch2_invalid=false" exists for completeness; all headers on the 2nd branch
// are ok in this case and the node is expected to send another BlockListRequest and accept the
// corresponding blocks without punishing the peer.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_check_happens_before_checking_if_blocks_were_requested(
    #[case] seed: Seed,
    #[values(false, true)] make_branch2_invalid: bool,
) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let node_blocks_count = rng.random_range(1..3);
        let branch1_len = rng.random_range(3..5);
        let branch2_len = rng.random_range(3..5);

        log::debug!(
            "node_blocks_count = {}, branch1_len = {}, branch2_len = {}",
            node_blocks_count,
            branch1_len,
            branch2_len
        );

        let node_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            node_blocks_count,
            &mut rng,
        );

        let branch1_blocks = make_new_blocks(
            &chain_config,
            node_blocks.last(),
            &time_getter.get_time_getter(),
            branch1_len,
            &mut rng,
        );

        let branch2_blocks = make_new_blocks(
            &chain_config,
            node_blocks.last(),
            &time_getter.get_time_getter(),
            branch2_len,
            &mut rng,
        );

        let chain_config = if make_branch2_invalid {
            let branch2_invalid_header_idx =
                rng.random_range(0..std::cmp::min(branch1_blocks.len(), branch2_blocks.len()));

            // To make one of the headers on branch2 invalid, specify a checkpoint referring to
            // a block on branch1.
            let checkpoint_height =
                BlockHeight::new((branch2_invalid_header_idx + node_blocks.len() + 1) as u64);
            let checkpoint_block_id: Id<GenBlock> =
                branch1_blocks[branch2_invalid_header_idx].get_id().into();

            let chain_config = Arc::new(
                common::chain::config::create_unit_test_config_builder()
                    .checkpoints([(checkpoint_height, checkpoint_block_id)].into())
                    .build(),
            );

            chain_config
        } else {
            chain_config
        };

        let p2p_config = Arc::new(test_p2p_config());

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(node_blocks.clone())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        log::debug!("Peer sends HeaderList for branch1");
        peer.send_headers(branch1_blocks.iter().map(|block| block.header().clone()).collect_vec())
            .await;

        log::debug!("Expecting BlockListRequest for branch 1");
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(
                branch1_blocks.iter().map(|block| block.get_id()).collect_vec()
            )),
        );

        log::debug!("Peer sends HeaderList for branch2");
        peer.send_headers(branch2_blocks.iter().map(|block| block.header().clone()).collect_vec())
            .await;

        if make_branch2_invalid {
            // The node should check the headers right away and discover that one of them is invalid.
            node.assert_peer_score_adjustment(peer.get_id(), 100).await;
            node.assert_no_sync_message().await;
        } else {
            // If the headers are ok, the node should accept the previously requested blocks
            // and make a new block request for the new ones.

            for block in &branch1_blocks {
                log::debug!("Peer sends BlockResponse for branch 1");
                peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                    block.clone(),
                )))
                .await;
            }

            log::debug!("Expecting BlockListRequest for branch 2");
            assert_eq!(
                node.get_sent_block_sync_message().await.1,
                BlockSyncMessage::BlockListRequest(BlockListRequest::new(
                    branch2_blocks.iter().map(|block| block.get_id()).collect_vec()
                )),
            );

            for block in &branch2_blocks {
                log::debug!("Peer sends BlockResponse for branch 2");
                peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                    block.clone(),
                )))
                .await;
            }

            log::debug!("Expecting final HeaderListRequest");
            assert_matches!(
                node.get_sent_block_sync_message().await.1,
                BlockSyncMessage::HeaderListRequest(_)
            );
        }

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;
        node.assert_no_sync_message().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that if the peer tries to extend a branch that has been invalidated in the node,
// the node will detect it when validating headers and won't try to download blocks that are
// known to be invalid.
// The actual test happens with "invalidate_branch2=true":
// 1) The node has a forked chain, where the 2nd branch has a manually invalidated block.
// 2) The peer sends a HeaderList that may include some part of the invalidated branch and also adds
//    new blocks on top of it.
// Expected result: the node adjusts peer's score immediately, without trying to download the
// blocks first.
// The case "invalidate_branch2=false" exists for completeness; no blocks on the 2nd branch are
// invalidated in this case and the node is expected to send a BlockListRequest and accept the
// corresponding blocks without punishing the peer.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extending_invalidated_chain_should_fail_at_header_check(
    #[case] seed: Seed,
    #[values(false, true)] invalidate_branch2: bool,
) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let common_blocks_count = rng.random_range(1..3);
        let branch1_blocks_count = rng.random_range(3..5);
        let branch2_known_blocks_count = rng.random_range(1..3);
        let branch2_unknown_blocks_count = rng.random_range(1..3);

        log::debug!(
            "common blk = {}, branch1 blk = {}, branch2 known blk = {}, branch2 unknown blk = {}",
            common_blocks_count,
            branch1_blocks_count,
            branch2_known_blocks_count,
            branch2_unknown_blocks_count
        );

        let common_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            common_blocks_count,
            &mut rng,
        );

        let branch1_blocks = make_new_blocks(
            &chain_config,
            common_blocks.last(),
            &time_getter.get_time_getter(),
            branch1_blocks_count,
            &mut rng,
        );

        let branch2_known_blocks = make_new_blocks(
            &chain_config,
            common_blocks.last(),
            &time_getter.get_time_getter(),
            branch2_known_blocks_count,
            &mut rng,
        );

        let branch2_unknown_blocks = make_new_blocks(
            &chain_config,
            branch2_known_blocks.last(),
            &time_getter.get_time_getter(),
            branch2_unknown_blocks_count,
            &mut rng,
        );

        let p2p_config = Arc::new(test_p2p_config());

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(
                [
                    common_blocks.as_slice(),
                    branch1_blocks.as_slice(),
                    branch2_known_blocks.as_slice(),
                ]
                .concat(),
            )
            .build()
            .await;

        if invalidate_branch2 {
            let block_id_to_invalidate =
                branch2_known_blocks[rng.random_range(0..branch2_known_blocks.len())].get_id();
            node.chainstate()
                .call_mut(move |cs| cs.invalidate_block(&block_id_to_invalidate))
                .await
                .unwrap()
                .unwrap()
        }

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let branch2_first_known_block_to_send_idx =
            rng.random_range(0..=branch2_known_blocks.len());
        let branch2_headers = branch2_known_blocks[branch2_first_known_block_to_send_idx..]
            .iter()
            .chain(branch2_unknown_blocks.iter())
            .map(|block| block.header().clone())
            .collect_vec();

        log::debug!("Peer sends HeaderList for branch2");
        peer.send_headers(branch2_headers).await;

        if invalidate_branch2 {
            // The node should discover that the headers extend an invalidated chain, without
            // the need to download the actual blocks, and discourage the peer right away.
            node.assert_peer_score_adjustment(peer.get_id(), 100).await;
            node.assert_no_sync_message().await;
        } else {
            // If the headers are ok, the node should make a block request for the unknown blocks.

            log::debug!("Expecting BlockListRequest for branch2_unknown_blocks");
            assert_eq!(
                node.get_sent_block_sync_message().await.1,
                BlockSyncMessage::BlockListRequest(BlockListRequest::new(
                    branch2_unknown_blocks.iter().map(|block| block.get_id()).collect_vec()
                )),
            );

            for block in &branch2_unknown_blocks {
                log::debug!("Peer sends BlockResponse for branch2_unknown_blocks");
                peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                    block.clone(),
                )))
                .await;
            }

            log::debug!("Expecting final HeaderListRequest");
            assert_matches!(
                node.get_sent_block_sync_message().await.1,
                BlockSyncMessage::HeaderListRequest(_)
            );
        }

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;
        node.assert_no_sync_message().await;
        node.join_subsystem_manager().await;
    })
    .await;
}
