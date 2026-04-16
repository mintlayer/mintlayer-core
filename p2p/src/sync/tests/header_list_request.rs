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

use chainstate::{ban_score::BanScore, Locator};
use chainstate_test_framework::TestFramework;
use common::{
    chain::config::create_unit_test_config,
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use logging::log;
use randomness::Rng as _;
use test_utils::{
    assert_matches_return_val,
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    config::P2pConfig,
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest},
    protocol::ProtocolConfig,
    sync::test_helpers::make_new_blocks,
    sync::tests::helpers::TestNode,
    test_helpers::{for_each_protocol_version, test_p2p_config_with_protocol_config},
    types::peer_id::PeerId,
    P2pError,
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_locator_size_exceeded(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block = tf.make_block_builder().build(&mut rng);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let headers = iter::repeat_n(block.get_id().into(), 102).collect();
        peer.send_block_sync_message(BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
            Locator::new(headers),
        )))
        .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(0, 0)).ban_score()
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
async fn valid_request(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        let block_index = tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();
        let locator = tf
            .chainstate
            .get_locator_from_height(block_index.block_height().prev_height().unwrap())
            .unwrap();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
            locator,
        )))
        .await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        let headers = match message {
            BlockSyncMessage::HeaderList(l) => l.into_headers(),
            m => panic!("Unexpected message: {m:?}"),
        };
        assert_eq!(headers.len(), 1);
        assert_eq!(&headers[0], block_index.block_header());
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_with_empty_header_list_when_in_ibd() {
    for_each_protocol_version(|protocol_version| async move {
        let time_getter = BasicTestTimeGetter::new();

        const STALLING_TIMEOUT: Duration = Duration::from_millis(500);

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
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
            backend_timeouts: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        // Node must be in Initial Download State
        assert!(node
            .chainstate()
            .call(|chainstate| chainstate.is_initial_block_download())
            .await
            .unwrap());

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        // Simulate the peer sending HeaderListRequest.
        let locator = node.get_locator_from_height(0.into()).await;
        peer.send_block_sync_message(BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
            locator,
        )))
        .await;

        // The node should send an empty header list.
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderList(HeaderList::new(Vec::new())),
        );

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

// The node communicates with a peer who is potentially on a different branch of a forked chain.
// The node's chain is longer than `msg_header_count_limit` and the height of the fork is less than
// or equal to `msg_header_count_limit`.
// 1) The node sends a header list request with a locator created from its best block.
// 2) The peer responds with a header list, last items of which may be from the other branch.
// 3) If there were headers from the other branch, the node sends a BlockListRequest and the
//    peer sends back the blocks.
// The node is expected to send another header list request with a locator made from the last block
// that the peer is known to have.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn locator_must_be_from_peers_known_best_block(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let node_blocks_count = 10;
        let msg_header_count_limit = 5;
        let common_blocks_count = rng.random_range(0..=msg_header_count_limit);
        let peer_specific_blocks_count = msg_header_count_limit - common_blocks_count;

        log::debug!("common_blocks_count = {common_blocks_count}");

        let p2p_config = Arc::new(test_p2p_config_with_protocol_config(ProtocolConfig {
            msg_header_count_limit: msg_header_count_limit.into(),

            max_request_blocks_count: Default::default(),
            max_addr_list_response_address_count: Default::default(),
            msg_max_locator_count: Default::default(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
        }));

        let node_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            node_blocks_count,
            &mut rng,
        );

        let peer_specific_blocks = make_new_blocks(
            &chain_config,
            common_blocks_count.checked_sub(1).map(|idx| &node_blocks[idx]),
            &time_getter.get_time_getter(),
            peer_specific_blocks_count,
            &mut rng,
        );
        let peer_block_headers = node_blocks[0..common_blocks_count]
            .iter()
            .chain(peer_specific_blocks.iter())
            .map(|block| block.header().clone())
            .collect_vec();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(node_blocks.clone())
            .build()
            .await;
        let node_expected_first_locator = node.get_locator_from_best_block().await;

        let peer = node.try_connect_peer(PeerId::new(), protocol_version);

        log::debug!("Expecting first HeaderListRequest");
        assert_eq!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
                node_expected_first_locator.clone()
            )),
        );

        log::debug!("Peer sends HeaderList");
        peer.send_headers(peer_block_headers[0..msg_header_count_limit].to_owned())
            .await;

        if common_blocks_count < msg_header_count_limit {
            log::debug!("Expecting BlockListRequest");
            let blocks_to_send =
                &peer_specific_blocks[0..msg_header_count_limit - common_blocks_count];
            assert_eq!(
                node.get_sent_block_sync_message().await.1,
                BlockSyncMessage::BlockListRequest(BlockListRequest::new(
                    blocks_to_send.iter().map(|block| block.get_id()).collect_vec()
                )),
            );

            for block in blocks_to_send {
                log::debug!("Peer sends BlockResponse");
                peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                    block.clone(),
                )))
                .await;
            }
        }

        log::debug!("Expecting second HeaderListRequest");
        let actual_header_list_req = assert_matches_return_val!(
            node.get_sent_block_sync_message().await.1,
            BlockSyncMessage::HeaderListRequest(req),
            req
        );
        // Note: obtain the second locator after we've got the HeaderListRequest message, so that
        // we're sure the BlockResponse's, if any, have been handled by the node and the peer-specific
        // blocks are in node's chainstate.
        let node_expected_second_locator = node
            .get_locator_from_block_id(&peer_block_headers.last().unwrap().block_id())
            .await;
        assert_eq!(
            actual_header_list_req.locator(),
            &node_expected_second_locator
        );

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;
        node.join_subsystem_manager().await;
    })
    .await;
}
