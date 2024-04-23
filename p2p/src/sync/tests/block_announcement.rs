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

use std::sync::Arc;

use chainstate::{ban_score::BanScore, BlockError, ChainstateError, CheckBlockError};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_unit_test_config, Builder as ChainConfigBuilder, ChainType},
        Block, NetUpgrades,
    },
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use consensus::ConsensusVerificationError;
use logging::log;
use test_utils::{random::Seed, BasicTestTimeGetter};

use crate::{
    config::P2pConfig,
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest},
    protocol::ProtocolConfig,
    sync::tests::helpers::TestNode,
    test_helpers::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
    P2pError,
};

use super::helpers::{make_new_blocks, make_new_top_blocks_return_headers};

// Sending even 1 singular unconnected header should produce the DisconnectedHeaders error.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_header_with_unknown_prev_block(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block_1 = tf.make_block_builder().build(&mut rng);
        let block_2 = tf.make_block_builder().with_parent(block_1.get_id().into()).build(&mut rng);

        let p2p_config = Arc::new(test_p2p_config());

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        // Sending even 1 unconnected header should lead to ban score increase.
        peer.send_headers(vec![block_2.header().clone()]).await;

        node.assert_peer_score_adjustment(
            peer.get_id(),
            P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
        )
        .await;
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// The peer ban score is increased if it sends an invalid header.
#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_timestamp() {
    for_each_protocol_version(|protocol_version| async move {
        let chain_config = Arc::new(create_unit_test_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let block = Block::new(
            Vec::new(),
            chain_config.genesis_block_id(),
            BlockTimestamp::from_int_seconds(1),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap();
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![block
            .header()
            .clone()])))
            .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ChainstateError(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::BlockTimeOrderInvalid(
                    BlockTimestamp::from_int_seconds(40),
                    BlockTimestamp::from_int_seconds(50),
                )),
            ))
            .ban_score()
        );
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// The peer ban score is increased if it sends an invalid header.
#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_consensus_data() {
    for_each_protocol_version(|protocol_version| async move {
        let chain_config = Arc::new(
            ChainConfigBuilder::new(ChainType::Regtest)
                // Enable consensus, so blocks with `ConsensusData::None` would be rejected.
                .consensus_upgrades(NetUpgrades::new_for_chain(ChainType::Regtest))
                .build(),
        );
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let block = Block::new(
            Vec::new(),
            chain_config.genesis_block_id(),
            BlockTimestamp::from_int_seconds(1),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap();
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![block
            .header()
            .clone()])))
            .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ChainstateError(ChainstateError::ProcessBlockError(
                BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
                    ConsensusVerificationError::ConsensusTypeMismatch("".into())
                )),
            ))
            .ban_score()
        );
        node.assert_no_sync_message().await;
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// The peer ban score is increased if the parent of the first announced block is unknown.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_headers_with_unknown_prev_block(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        let block = tf.make_block_builder().build(&mut rng);
        let orphan_block1 =
            tf.make_block_builder().with_parent(block.get_id().into()).build(&mut rng);
        let orphan_block2 = tf
            .make_block_builder()
            .with_parent(orphan_block1.get_id().into())
            .build(&mut rng);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_headers(vec![
            orphan_block1.header().clone(),
            orphan_block2.header().clone(),
        ])
        .await;

        node.assert_peer_score_adjustment(
            peer.get_id(),
            P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
        )
        .await;
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
async fn valid_block(#[case] seed: Seed) {
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

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![block
            .header()
            .clone()])))
            .await;

        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
        );
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that peer's best known block is taken into account when making block announcements.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn best_known_block_is_considered(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        // Create some initial blocks.
        let blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            1,
            &mut rng,
        );
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_blocks(blocks)
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        // Simulate the initial header exchange; make the peer send the node a locator containing
        // the node's tip, so that it responds with an empty header list.
        // I.e. we expect that though the node haven't sent any headers, it has remembered that
        // the peer already has the tip.
        {
            // First, respond to node's initial header request (made inside connect_peer).
            peer.send_headers(vec![]).await;

            let locator = node.get_locator_from_height(1.into()).await;

            peer.send_block_sync_message(BlockSyncMessage::HeaderListRequest(
                HeaderListRequest::new(locator),
            ))
            .await;

            log::debug!("Expecting initial header response");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::HeaderList(HeaderList::new(Vec::new()))
            );
        }

        let first_two_headers = {
            // Create two blocks. Note that this may result in generating two "ChainstateNewTip"
            // local events in rapid succession. But the implementation must make sure that only
            // one HeaderList message is produced.

            let headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                0,
                2,
            )
            .await;

            log::debug!("Expecting first announcement");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::HeaderList(HeaderList::new(headers.clone()))
            );

            log::debug!("Expecting no further announcements for now");
            node.assert_no_sync_message().await;

            headers
        };

        let second_two_headers = {
            // Create two more blocks; the expected result is that the node will send both
            // the previous two headers and the new ones.
            // I.e. the node should not consider what headers it has sent previously; only the
            // blocks that the peer has must be considered.

            let headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                0,
                2,
            )
            .await;

            log::debug!("Expecting second announcement");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::HeaderList(HeaderList::new(
                    [&first_two_headers[..], &headers[..]].concat()
                ))
            );

            log::debug!("Expecting no further announcements for now");
            node.assert_no_sync_message().await;

            headers
        };

        let third_two_headers = {
            // Now make a block request to the node and expect it to send the blocks.
            // After that, create two more blocks and check that the header announcement
            // doesn't include the headers of the already sent blocks.

            log::debug!("Sending block list request to the node");
            peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(
                BlockListRequest::new(first_two_headers.iter().map(|hdr| hdr.block_id()).collect()),
            ))
            .await;

            let block1 = node.get_block(first_two_headers[0].block_id()).await.unwrap();
            let block2 = node.get_block(first_two_headers[1].block_id()).await.unwrap();

            log::debug!("Expecting first block response");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::BlockResponse(BlockResponse::new(block1))
            );

            log::debug!("Expecting second block response");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::BlockResponse(BlockResponse::new(block2))
            );

            let headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                0,
                2,
            )
            .await;

            log::debug!("Expecting third announcement");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::HeaderList(HeaderList::new(
                    [&second_two_headers[..], &headers[..]].concat()
                ))
            );

            log::debug!("Expecting no further announcements for now");
            node.assert_no_sync_message().await;

            headers
        };

        {
            // Send a header announcement from the peer containing second_two_headers.
            // After that, create two more blocks on the node. The announcement that the node will
            // send must not include second_two_headers, because the node must have remembered
            // that the peer already has those blocks.

            log::debug!("Sending header announcement to the node");
            peer.send_headers(second_two_headers).await;

            log::debug!("Expecting no events from the node for now");
            node.assert_no_sync_message().await;

            let headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                0,
                2,
            )
            .await;

            log::debug!("Expecting fourth announcement");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::HeaderList(HeaderList::new(
                    [&third_two_headers[..], &headers[..]].concat()
                ))
            );

            log::debug!("Expecting no further announcements for now");
            node.assert_no_sync_message().await;
        }

        {
            // Create a better branch starting at genesis; it should be announced via a single
            // HeaderList message.
            let reorg_headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                9,
                10,
            )
            .await;

            log::debug!("Expecting fifth announcement");
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                BlockSyncMessage::HeaderList(HeaderList::new(reorg_headers))
            );
        }

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Send two HeaderList messages to the node, where the headers of the second one are connected
// to the headers in the first one, but not to anything else.
// The node should see them as disconnected and increase the peer's ban score.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_headers_connected_to_previously_sent_headers(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();
        let p2p_config = Arc::new(P2pConfig {
            protocol_config: ProtocolConfig {
                max_request_blocks_count: 1.into(),

                msg_header_count_limit: Default::default(),
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
        });

        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            1,
            &mut rng,
        );
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_blocks(initial_blocks.clone())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let peers_blocks = make_new_blocks(
            &chain_config,
            Some(&initial_blocks[0]),
            &time_getter.get_time_getter(),
            4,
            &mut rng,
        );
        let peers_block_headers: Vec<_> =
            peers_blocks.iter().map(|blk| blk.header().clone()).collect();

        // Announce first 2 blocks to the node; the node should request one block (because it's the
        // limit specified in p2p_config above).
        log::debug!("Sending first 2 headers");
        peer.send_headers(peers_block_headers[0..2].to_owned()).await;
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![
                peers_blocks[0].get_id()
            ]))
        );
        node.assert_no_peer_manager_event().await;

        // Announce the second 2 blocks to the node.
        // The node should see them as disconnected and increase the peer's ban score.
        log::debug!("Sending second 2 headers");
        peer.send_headers(peers_block_headers[2..4].to_owned()).await;

        node.assert_peer_score_adjustment(
            peer.get_id(),
            P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
        )
        .await;

        node.assert_no_sync_message().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

// This is similar to send_headers_connected_to_previously_sent_headers, but here the second
// header list is connected to a block which the node is trying to download. The headers
// should also be considered disconnected in this case.
// Note that this behavior was allowed at some point in V1. But the implementation never used
// this fact when sending headers, so we could disallow it without breaking the compatibility.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_headers_connected_to_block_which_is_being_downloaded(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();
        let p2p_config = Arc::new(P2pConfig {
            protocol_config: ProtocolConfig {
                max_request_blocks_count: 1.into(),

                msg_header_count_limit: Default::default(),
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
        });

        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            1,
            &mut rng,
        );
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_blocks(initial_blocks.clone())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let peers_blocks = make_new_blocks(
            &chain_config,
            Some(&initial_blocks[0]),
            &time_getter.get_time_getter(),
            4,
            &mut rng,
        );
        let peers_block_headers: Vec<_> =
            peers_blocks.iter().map(|blk| blk.header().clone()).collect();

        // Announce first 2 blocks to the node; the node should request one block (because it's the
        // limit specified in p2p_config above).
        log::debug!("Sending first 2 headers");
        peer.send_headers(peers_block_headers[0..2].to_owned()).await;
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![
                peers_blocks[0].get_id()
            ]))
        );
        node.assert_no_peer_manager_event().await;

        // Announce blocks 1, 2, 3 to the node - block 1 is connected to block 0, which
        // the node has already requested, but which it hasn't received yet.
        log::debug!("Sending headers 1, 2, 3");
        peer.send_headers(peers_block_headers[1..4].to_owned()).await;

        node.assert_peer_score_adjustment(
            peer.get_id(),
            P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
        )
        .await;

        node.assert_no_sync_message().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

// The peer announces block headers 0, 1, 2, 3, while the header 2 is already in the node's
// pending_headers.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_pending_headers_update(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();
        let p2p_config = Arc::new(P2pConfig {
            protocol_config: ProtocolConfig {
                max_request_blocks_count: 2.into(),

                msg_header_count_limit: Default::default(),
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
        });

        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            1,
            &mut rng,
        );
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_blocks(initial_blocks.clone())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let peers_blocks = make_new_blocks(
            &chain_config,
            Some(&initial_blocks[0]),
            &time_getter.get_time_getter(),
            4,
            &mut rng,
        );
        let peers_block_headers: Vec<_> =
            peers_blocks.iter().map(|blk| blk.header().clone()).collect();

        // Announce first 3 blocks to the node; the node should request 2 blocks (because it's the
        // limit specified in p2p_config above).
        log::debug!("Sending first 3 headers");
        peer.send_headers(peers_block_headers[0..3].to_owned()).await;
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![
                peers_blocks[0].get_id(),
                peers_blocks[1].get_id()
            ]))
        );
        node.assert_no_peer_manager_event().await;

        // Simulate the following situation: the 4th block has just been produced but the peer hasn't
        // yet received the block request, so it has to send all 4 headers.
        // The node, which already has block 2 in its pending_headers collection, must update
        // it correctly.
        log::debug!("Sending headers 0, 1, 2, 3");
        peer.send_headers(peers_block_headers[0..4].to_owned()).await;
        node.assert_no_peer_manager_event().await;

        log::debug!("Sending blocks 0, 1");
        peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
            peers_blocks[0].clone(),
        )))
        .await;
        peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
            peers_blocks[1].clone(),
        )))
        .await;

        log::debug!("Expecting request for blocks 2, 3");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![
                peers_blocks[2].get_id(),
                peers_blocks[3].get_id()
            ]))
        );
        node.assert_no_peer_manager_event().await;

        node.assert_no_sync_message().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

// The peer asks for blocks in the reverse order; the node sends the blocks in that order.
// Then some new blocks are created on the node; the node must announce the new blocks,
// correctly taking into account the previously sent ones (i.e. only headers of the newly
// created blocks should be sent).
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_best_sent_block_update(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let initial_blocks = make_new_blocks(
            &chain_config,
            None,
            &time_getter.get_time_getter(),
            2,
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

        // Respond to node's initial header request (made inside connect_peer)
        peer.send_headers(vec![]).await;

        log::debug!("Sending header list request to the node");
        let locator = node.get_locator_from_height(0.into()).await;
        peer.send_block_sync_message(BlockSyncMessage::HeaderListRequest(HeaderListRequest::new(
            locator,
        )))
        .await;

        log::debug!("Expecting header list response");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::HeaderList(HeaderList::new(initial_block_headers.clone()))
        );

        log::debug!("Sending block list request to the node with reversed block order");
        peer.send_block_sync_message(BlockSyncMessage::BlockListRequest(BlockListRequest::new(
            initial_block_headers.iter().map(|hdr| hdr.block_id()).rev().collect(),
        )))
        .await;

        log::debug!("Expecting block response for block #1");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockResponse(BlockResponse::new(initial_blocks[1].clone()))
        );

        log::debug!("Expecting block response for block #0");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::BlockResponse(BlockResponse::new(initial_blocks[0].clone()))
        );

        let headers = make_new_top_blocks_return_headers(
            node.chainstate(),
            time_getter.get_time_getter(),
            &mut rng,
            0,
            2,
        )
        .await;

        log::debug!("Expecting block announcement");
        let (sent_to, message) = node.get_sent_block_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            BlockSyncMessage::HeaderList(HeaderList::new(headers))
        );

        node.assert_no_sync_message().await;
        node.assert_no_peer_manager_event().await;
        node.join_subsystem_manager().await;
    })
    .await;
}
