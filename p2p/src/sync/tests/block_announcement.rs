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
use p2p_test_utils::P2pBasicTestTimeGetter;
use test_utils::random::Seed;

use crate::{
    config::P2pConfig,
    error::ProtocolError,
    message::{BlockListRequest, HeaderList, HeaderListRequest, SyncMessage},
    protocol::SupportedProtocolVersion,
    sync::tests::helpers::TestNode,
    testing_utils::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
    P2pError,
};

use super::helpers::{make_new_blocks, make_new_top_blocks_return_headers};

// V1: the header list request is sent if the parent of the singular announced block is unknown.
// However, if max_singular_unconnected_headers is exceeded, the DisconnectedHeaders error
// is generated.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_header_with_unknown_prev_block_v1(#[case] seed: Seed) {
    let protocol_version = SupportedProtocolVersion::V1.into();

    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block_1 = tf.make_block_builder().build();
    let block_2 = tf.make_block_builder().with_parent(block_1.get_id().into()).build();

    let p2p_config = Arc::new(P2pConfig {
        max_singular_unconnected_headers: 1.into(),

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
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        sync_stalling_timeout: Default::default(),
        enable_block_relay_peers: Default::default(),
    });

    let mut node = TestNode::builder(protocol_version)
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = node.connect_peer(PeerId::new(), protocol_version).await;

    // The first attempt to send an unconnected header should trigger HeaderListRequest.
    peer.send_headers(vec![block_2.header().clone()]).await;

    // Note: we call assert_no_peer_manager_event twice; the last call is needed to make sure
    // that the event is caught even if it's late; the first one just allows the test to fail
    // faster if the event is not late.
    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.get_sent_message().await;
    assert_eq!(sent_to, peer.get_id());
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    node.assert_no_peer_manager_event().await;

    // The second attempt to send an unconnected header should increase the ban score.
    peer.send_headers(vec![block_2.header().clone()]).await;

    node.assert_peer_score_adjustment(
        peer.get_id(),
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
    )
    .await;
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

// Same as single_header_with_unknown_prev_block_v1, but here a connected header list is sent
// in between the two attempts to send unconnected ones. This should reset the number of
// singular unconnected headers, so no error should be generated.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_header_with_unknown_prev_block_with_intermittent_connected_headers_v1(
    #[case] seed: Seed,
) {
    let protocol_version = SupportedProtocolVersion::V1.into();

    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block_1 = tf.make_block_builder().add_test_transaction(&mut rng).build();
    let block_11 = tf
        .make_block_builder()
        .add_test_transaction(&mut rng)
        .with_parent(chain_config.genesis_block_id())
        .build();
    let block_2 = tf.make_block_builder().with_parent(block_1.get_id().into()).build();

    let p2p_config = Arc::new(P2pConfig {
        max_singular_unconnected_headers: 1.into(),

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
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        sync_stalling_timeout: Default::default(),
        enable_block_relay_peers: Default::default(),
    });

    let mut node = TestNode::builder(protocol_version)
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = node.connect_peer(PeerId::new(), protocol_version).await;

    // The first attempt to send an unconnected header should trigger HeaderListRequest.
    peer.send_headers(vec![block_2.header().clone()]).await;

    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.get_sent_message().await;
    assert_eq!(sent_to, peer.get_id());
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    node.assert_no_peer_manager_event().await;

    // Send a header with a known parent, the node should ask for blocks
    peer.send_headers(vec![block_11.header().clone()]).await;

    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.get_sent_message().await;
    assert_eq!(sent_to, peer.get_id());
    assert!(matches!(message, SyncMessage::BlockListRequest(_)));
    node.assert_no_peer_manager_event().await;

    // The second attempt to send an unconnected header should again trigger HeaderListRequest,
    // because a correct header list message was received between the attempts and the counter
    // for the unconnected headers has been reset.
    peer.send_headers(vec![block_2.header().clone()]).await;

    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.get_sent_message().await;
    assert_eq!(sent_to, peer.get_id());
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    node.assert_no_peer_manager_event().await;

    node.join_subsystem_manager().await;
}

// In V2 sending even 1 singular unconnected header should produce the DisconnectedHeaders error.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_header_with_unknown_prev_block_v2(#[case] seed: Seed) {
    let protocol_version = SupportedProtocolVersion::V2.into();

    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block_1 = tf.make_block_builder().build();
    let block_2 = tf.make_block_builder().with_parent(block_1.get_id().into()).build();

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
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
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
        peer.send_message(SyncMessage::HeaderList(HeaderList::new(vec![block
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
        node.assert_no_event().await;

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
            ChainConfigBuilder::new(ChainType::Mainnet)
                // Enable consensus, so blocks with `ConsensusData::None` would be rejected.
                .net_upgrades(NetUpgrades::new(ChainType::Mainnet))
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
        peer.send_message(SyncMessage::HeaderList(HeaderList::new(vec![block
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
        node.assert_no_event().await;
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
        let block = tf.make_block_builder().build();
        let orphan_block1 = tf.make_block_builder().with_parent(block.get_id().into()).build();
        let orphan_block2 =
            tf.make_block_builder().with_parent(orphan_block1.get_id().into()).build();

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
        node.assert_no_event().await;

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
        let block = tf.make_block_builder().build();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_message(SyncMessage::HeaderList(HeaderList::new(vec![block
            .header()
            .clone()])))
            .await;

        let (sent_to, message) = node.get_sent_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(
            message,
            SyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
        );
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that the best known header is taken into account when making block announcements.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn best_known_header_is_considered(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = P2pBasicTestTimeGetter::new();

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
            let locator = node.get_locator_from_height(1.into()).await;

            peer.send_message(SyncMessage::HeaderListRequest(HeaderListRequest::new(
                locator,
            )))
            .await;

            log::debug!("Expecting initial header response");
            let (sent_to, message) = node.get_sent_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                SyncMessage::HeaderList(HeaderList::new(Vec::new()))
            );
        }

        {
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
            let (sent_to, message) = node.get_sent_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                SyncMessage::HeaderList(HeaderList::new(headers.clone()))
            );

            log::debug!("Expecting no further announcements for now");
            node.assert_no_event().await;
        }

        // Note: since best_sent_block_header is not taken into account by V1, this portion
        // of the test has to be disabled.
        if protocol_version >= SupportedProtocolVersion::V2.into() {
            // Do exactly the same as in the previous section; the expected result is the same as well.
            // The purpose of this is to ensure that the node correctly takes into account
            // headers that it has already sent (as opposed to what headers have been revealed
            // by the peer, which is checked by the previous section).
            let headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                0,
                2,
            )
            .await;

            log::debug!("Expecting second announcement");
            let (sent_to, message) = node.get_sent_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                SyncMessage::HeaderList(HeaderList::new(headers.clone()))
            );

            log::debug!("Expecting no further announcements for now");
            node.assert_no_event().await;
        }

        {
            // Create a better branch starting at genesis; it should be announced via a single
            // HeaderList message.
            let reorg_headers = make_new_top_blocks_return_headers(
                node.chainstate(),
                time_getter.get_time_getter(),
                &mut rng,
                5,
                6,
            )
            .await;

            log::debug!("Expecting third announcement");
            let (sent_to, message) = node.get_sent_message().await;
            assert_eq!(sent_to, peer.get_id());
            assert_eq!(
                message,
                SyncMessage::HeaderList(HeaderList::new(reorg_headers))
            );
        }

        node.assert_no_error().await;
        node.assert_no_peer_manager_event().await;

        node.join_subsystem_manager().await;
    })
    .await;
}
