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

use chainstate::{ban_score::BanScore, Locator};
use chainstate_test_framework::TestFramework;
use common::{
    chain::config::create_unit_test_config,
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use p2p_test_utils::P2pBasicTestTimeGetter;
use test_utils::random::Seed;

use crate::{
    config::P2pConfig,
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, HeaderList, HeaderListRequest, SyncMessage},
    protocol::ProtocolVersion,
    sync::tests::helpers::{make_new_blocks, TestNode},
    testing_utils::for_each_protocol_version,
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
        let block = tf.make_block_builder().build();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let headers = iter::repeat(block.get_id().into()).take(102).collect();
        peer.send_message(SyncMessage::HeaderListRequest(HeaderListRequest::new(
            Locator::new(headers),
        )))
        .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(0, 0)).ban_score()
        );
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
async fn valid_request(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        let block_index = tf.make_block_builder().build_and_process().unwrap().unwrap();
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

        peer.send_message(SyncMessage::HeaderListRequest(HeaderListRequest::new(
            locator,
        )))
        .await;

        let (sent_to, message) = node.get_sent_message().await;
        assert_eq!(peer.get_id(), sent_to);
        let headers = match message {
            SyncMessage::HeaderList(l) => l.into_headers(),
            m => panic!("Unexpected message: {m:?}"),
        };
        assert_eq!(headers.len(), 1);
        assert_eq!(&headers[0], block_index.block_header());
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// If the peer ignores our header requests, but asks us for blocks at the same time, we
// should not disconnect it (we assume it's in IBD).
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy(), ProtocolVersion::new(1))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_peer_to_ignore_header_requests_when_asking_for_blocks(
    #[case] seed: Seed,
    #[case] protocol_version: ProtocolVersion,
) {
    let mut rng = test_utils::random::make_seedable_rng(seed);
    let time_getter = P2pBasicTestTimeGetter::new();

    const STALLING_TIMEOUT: Duration = Duration::from_millis(500);
    const DELAY: Duration = Duration::from_millis(400);

    let chain_config = Arc::new(create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        // Note: max_request_blocks_count doesn't really matter here. But we'll be sending
        // one block at a time, so it's better to pretend that we do that because of the limit
        // (just in case it becomes important in the future, like it is for msg_header_count_limit).
        max_request_blocks_count: 1.into(),
        sync_stalling_timeout: STALLING_TIMEOUT.into(),

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
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        enable_block_relay_peers: Default::default(),
    });

    let blocks = make_new_blocks(
        &chain_config,
        None,
        &time_getter.get_time_getter(),
        3,
        &mut rng,
    );
    let headers = blocks.iter().map(|b| b.header().clone()).collect();

    let mut node = TestNode::builder(protocol_version)
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(blocks.clone())
        .build()
        .await;

    let peer = node.connect_peer(PeerId::new(), protocol_version).await;

    // Simulate the peer sending HeaderListRequest too.
    let locator = node.get_locator_from_height(0.into()).await;
    peer.send_message(SyncMessage::HeaderListRequest(HeaderListRequest::new(
        locator,
    )))
    .await;

    // The node should send the header list.
    assert_eq!(
        node.get_sent_message().await.1,
        SyncMessage::HeaderList(HeaderList::new(headers)),
    );

    // Now send each block after a delay.
    for block in blocks.into_iter() {
        time_getter.advance_time(DELAY);
        peer.send_message(SyncMessage::BlockListRequest(BlockListRequest::new(vec![
            block.get_id(),
        ])))
        .await;

        // Eventually, the total time passed will become bigger than the timeout. Still, the peer
        // shouldn't be disconnected because it's been asking for blocks.
        // Just in case, check that there were no peer manager events at all, not just disconnects.
        // Also, do it on every iteration to make the test fail faster.
        node.assert_no_peer_manager_event().await;

        // The node should send the block.
        assert_eq!(
            node.get_sent_message().await.1,
            SyncMessage::BlockResponse(BlockResponse::new(block)),
        );
    }

    node.assert_no_error().await;
    node.assert_no_peer_manager_event().await;
    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(ProtocolVersion::new(2))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_with_empty_header_list_when_in_ibd(#[case] protocol_version: ProtocolVersion) {
    let time_getter = P2pBasicTestTimeGetter::new();

    const STALLING_TIMEOUT: Duration = Duration::from_millis(500);

    let chain_config = Arc::new(create_unit_test_config());
    let p2p_config = Arc::new(P2pConfig {
        max_request_blocks_count: Default::default(),
        sync_stalling_timeout: STALLING_TIMEOUT.into(),

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
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        enable_block_relay_peers: Default::default(),
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
    peer.send_message(SyncMessage::HeaderListRequest(HeaderListRequest::new(
        locator,
    )))
    .await;

    // The node should send an empty header list.
    assert_eq!(
        node.get_sent_message().await.1,
        SyncMessage::HeaderList(HeaderList::new(Vec::new())),
    );

    node.assert_no_error().await;
    node.assert_no_peer_manager_event().await;
    node.join_subsystem_manager().await;
}
