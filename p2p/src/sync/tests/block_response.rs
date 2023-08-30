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

use std::{sync::Arc, time::Duration};

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{
    chain::config::create_unit_test_config,
    primitives::{user_agent::mintlayer_core_user_agent, Idable},
};
use crypto::random::Rng;
use p2p_test_utils::create_n_blocks;
use p2p_test_utils::P2pBasicTestTimeGetter;
use test_utils::random::Seed;

use crate::{
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, HeaderList, HeaderListRequest, SyncMessage},
    sync::tests::helpers::{make_new_blocks, make_new_top_blocks_return_headers, TestNode},
    testing_utils::test_p2p_config,
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrequested_block(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)))
        .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned())).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_response(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let num_blocks = rng.gen_range(2..10);
    let blocks = create_n_blocks(&mut tf, num_blocks);

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    node.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers))).await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    let ids = blocks.iter().map(|b| b.get_id()).collect();
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(ids))
    );

    for block in blocks.into_iter() {
        node.send_message(
            peer,
            SyncMessage::BlockResponse(BlockResponse::new(block.clone())),
        )
        .await;
    }

    // A peer would request headers after the last block.
    assert!(matches!(
        node.message().await.1,
        SyncMessage::HeaderListRequest(HeaderListRequest { .. })
    ));

    node.assert_no_error().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect(#[case] seed: Seed) {
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
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        block_relay_peer_count: Default::default(),
    });
    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_message(
        peer,
        SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
    )
    .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    node.assert_disconnect_peer_event(peer).await;

    node.join_subsystem_manager().await;
}

// Respond to a block request with a delay that is only slightly less than the timeout.
// Then respond to the following HeaderListRequest with the same delay.
// The peer should not be disconnected.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_response(#[case] seed: Seed) {
    logging::init_logging::<&std::path::Path>(None);

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
        max_singular_unconnected_headers: Default::default(),
        block_relay_peer_count: Default::default(),
    });

    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().with_parent(chain_config.genesis_block_id()).build();

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_message(
        peer,
        SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
    )
    .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
    );

    time_getter.advance_time(DELAY);

    node.send_message(
        peer,
        SyncMessage::BlockResponse(BlockResponse::new(block.clone())),
    )
    .await;

    assert!(matches!(
        node.message().await.1,
        SyncMessage::HeaderListRequest(HeaderListRequest { .. })
    ));

    time_getter.advance_time(DELAY);

    node.send_message(peer, SyncMessage::HeaderList(HeaderList::new(Vec::new())))
        .await;

    node.assert_no_error().await;
    // Just in case, check that there were no peer manager events at all, not just disconnects.
    node.assert_no_peer_manager_event().await;

    node.join_subsystem_manager().await;
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
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidated_block(#[case] seed: Seed) {
    logging::init_logging::<&std::path::Path>(None);

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

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(p2p_config)
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(initial_blocks.clone())
        .build()
        .await;

    let peer = PeerId::new();
    // Connect to the peer and check that HeaderListRequest is sent to it.
    node.connect_peer(peer).await;

    // Receive HeaderListRequest from the peer.
    let peers_locator = node.get_locator_from_height(0.into()).await;
    node.send_message(
        peer,
        SyncMessage::HeaderListRequest(HeaderListRequest::new(peers_locator)),
    )
    .await;

    // The node sends HeaderList.
    let initial_blocks_headers = initial_blocks.iter().map(|b| b.header().clone()).collect();
    assert_eq!(
        node.message().await.1,
        SyncMessage::HeaderList(HeaderList::new(initial_blocks_headers))
    );

    // Receive BlockListRequest from the peer.
    let initial_blocks_ids = initial_blocks.iter().map(|b| b.get_id()).collect();
    node.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(initial_blocks_ids)),
    )
    .await;

    // The node sends block responses.
    assert_eq!(
        node.message().await.1,
        SyncMessage::BlockResponse(BlockResponse::new(initial_blocks[0].clone()))
    );
    assert_eq!(
        node.message().await.1,
        SyncMessage::BlockResponse(BlockResponse::new(initial_blocks[1].clone()))
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
        node.message().await.1,
        SyncMessage::HeaderList(HeaderList::new(vec![new_header.clone()]))
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
    node.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(vec![new_header.block_id()])),
    )
    .await;

    node.assert_no_error().await;

    node.join_subsystem_manager().await;
}
