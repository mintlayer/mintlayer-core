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
    primitives::Idable,
};
use consensus::ConsensusVerificationError;
use test_utils::random::Seed;

use crate::{
    config::P2pConfig,
    error::ProtocolError,
    message::{BlockListRequest, HeaderList, SyncMessage},
    sync::tests::helpers::TestNode,
    types::peer_id::PeerId,
    P2pError,
};

// The header list request is sent if the parent of the singular announced block is unknown.
// However, if max_singular_unconnected_headers is exceeded, the DisconnectedHeaders error
// is generated.
// Note: this is a legacy behavior that will be removed in the protocol v2.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_header_with_unknown_prev_block(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block_1 = tf.make_block_builder().build();
    let block_2 = tf.make_block_builder().with_parent(block_1.get_id().into()).build();

    let p2p_config = Arc::new(P2pConfig {
        max_singular_unconnected_headers: 1.into(),
        ..P2pConfig::default()
    });

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    // The first attempt to send an unconnected header should trigger HeaderListRequest.
    node.send_headers(peer, vec![block_2.header().clone()]).await;

    // Note: we call assert_no_peer_manager_event twice; the last call is needed to make sure
    // that the event is caught even if it's late; the first one just allows the test to fail
    // faster if the event is not late.
    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.message().await;
    assert_eq!(sent_to, peer);
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    node.assert_no_peer_manager_event().await;

    // The second attempt to send an unconnected header should increase the ban score.
    node.send_headers(peer, vec![block_2.header().clone()]).await;

    node.assert_peer_score_adjustment(
        peer,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
    )
    .await;
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

// Same as single_header_with_unknown_prev_block, but here a connected header list is sent
// in between the two attempts to send unconnected ones.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_header_with_unknown_prev_block_with_intermittent_connected_headers(
    #[case] seed: Seed,
) {
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
        ..P2pConfig::default()
    });

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    // The first attempt to send an unconnected header should trigger HeaderListRequest.
    node.send_headers(peer, vec![block_2.header().clone()]).await;

    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.message().await;
    assert_eq!(sent_to, peer);
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    node.assert_no_peer_manager_event().await;

    // Send a header with a known parent, the node should ask for blocks
    node.send_headers(peer, vec![block_11.header().clone()]).await;

    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.message().await;
    assert_eq!(sent_to, peer);
    assert!(matches!(message, SyncMessage::BlockListRequest(_)));
    node.assert_no_peer_manager_event().await;

    // The second attempt to send an unconnected header should again trigger HeaderListRequest,
    // because a correct header list message was received between the attempts and the counter
    // for the unconnected headers has been reset.
    node.send_headers(peer, vec![block_2.header().clone()]).await;

    node.assert_no_peer_manager_event().await;
    let (sent_to, message) = node.message().await;
    assert_eq!(sent_to, peer);
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    node.assert_no_peer_manager_event().await;

    node.join_subsystem_manager().await;
}

// The peer ban score is increased if it sends an invalid header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_timestamp() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut node = TestNode::builder().with_chain_config(Arc::clone(&chain_config)).build().await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let block = Block::new(
        Vec::new(),
        chain_config.genesis_block_id(),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    node.send_message(
        peer,
        SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
    )
    .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
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
}

// The peer ban score is increased if it sends an invalid header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_consensus_data() {
    let chain_config = Arc::new(
        ChainConfigBuilder::new(ChainType::Mainnet)
            // Enable consensus, so blocks with `ConsensusData::None` would be rejected.
            .net_upgrades(NetUpgrades::new(ChainType::Mainnet))
            .build(),
    );
    let mut node = TestNode::builder().with_chain_config(Arc::clone(&chain_config)).build().await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let block = Block::new(
        Vec::new(),
        chain_config.genesis_block_id(),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    node.send_message(
        peer,
        SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
    )
    .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
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
}

// The peer ban score is increased if the parent of the first announced block is unknown.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_headers_with_unknown_prev_block(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let orphan_block1 = tf.make_block_builder().with_parent(block.get_id().into()).build();
    let orphan_block2 = tf.make_block_builder().with_parent(orphan_block1.get_id().into()).build();

    let mut node = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_headers(
        peer,
        vec![orphan_block1.header().clone(), orphan_block2.header().clone()],
    )
    .await;

    node.assert_peer_score_adjustment(
        peer,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score(),
    )
    .await;
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_block(#[case] seed: Seed) {
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

    node.send_message(
        peer,
        SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
    )
    .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(sent_to, peer);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
    );
    node.assert_no_error().await;

    node.join_subsystem_manager().await;
}
