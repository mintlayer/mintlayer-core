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

use chainstate::ban_score::BanScore;
use common::{chain::config::create_unit_test_config, primitives::Idable};
use crypto::random::Rng;
use p2p_test_utils::{
    create_block, create_n_blocks, import_blocks, start_chainstate, TestBlockInfo,
};
use test_utils::random::Seed;

use crate::{
    error::ProtocolError,
    sync::{tests::helpers::SyncManagerHandle, BlockListRequest, BlockResponse, SyncMessage},
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

// Messages from unknown peers are ignored.
#[tokio::test]
async fn nonexistent_peer() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();
    handle.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(Vec::new())),
    );

    handle.assert_no_error().await;
    handle.assert_no_peer_manager_event().await;
}

#[tokio::test]
async fn max_block_count_in_request_exceeded() {
    let p2p_config = Arc::new(P2pConfig::default());
    let chain_config = Arc::new(create_unit_test_config());
    let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
    // Import a block to finish the initial block download.
    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    import_blocks(&chainstate, vec![block.clone()]).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(chainstate)
        .with_p2p_config(Arc::clone(&p2p_config))
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let blocks = iter::repeat(block.get_id())
        .take(*p2p_config.max_request_blocks_count + 1)
        .collect();
    handle.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(blocks)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::BlocksRequestLimitExceeded(0, 0)).ban_score()
    );
    handle.assert_no_event().await;
}

#[tokio::test]
async fn unknown_blocks() {
    let chain_config = Arc::new(create_unit_test_config());
    let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
    // Import a block to finish the initial block download.
    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    import_blocks(&chainstate, vec![block.clone()]).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_chainstate(chainstate)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let unknown_blocks = create_n_blocks(chain_config, TestBlockInfo::from_block(&block), 2)
        .into_iter()
        .map(|b| b.get_id())
        .collect();
    handle.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(unknown_blocks)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::UnknownBlockRequested).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn valid_request(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
    // Import several blocks.
    let num_blocks = rng.gen_range(2..10);
    let blocks = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        num_blocks,
    );
    import_blocks(&chainstate, blocks.clone()).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(chainstate)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let ids = blocks.iter().map(|b| b.get_id()).collect();
    handle.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(ids)),
    );

    for block in blocks {
        let (sent_to, message) = handle.message().await;
        assert_eq!(peer, sent_to);
        assert_eq!(
            message,
            SyncMessage::BlockResponse(BlockResponse::new(block))
        );
    }

    handle.assert_no_error().await;
    handle.assert_no_peer_manager_event().await;
}
