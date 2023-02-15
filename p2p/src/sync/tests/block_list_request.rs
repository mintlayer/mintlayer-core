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

use common::{chain::config::create_unit_test_config, primitives::Idable};
use p2p_test_utils::{
    create_block, create_n_blocks, import_blocks, start_chainstate, TestBlockInfo,
};

use crate::{
    net::default_backend::types::PeerId,
    sync::{tests::helpers::SyncManagerHandle, BlockListRequest, BlockResponse, SyncMessage},
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
}

#[tokio::test]
async fn max_block_exceeded() {
    let chain_config = Arc::new(create_unit_test_config());
    let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
    // Import a block to finish the initial block download.
    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    import_blocks(&chainstate, vec![block.clone()]).await;

    let mut handle =
        SyncManagerHandle::with_chainstate_and_config(Arc::clone(&chain_config), chainstate).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let blocks = iter::repeat(block.get_id()).take(501).collect();
    handle.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(blocks)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(score, 20);
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

    let mut handle =
        SyncManagerHandle::with_chainstate_and_config(Arc::clone(&chain_config), chainstate).await;

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
    assert_eq!(score, 20);
}

#[tokio::test]
async fn valid_request() {
    let chain_config = Arc::new(create_unit_test_config());
    let chainstate = start_chainstate(Arc::clone(&chain_config)).await;
    // Import several blocks.
    let blocks = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        2,
    );
    import_blocks(&chainstate, blocks.clone()).await;

    let mut handle =
        SyncManagerHandle::with_chainstate_and_config(Arc::clone(&chain_config), chainstate).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let ids = blocks.iter().map(|b| b.get_id()).collect();
    handle.send_message(
        peer,
        SyncMessage::BlockListRequest(BlockListRequest::new(ids)),
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockResponse(BlockResponse::new(blocks[0].clone()))
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockResponse(BlockResponse::new(blocks[1].clone()))
    );
}
