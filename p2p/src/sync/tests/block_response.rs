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

use common::{chain::config::create_unit_test_config, primitives::Idable};
use p2p_test_utils::{create_block, create_n_blocks, TestBlockInfo};

use crate::{
    net::default_backend::types::PeerId,
    sync::{
        tests::helpers::SyncManagerHandle, Announcement, BlockListRequest, BlockResponse,
        HeaderListResponse, SyncMessage,
    },
};

// Messages from unknown peers are ignored.
#[tokio::test]
async fn nonexistent_peer() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();

    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    handle.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)));
}

#[tokio::test]
async fn unrequested_block() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    handle.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(score, 20);
}

#[tokio::test]
async fn valid_response() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let blocks = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        2,
    );
    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    let ids = blocks.iter().map(|b| b.get_id()).collect();
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(ids))
    );

    // First block.
    handle.send_message(
        peer,
        SyncMessage::BlockResponse(BlockResponse::new(blocks[0].clone())),
    );
    assert_eq!(
        handle.announcement().await,
        Announcement::Block(blocks[0].header().clone())
    );

    // Second block.
    handle.send_message(
        peer,
        SyncMessage::BlockResponse(BlockResponse::new(blocks[1].clone())),
    );
    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
    assert_eq!(
        handle.announcement().await,
        Announcement::Block(blocks[1].header().clone())
    );
}
