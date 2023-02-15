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
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        config::{create_unit_test_config, Builder as ChainConfigBuilder, ChainType},
        Block, NetUpgrades,
    },
    primitives::Idable,
};
use consensus::ConsensusVerificationError;
use p2p_test_utils::{create_block, create_n_blocks, TestBlockInfo};

use crate::{
    net::default_backend::types::PeerId,
    sync::{tests::helpers::SyncManagerHandle, Announcement, BlockListRequest, SyncMessage},
    P2pError,
};

// Announcements from unknown peers are ignored.
#[tokio::test]
async fn nonexistent_peer() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    handle.make_announcement(peer, Announcement::Block(block.header().clone()));
}

// The header list request is sent if the parent of the announced block is unknown.
#[tokio::test]
async fn unknown_prev_block() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let blocks = create_n_blocks(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
        2,
    );
    handle.make_announcement(peer, Announcement::Block(blocks[1].header().clone()));

    let (sent_to, message) = handle.message().await;
    assert_eq!(sent_to, peer);
    assert!(matches!(message, SyncMessage::HeaderListRequest(_)));
}

// The peer ban score is increased if it sends an invalid header.
#[tokio::test]
async fn invalid_timestamp() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let block = Block::new(
        Vec::new(),
        chain_config.genesis_block_id(),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    handle.make_announcement(peer, Announcement::Block(block.header().clone()));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ChainstateError(ChainstateError::ProcessBlockError(
            BlockError::CheckBlockFailed(CheckBlockError::BlockTimeOrderInvalid),
        ))
        .ban_score()
    );
}

// The peer ban score is increased if it sends an invalid header.
#[tokio::test]
async fn invalid_consensus_data() {
    let chain_config = Arc::new(
        ChainConfigBuilder::new(ChainType::Mainnet)
            // Enable consensus, so blocks with `ConsensusData::None` would be rejected.
            .net_upgrades(NetUpgrades::new(ChainType::Mainnet))
            .build(),
    );
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let block = Block::new(
        Vec::new(),
        chain_config.genesis_block_id(),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    handle.make_announcement(peer, Announcement::Block(block.header().clone()));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
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
}

#[tokio::test]
async fn valid_block() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::with_config(Arc::clone(&chain_config)).await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let block = create_block(
        Arc::clone(&chain_config),
        TestBlockInfo::from_genesis(chain_config.genesis_block()),
    );
    handle.make_announcement(peer, Announcement::Block(block.header().clone()));

    let (sent_to, message) = handle.message().await;
    assert_eq!(sent_to, peer);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
    );
}
