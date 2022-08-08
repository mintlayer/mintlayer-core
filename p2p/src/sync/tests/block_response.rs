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

use super::*;
use chainstate::ChainstateError;
use common::chain::block::consensus_data::PoWData;
use p2p_test_utils::{make_libp2p_addr, TestBlockInfo};

// peer doesn't exist
#[tokio::test]
async fn peer_doesnt_exist() {
    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(make_libp2p_addr()).await;

    assert_eq!(
        mgr.validate_header_response(&PeerId::random(), vec![]).await,
        Err(P2pError::PeerError(PeerError::PeerDoesntExist)),
    );
}

// submit valid block but the peer is in invalid state
#[tokio::test]
async fn valid_block() {
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(make_libp2p_addr()).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        1,
    );
    let first = blocks[0].header().clone();
    mgr.peers
        .get_mut(&peer_id)
        .unwrap()
        .set_state(peer::PeerSyncState::UploadingBlocks(first.get_id()));

    assert_eq!(
        mgr.validate_block_response(&peer_id, blocks).await,
        Ok(None),
    );
}

// submit valid block
#[tokio::test]
async fn valid_block_invalid_state() {
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(make_libp2p_addr()).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        1,
    );

    assert_eq!(
        mgr.validate_block_response(&peer_id, blocks).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// submit the same block twice
#[tokio::test]
async fn valid_block_resubmitted_chainstate() {
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(make_libp2p_addr()).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        1,
    );
    let first = blocks[0].header().clone();
    mgr.peers
        .get_mut(&peer_id)
        .unwrap()
        .set_state(peer::PeerSyncState::UploadingBlocks(first.get_id()));

    assert_eq!(
        mgr.validate_block_response(&peer_id, blocks.clone()).await,
        Ok(None),
    );
    assert_eq!(
        mgr.validate_block_response(&peer_id, blocks).await,
        Ok(None),
    );
}

// block validation fails
#[tokio::test]
async fn invalid_block() {
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) =
        make_sync_manager::<Libp2pService>(make_libp2p_addr()).await;
    let peer_id = PeerId::random();
    mgr.register_peer(peer_id).await.unwrap();

    let mut blocks = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        1,
    );
    let first = blocks[0].header().clone();
    mgr.peers
        .get_mut(&peer_id)
        .unwrap()
        .set_state(peer::PeerSyncState::UploadingBlocks(first.get_id()));
    blocks[0].update_consensus_data(common::chain::block::ConsensusData::PoW(PoWData::new(
        common::primitives::Compact(1337),
        0,
    )));

    assert!(std::matches!(
        mgr.validate_block_response(&peer_id, blocks.clone()).await,
        Err(P2pError::ChainstateError(
            ChainstateError::ProcessBlockError(_)
        ))
    ));
}
