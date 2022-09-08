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
use crate::net::mock::{types::MockPeerId, MockService};
use chainstate::ChainstateError;
use common::chain::block::consensus_data::PoWData;
use p2p_test_utils::{
    MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress, TestBlockInfo,
};

// peer doesn't exist
async fn peer_doesnt_exist<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;

    assert_eq!(
        mgr.validate_header_response(&peer_id, vec![]).await,
        Err(P2pError::PeerError(PeerError::PeerDoesntExist)),
    );
}

// // TODO: FIXME:
// #[tokio::test]
// async fn peer_doesnt_exist_libp2p() {
//     peer_doesnt_exist::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn peer_doesnt_exist_mock() {
    peer_doesnt_exist::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// submit valid block but the peer is in invalid state
async fn valid_block<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

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

// #[tokio::test]
// async fn valid_block_libp2p() {
//     valid_block::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn valid_block_mock() {
    valid_block::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// submit valid block
async fn valid_block_invalid_state<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

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

// #[tokio::test]
// async fn valid_block_invalid_state_libp2p() {
//     valid_block_invalid_state::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn valid_block_invalid_state_mock() {
    valid_block_invalid_state::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// submit the same block twice
async fn valid_block_resubmitted_chainstate<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

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

// #[tokio::test]
// async fn valid_block_resubmitted_chainstate_libp2p() {
//     valid_block_resubmitted_chainstate::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn valid_block_resubmitted_chainstate_mock() {
    valid_block_resubmitted_chainstate::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// block validation fails
async fn invalid_block<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

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

// #[tokio::test]
// async fn invalid_block_libp2p() {
//     invalid_block::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn invalid_block_mock() {
    invalid_block::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}
