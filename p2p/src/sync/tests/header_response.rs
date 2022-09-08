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
use crypto::random::{Rng, SliceRandom};
use p2p_test_utils::{
    MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress, TestBlockInfo,
};

// response contains more than 2000 headers
async fn too_many_headers<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    let headers = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        2001,
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers,).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// #[tokio::test]
// async fn too_many_headers_libp2p() {
//     too_many_headers::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn too_many_headers_mock() {
    too_many_headers::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// header response is empty
async fn empty_response<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    assert_eq!(
        mgr.validate_header_response(&peer_id, vec![]).await,
        Ok(None),
    );
}

// #[tokio::test]
// async fn empty_response_libp2p() {
//     empty_response::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn empty_response_mock() {
    empty_response::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// valid response with headers in order and the first header attaching to local chain
async fn valid_response<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    let headers = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        rng.gen_range(1..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();
    let first = headers[0].clone();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers).await,
        Ok(Some(first)),
    );
}

// #[tokio::test]
// async fn valid_response_libp2p() {
//     valid_response::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn valid_response_mock() {
    valid_response::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// the first header doesn't attach to local chain
async fn header_doesnt_attach_to_local_chain<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    let headers = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        rng.gen_range(2..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers[1..].to_vec()).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// #[tokio::test]
// async fn header_doesnt_attach_to_local_chain_libp2p() {
//     header_doesnt_attach_to_local_chain::<Libp2pService>(make_libp2p_addr(), PeerId::random())
//         .await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn header_doesnt_attach_to_local_chain_mock() {
    header_doesnt_attach_to_local_chain::<MockService>(make_mock_addr(), MockPeerId::random())
        .await;
}

// valid headers but they are not in order
async fn headers_not_in_order<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    let mut headers = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        rng.gen_range(5..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();
    headers.shuffle(&mut rng);

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers[1..].to_vec(),).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// #[tokio::test]
// async fn headers_not_in_order_libp2p() {
//     headers_not_in_order::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn headers_not_in_order_mock() {
    headers_not_in_order::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

// peer state is incorrect to be sending header responses
async fn invalid_state<T>(addr: T::Address, peer_id: T::PeerId)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pubsub, _swarm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    mgr.peers.get_mut(&peer_id).unwrap().set_state(peer::PeerSyncState::Unknown);

    let headers = p2p_test_utils::create_n_blocks(
        Arc::clone(&config),
        TestBlockInfo::from_genesis(config.genesis_block()),
        rng.gen_range(1..100),
    )
    .iter()
    .map(|block| block.header().clone())
    .collect::<Vec<_>>();

    assert_eq!(
        mgr.validate_header_response(&peer_id, headers,).await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage)),
    );
}

// #[tokio::test]
// async fn invalid_state_libp2p() {
//     invalid_state::<Libp2pService>(make_libp2p_addr(), PeerId::random()).await;
// }

// TODO: fix https://github.com/mintlayer/mintlayer-core/issues/375
#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn invalid_state_mock() {
    invalid_state::<MockService>(make_mock_addr(), MockPeerId::random()).await;
}

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
