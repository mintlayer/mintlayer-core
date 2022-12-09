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

use crypto::random::{Rng, SliceRandom};
use libp2p::PeerId;

use crate::testing_utils::{
    TestTransportChannel, TestTransportLibp2p, TestTransportMaker, TestTransportNoise,
    TestTransportTcp,
};
use p2p_test_utils::TestBlockInfo;

use crate::{
    error::{P2pError, PeerError, ProtocolError},
    net::{
        libp2p::Libp2pService,
        mock::{
            transport::{MockChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            types::MockPeerId,
            MockService,
        },
    },
    sync::{
        peer,
        tests::{make_sync_manager, register_peer, MakeTestPeerId},
    },
    ConnectivityService, NetworkingService, SyncingMessagingService,
};

// response contains more than 2000 headers
async fn too_many_headers<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let config = Arc::new(common::chain::config::create_unit_test_config());
    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
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

#[tokio::test]
async fn too_many_headers_libp2p() {
    too_many_headers::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn too_many_headers_mock_tcp() {
    too_many_headers::<TestTransportTcp, MockPeerId, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn too_many_headers_mock_channels() {
    too_many_headers::<TestTransportChannel, MockPeerId, MockService<MockChannelTransport>>().await;
}

#[tokio::test]
async fn too_many_headers_mock_noise() {
    too_many_headers::<TestTransportNoise, MockPeerId, MockService<NoiseTcpTransport>>().await;
}

// header response is empty
async fn empty_response<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
    register_peer(&mut mgr, peer_id).await;

    assert_eq!(
        mgr.validate_header_response(&peer_id, vec![]).await,
        Ok(None),
    );
}

#[tokio::test]
async fn empty_response_libp2p() {
    empty_response::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn empty_response_mock_tcp() {
    empty_response::<TestTransportTcp, MockPeerId, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn empty_response_mock_channels() {
    empty_response::<TestTransportChannel, MockPeerId, MockService<MockChannelTransport>>().await;
}

#[tokio::test]
async fn empty_response_mock_noise() {
    empty_response::<TestTransportNoise, MockPeerId, MockService<NoiseTcpTransport>>().await;
}

// valid response with headers in order and the first header attaching to local chain
async fn valid_response<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
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

#[tokio::test]
async fn valid_response_libp2p() {
    valid_response::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn valid_response_mock_tcp() {
    valid_response::<TestTransportTcp, MockPeerId, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn valid_response_mock_channles() {
    valid_response::<TestTransportChannel, MockPeerId, MockService<MockChannelTransport>>().await;
}

#[tokio::test]
async fn valid_response_mock_noise() {
    valid_response::<TestTransportNoise, MockPeerId, MockService<NoiseTcpTransport>>().await;
}

// the first header doesn't attach to local chain
async fn header_doesnt_attach_to_local_chain<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
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

#[tokio::test]
async fn header_doesnt_attach_to_local_chain_libp2p() {
    header_doesnt_attach_to_local_chain::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn header_doesnt_attach_to_local_chain_mock_tcp() {
    header_doesnt_attach_to_local_chain::<
        TestTransportTcp,
        MockPeerId,
        MockService<TcpTransportSocket>,
    >()
    .await;
}

#[tokio::test]
async fn header_doesnt_attach_to_local_chain_mock_channel() {
    header_doesnt_attach_to_local_chain::<
        TestTransportChannel,
        MockPeerId,
        MockService<MockChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn header_doesnt_attach_to_local_chain_mock_noise() {
    header_doesnt_attach_to_local_chain::<
        TestTransportNoise,
        MockPeerId,
        MockService<NoiseTcpTransport>,
    >()
    .await;
}

// valid headers but they are not in order
async fn headers_not_in_order<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
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

#[tokio::test]
async fn headers_not_in_order_libp2p() {
    headers_not_in_order::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn headers_not_in_order_mock_tcp() {
    headers_not_in_order::<TestTransportTcp, MockPeerId, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn headers_not_in_order_mock_channels() {
    headers_not_in_order::<TestTransportChannel, MockPeerId, MockService<MockChannelTransport>>()
        .await;
}

#[tokio::test]
async fn headers_not_in_order_mock_noise() {
    headers_not_in_order::<TestTransportNoise, MockPeerId, MockService<NoiseTcpTransport>>().await;
}

// peer state is incorrect to be sending header responses
async fn invalid_state<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let mut rng = crypto::random::make_pseudo_rng();
    let config = Arc::new(common::chain::config::create_unit_test_config());

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
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

#[tokio::test]
async fn invalid_state_libp2p() {
    invalid_state::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn invalid_state_mock_tcp() {
    invalid_state::<TestTransportTcp, MockPeerId, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn invalid_state_mock_channels() {
    invalid_state::<TestTransportChannel, MockPeerId, MockService<MockChannelTransport>>().await;
}

#[tokio::test]
async fn invalid_state_mock_noise() {
    invalid_state::<TestTransportNoise, MockPeerId, MockService<NoiseTcpTransport>>().await;
}

// peer doesn't exist
async fn peer_doesnt_exist<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;

    assert_eq!(
        mgr.validate_header_response(&peer_id, vec![]).await,
        Err(P2pError::PeerError(PeerError::PeerDoesntExist)),
    );
}

#[tokio::test]
async fn peer_doesnt_exist_libp2p() {
    peer_doesnt_exist::<TestTransportLibp2p, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn peer_doesnt_exist_mock_tcp() {
    peer_doesnt_exist::<TestTransportTcp, MockPeerId, MockService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn peer_doesnt_exist_mock_channels() {
    peer_doesnt_exist::<TestTransportChannel, MockPeerId, MockService<MockChannelTransport>>()
        .await;
}

#[tokio::test]
async fn peer_doesnt_exist_mock_noise() {
    peer_doesnt_exist::<TestTransportNoise, MockPeerId, MockService<NoiseTcpTransport>>().await;
}
