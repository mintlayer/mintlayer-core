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
use crate::net::mock::{
    transport::{ChannelMockTransport, TcpMockTransport},
    types::MockPeerId,
    MockService,
};
use p2p_test_utils::{MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress};

// handle peer reconnection
async fn test_peer_reconnected<A, P, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::random();

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(addr).await;
    register_peer(&mut mgr, peer_id).await;

    assert_eq!(mgr.peers.len(), 1);
    assert_eq!(
        mgr.register_peer(peer_id).await,
        Err(P2pError::PeerError(PeerError::PeerAlreadyExists))
    );
}

#[tokio::test]
async fn test_peer_reconnected_libp2p() {
    test_peer_reconnected::<MakeP2pAddress, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn test_peer_reconnected_mock_tcp() {
    test_peer_reconnected::<MakeTcpAddress, MockPeerId, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn test_peer_reconnected_mock_channels() {
    test_peer_reconnected::<MakeChannelAddress, MockPeerId, MockService<ChannelMockTransport>>()
        .await;
}

// handle peer disconnection event
async fn test_peer_disconnected<A, P, T>()
where
    A: MakeTestAddress<Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id1 = P::random();
    let peer_id2 = P::random();

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(addr).await;

    // send Connected event to SyncManager
    register_peer(&mut mgr, peer_id1).await;
    assert_eq!(mgr.peers.len(), 1);

    // no peer with this id exist, nothing happens
    mgr.unregister_peer(peer_id2);
    assert_eq!(mgr.peers.len(), 1);

    mgr.unregister_peer(peer_id1);
    assert!(mgr.peers.is_empty());
}

#[tokio::test]
async fn test_peer_disconnected_libp2p() {
    test_peer_disconnected::<MakeP2pAddress, PeerId, Libp2pService>().await;
}

#[tokio::test]
async fn test_peer_disconnected_mock_tcp() {
    test_peer_disconnected::<MakeTcpAddress, MockPeerId, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn test_peer_disconnected_mock_channels() {
    test_peer_disconnected::<MakeChannelAddress, MockPeerId, MockService<ChannelMockTransport>>()
        .await;
}
