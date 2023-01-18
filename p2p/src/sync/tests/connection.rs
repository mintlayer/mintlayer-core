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

use crate::testing_utils::{
    TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
};

use crate::{
    error::{P2pError, PeerError},
    net::default_backend::{
        transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
        types::PeerId,
        DefaultNetworkingService,
    },
    sync::tests::{make_sync_manager, register_peer, MakeTestPeerId},
    ConnectivityService, NetworkingService, SyncingMessagingService,
};

// handle peer reconnection
async fn test_peer_reconnected<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id = P::new();

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;
    register_peer(&mut mgr, peer_id).await;

    assert_eq!(mgr.peers.len(), 1);
    assert_eq!(
        mgr.register_peer(peer_id).await,
        Err(P2pError::PeerError(PeerError::PeerAlreadyExists))
    );
}

#[tokio::test]
async fn test_peer_reconnected_tcp() {
    test_peer_reconnected::<TestTransportTcp, PeerId, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn test_peer_reconnected_channels() {
    test_peer_reconnected::<
        TestTransportChannel,
        PeerId,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn test_peer_reconnected_noise() {
    test_peer_reconnected::<TestTransportNoise, PeerId, DefaultNetworkingService<NoiseTcpTransport>>().await;
}

// handle peer disconnection event
async fn test_peer_disconnected<A, P, T>()
where
    A: TestTransportMaker<Transport = T::Transport, Address = T::Address>,
    P: MakeTestPeerId<PeerId = T::PeerId>,
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
    T::SyncingMessagingHandle: SyncingMessagingService<T>,
{
    let addr = A::make_address();
    let peer_id1 = P::new();
    let peer_id2 = P::new();

    let (mut mgr, _conn, _sync, _pm) = make_sync_manager::<T>(A::make_transport(), addr).await;

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
async fn test_peer_disconnected_tcp() {
    test_peer_disconnected::<TestTransportTcp, PeerId, DefaultNetworkingService<TcpTransportSocket>>().await;
}

#[tokio::test]
async fn test_peer_disconnected_channels() {
    test_peer_disconnected::<
        TestTransportChannel,
        PeerId,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[tokio::test]
async fn test_peer_disconnected_noise() {
    test_peer_disconnected::<TestTransportNoise, PeerId, DefaultNetworkingService<NoiseTcpTransport>>().await;
}
