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

use p2p::{
    error::{DialError, P2pError},
    net::{
        libp2p::Libp2pService,
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            MockService,
        },
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
};
use p2p_test_utils::{MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress};

async fn connect<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + std::fmt::Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    S::start(A::make_address(), config, Default::default()).await.unwrap();
}

#[tokio::test]
async fn connect_libp2p() {
    connect::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn connect_mock_tcp() {
    connect::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn connect_mock_channels() {
    connect::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

// Verify that binding to the same interface twice is not possible.
async fn connect_address_in_use<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + std::fmt::Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (connectivity, _sync) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();
    let address = connectivity.local_addr().await.unwrap().unwrap();

    let res = S::start(address, config, Default::default()).await;
    match res {
        Err(e) => {
            assert_eq!(
                e,
                P2pError::DialError(DialError::IoError(std::io::ErrorKind::AddrInUse))
            );
        }
        Ok(_) => panic!("address is not in use"),
    }
}

#[tokio::test]
async fn connect_address_in_use_libp2p() {
    connect_address_in_use::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn connect_address_in_use_mock_tcp() {
    connect_address_in_use::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn connect_address_in_use_mock_channels() {
    connect_address_in_use::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

// Try to connect two nodes together by having `service1` listen for network events and having
// `service2` trying to connect to `service1`.
async fn connect_accept<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + std::fmt::Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut service1, _) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();
    let (mut service2, _) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();

    let conn_addr = service1.local_addr().await.unwrap().unwrap();
    let (res1, res2) = tokio::join!(service1.poll_next(), service2.connect(conn_addr));
    assert!(res2.is_ok());
    assert!(res1.is_ok());
}

#[tokio::test]
async fn connect_accept_libp2p() {
    connect_accept::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn connect_accept_mock_tcp() {
    connect_accept::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn connect_accept_mock_channels() {
    connect_accept::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}
