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

//! Connection tests.

use std::{fmt::Debug, sync::Arc};

use p2p::testing_utils::TestTransport;
use p2p::{
    error::{DialError, P2pError},
    net::{ConnectivityService, NetworkingService, SyncingMessagingService},
};

tests![
    connect,
    #[cfg(not(target_os = "windows"))]
    connect_address_in_use,
    connect_accept,
];

async fn connect<A, S>()
where
    A: TestTransport<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    S::start(
        A::make_transport(),
        A::make_address(),
        config,
        Default::default(),
    )
    .await
    .unwrap();
}

// Check that connecting twice to the same address isn't possible.
// TODO: Investigate why this test fails on Windows.
#[cfg(not(target_os = "windows"))]
async fn connect_address_in_use<A, S>()
where
    A: TestTransport<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S> + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S> + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (connectivity, _sync) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    let address = connectivity.local_addr().await.unwrap().unwrap();
    let res = S::start(A::make_transport(), address, config, Default::default())
        .await
        .expect_err("address is not in use");
    assert_eq!(
        res,
        P2pError::DialError(DialError::IoError(std::io::ErrorKind::AddrInUse))
    );
}

// Try to connect two nodes by having `service1` listen for network events and having `service2`
// trying to connect to `service1`.
async fn connect_accept<A, S>()
where
    A: TestTransport<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + std::fmt::Debug + 'static,
    S::ConnectivityHandle: ConnectivityService<S>,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut service1, _) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();
    let (mut service2, _) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    let conn_addr = service1.local_addr().await.unwrap().unwrap();
    let (res1, res2) = tokio::join!(service1.poll_next(), service2.connect(conn_addr));
    res1.unwrap();
    res2.unwrap();
}
