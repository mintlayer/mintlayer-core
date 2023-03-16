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

use p2p::testing_utils::{test_p2p_config, TestTransportMaker};
use p2p::{
    error::{DialError, P2pError},
    net::{ConnectivityService, NetworkingService, SyncingMessagingService},
};

tests![connect, connect_address_in_use, connect_accept,];

async fn connect<T, N, A>()
where
    T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N>,
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    N::start(
        T::make_transport(),
        vec![T::make_address()],
        config,
        p2p_config,
    )
    .await
    .unwrap();
}

// Check that connecting twice to the same address isn't possible.
async fn connect_address_in_use<T, N, A>()
where
    T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N> + Debug,
    N::SyncingMessagingHandle: SyncingMessagingService<N> + Debug,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (connectivity, _sync) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let addresses = connectivity.local_addresses().to_vec();
    let res = N::start(
        T::make_transport(),
        addresses,
        config,
        Arc::clone(&p2p_config),
    )
    .await
    .expect_err("address is not in use");
    assert!(matches!(
        res,
        P2pError::DialError(DialError::IoError(
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable
        ))
    ));
}

// Try to connect two nodes by having `service1` listen for network events and having `service2`
// trying to connect to `service1`.
async fn connect_accept<T, N, A>()
where
    T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
    N: NetworkingService + std::fmt::Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N>,
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (mut service1, _) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();
    let (mut service2, _) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();

    let conn_addr = service1.local_addresses().to_vec();
    service2.connect(conn_addr[0].clone()).unwrap();
    service1.poll_next().await.unwrap();
}
