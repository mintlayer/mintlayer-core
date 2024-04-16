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

use tokio::sync::{mpsc, oneshot};

use common::time_getter::TimeGetter;
use networking::{error::NetworkingError, test_helpers::TestTransportMaker};
use p2p::{
    error::P2pError,
    net::{ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver},
    test_helpers::test_p2p_config,
};
use test_utils::assert_matches;
use utils::atomics::SeqCstAtomicBool;

tests![connect, connect_address_in_use, connect_accept,];

#[allow(clippy::extra_unused_type_parameters)]
#[tracing::instrument]
async fn connect<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N>,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let time_getter = TimeGetter::default();
    N::start(
        true,
        T::make_transport(),
        vec![T::make_address().into()],
        config,
        p2p_config,
        time_getter,
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    shutdown.store(true);
    let _ = shutdown_sender.send(());
}

// Check that connecting twice to the same address isn't possible.
#[allow(clippy::extra_unused_type_parameters)]
#[tracing::instrument]
async fn connect_address_in_use<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N> + Debug,
    N::MessagingHandle: MessagingService + Debug,
    N::SyncingEventReceiver: SyncingEventReceiver + Debug,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender_1, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let time_getter = TimeGetter::default();
    let (connectivity, _messaging_handle, _sync, _) = N::start(
        true,
        T::make_transport(),
        vec![T::make_address().into()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let addresses = connectivity.local_addresses().to_vec();
    let (shutdown_sender_2, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let res = N::start(
        true,
        T::make_transport(),
        addresses,
        config,
        Arc::clone(&p2p_config),
        time_getter,
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .expect_err("address is not in use");
    assert_matches!(
        res,
        P2pError::NetworkingError(NetworkingError::IoError(
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable
        ))
    );

    shutdown.store(true);
    let _ = shutdown_sender_2.send(());
    let _ = shutdown_sender_1.send(());
}

// Try to connect two nodes by having `service1` listen for network events and having `service2`
// trying to connect to `service1`.
#[allow(clippy::extra_unused_type_parameters)]
#[tracing::instrument]
async fn connect_accept<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N>,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
{
    let config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender_1, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let time_getter = TimeGetter::default();
    let (mut service1, _, _, _) = N::start(
        true,
        T::make_transport(),
        vec![T::make_address().into()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (shutdown_sender_2, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut service2, _, _, _) = N::start(
        true,
        T::make_transport(),
        vec![T::make_address().into()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let conn_addr = service1.local_addresses().to_vec();
    service2.connect(conn_addr[0], None).unwrap();
    service1.poll_next().await.unwrap();

    shutdown.store(true);
    let _ = shutdown_sender_2.send(());
    let _ = shutdown_sender_1.send(());
}
