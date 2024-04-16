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

use std::{fmt::Debug, sync::Arc, time::Duration};

use common::time_getter::TimeGetter;
use tokio::{
    sync::{
        mpsc::{self, error::TryRecvError},
        oneshot,
    },
    time::timeout,
};

use networking::test_helpers::TestTransportMaker;
use p2p::{
    net::{
        types::services::Service, ConnectivityService, MessagingService, NetworkingService,
        SyncingEventReceiver,
    },
    test_helpers::{connect_and_accept_services, test_p2p_config},
    P2pEvent,
};
use utils::atomics::SeqCstAtomicBool;

tests![peer_events,];

#[allow(clippy::extra_unused_type_parameters)]
#[tracing::instrument]
async fn peer_events<T, N>()
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
    let (subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let time_getter = TimeGetter::default();
    let (mut service1, _, _sync, _) = N::start(
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

    let (events_sender, mut events_receiver) = mpsc::unbounded_channel();
    let handler = Arc::new(move |event| {
        events_sender.send(event).unwrap();
    });
    assert!(subscribers_sender.send(handler).is_ok());

    let (shutdown_sender_2, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut service2, _, _sync, _) = N::start(
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

    assert_eq!(events_receiver.try_recv(), Err(TryRecvError::Empty));
    let (_, _, info) = connect_and_accept_services::<N>(&mut service1, &mut service2).await;

    match timeout(Duration::from_secs(5), events_receiver.recv()).await.unwrap() {
        Some(P2pEvent::PeerConnected {
            id,
            services,
            address: _,
            inbound: _,
            user_agent: _,
            software_version: _,
        }) => {
            assert_eq!(id, info.peer_id);
            assert_eq!(
                services,
                [Service::Transactions, Service::Blocks, Service::PeerAddresses].as_ref().into()
            );
        }
        res => panic!("unexpected result: {res:?}"),
    }

    service1.disconnect(info.peer_id, None).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), events_receiver.recv()).await.unwrap(),
        Some(P2pEvent::PeerDisconnected(info.peer_id))
    );

    shutdown.store(true);
    let _ = shutdown_sender_2.send(());
    let _ = shutdown_sender_1.send(());
}
