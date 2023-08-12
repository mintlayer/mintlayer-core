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

use std::{fmt::Debug, sync::Arc};

use tokio::sync::{mpsc, oneshot};

use common::{
    chain::block::{consensus_data::ConsensusData, timestamp::BlockTimestamp, Block, BlockReward},
    primitives::{Id, H256},
    time_getter::TimeGetter,
};
use p2p::{
    config::{NodeType, P2pConfig},
    message::{HeaderList, SyncMessage},
    net::{
        types::SyncingEvent, ConnectivityService, MessagingService, NetworkingService,
        SyncingEventReceiver,
    },
    testing_utils::{connect_and_accept_services, test_p2p_config, TestTransportMaker},
};
use utils::atomics::SeqCstAtomicBool;

tests![block_announcement, block_announcement_no_subscription,];

#[allow(clippy::extra_unused_type_parameters)]
async fn block_announcement<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender_1, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let time_getter = TimeGetter::default();
    let (mut conn1, mut messaging_handle1, mut sync1, _) = N::start(
        T::make_transport(),
        vec![T::make_address()],
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
    let (mut conn2, mut messaging_handle2, mut sync2, _) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        time_getter,
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_, peer1, peer2) = connect_and_accept_services::<N>(&mut conn1, &mut conn2).await;

    let block = Block::new(
        vec![],
        Id::new(H256([0x01; 32])),
        BlockTimestamp::from_int_seconds(1337u64),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    messaging_handle1
        .send_message(
            peer2.peer_id,
            SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
        )
        .unwrap();

    let mut sync_rx_2 = match sync2.poll_next().await.unwrap() {
        SyncingEvent::Connected {
            peer_id: _,
            services: _,
            sync_rx,
        } => sync_rx,
        event => panic!("Unexpected event: {event:?}"),
    };

    // Poll an event from the network for server2.
    let header = match sync_rx_2.recv().await.unwrap() {
        SyncMessage::HeaderList(l) => {
            assert_eq!(l.headers().len(), 1);
            l.into_headers().pop().unwrap()
        }
        a => panic!("Unexpected announcement: {a:?}"),
    };
    assert_eq!(header.timestamp().as_int_seconds(), 1337u64);
    assert_eq!(&header, block.header());

    let block = Block::new(
        vec![],
        Id::new(H256([0x02; 32])),
        BlockTimestamp::from_int_seconds(1338u64),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    messaging_handle2
        .send_message(
            peer1.peer_id,
            SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
        )
        .unwrap();

    let mut sync_rx_1 = match sync1.poll_next().await.unwrap() {
        SyncingEvent::Connected {
            peer_id: _,
            services: _,
            sync_rx,
        } => sync_rx,
        event => panic!("Unexpected event: {event:?}"),
    };

    let header = match sync_rx_1.recv().await.unwrap() {
        SyncMessage::HeaderList(l) => {
            assert_eq!(l.headers().len(), 1);
            l.into_headers().pop().unwrap()
        }
        a => panic!("Unexpected announcement: {a:?}"),
    };
    assert_eq!(block.timestamp(), BlockTimestamp::from_int_seconds(1338u64));
    assert_eq!(&header, block.header());

    shutdown.store(true);
    let _ = shutdown_sender_2.send(());
    let _ = shutdown_sender_1.send(());
}

#[allow(clippy::extra_unused_type_parameters)]
async fn block_announcement_no_subscription<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let chain_config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Vec::new(),
        socks5_proxy: None,
        boot_nodes: Vec::new(),
        reserved_nodes: Vec::new(),
        node_type: NodeType::Inactive.into(),
        ..P2pConfig::default()
    });
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender_1, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let time_getter = TimeGetter::default();
    let (mut conn1, mut messaging_handle1, _sync1, _) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&chain_config),
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
    let (mut conn2, _messaging_handle2, _sync2, _) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        chain_config,
        p2p_config,
        time_getter,
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_, _peer1, peer2) = connect_and_accept_services::<N>(&mut conn1, &mut conn2).await;

    let block = Block::new(
        vec![],
        Id::new(H256([0x01; 32])),
        BlockTimestamp::from_int_seconds(1337u64),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    messaging_handle1
        .send_message(
            peer2.peer_id,
            SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
        )
        .unwrap();

    shutdown.store(true);
    let _ = shutdown_sender_2.send(());
    let _ = shutdown_sender_1.send(());
}
