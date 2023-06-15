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
};

use p2p::testing_utils::{
    connect_and_accept_services, test_p2p_config, TestTransportChannel, TestTransportMaker,
    TestTransportNoise, TestTransportTcp,
};
use p2p::{
    message::{HeaderList, SyncMessage},
    net::{
        default_backend::{
            transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
            DefaultNetworkingService,
        },
        types::SyncingEvent,
        ConnectivityService, MessagingService, NetworkingService, SyncingEventReceiver,
    },
};

// Test announcements with multiple peers and verify that the message validation is done and peers
// don't automatically forward the messages.
// TODO: Implement announcements resending in partially connected networks.
async fn block_announcement_3_peers<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug,
    S::MessagingHandle: MessagingService,
    S::SyncingEventReceiver: SyncingEventReceiver,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(test_p2p_config());
    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn1, mut messaging_handle1, _sync1, _) = S::start(
        A::make_transport(),
        vec![A::make_address()],
        Arc::clone(&config),
        Arc::clone(&p2p_config),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_shutdown_sender, shutdown_receiver_1) = oneshot::channel();
    let (_shutdown_sender, shutdown_receiver_2) = oneshot::channel();
    let (_shutdown_sender, shutdown_receiver_3) = oneshot::channel();
    let shutdown_receivers = [shutdown_receiver_1, shutdown_receiver_2, shutdown_receiver_3];

    let (_subscribers_sender, subscribers_receiver_1) = mpsc::unbounded_channel();
    let (_subscribers_sender, subscribers_receiver_2) = mpsc::unbounded_channel();
    let (_subscribers_sender, subscribers_receiver_3) = mpsc::unbounded_channel();
    let subscribers_receivers =
        [subscribers_receiver_1, subscribers_receiver_2, subscribers_receiver_3];

    let (mut peer1, mut peer2, mut peer3) = {
        let mut peers = futures::future::join_all(
            shutdown_receivers.into_iter().zip(subscribers_receivers.into_iter()).map(
                |(shutdown_receiver, subscribers_receiver)| async {
                    let res = S::start(
                        A::make_transport(),
                        vec![A::make_address()],
                        Arc::clone(&config),
                        Arc::clone(&p2p_config),
                        shutdown_receiver,
                        subscribers_receiver,
                    )
                    .await
                    .unwrap();
                    (res.0, res.2)
                },
            ),
        )
        .await;

        (
            peers.pop().unwrap(),
            peers.pop().unwrap(),
            peers.pop().unwrap(),
        )
    };

    // Connect peers into a partial mesh.
    connect_and_accept_services::<S>(&mut conn1, &mut peer1.0).await;
    connect_and_accept_services::<S>(&mut peer1.0, &mut peer2.0).await;
    connect_and_accept_services::<S>(&mut peer2.0, &mut peer3.0).await;

    messaging_handle1
        .broadcast_message(SyncMessage::HeaderList(HeaderList::new(vec![Block::new(
            vec![],
            Id::new(H256([0x03; 32])),
            BlockTimestamp::from_int_seconds(1337u64),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap()
        .header()
        .clone()])))
        .unwrap();

    // Verify that all peers received the message even though they weren't directly connected.
    let event = peer1.1.poll_next().await.unwrap();
    assert!(matches!(
        event,
        SyncingEvent::Message {
            peer: _,
            message: SyncMessage::HeaderList(_),
        }
    ));

    // try to poll the other gossipsubs and verify that as `peer1` hasn't registered
    // the message as valid, it is not forwarded and the code instead timeouts
    // if the message would've been forward to `peer2` and `peer3`, the messages would
    // be received instantaneously and the cod wouldn't timeout

    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
        }
        _ = peer2.1.poll_next() => {
            panic!("peer2 received message")
        }
        _ = peer3.1.poll_next() => {
            panic!("peer3 received message")
        }
    }

    // verify that the peer2 gets the message
    let event = peer2.1.poll_next().await.unwrap();
    assert!(matches!(
        event,
        SyncingEvent::Message {
            peer: _,
            message: SyncMessage::HeaderList(_),
        }
    ));

    // verify that peer3 didn't get the message until peer2 validated it
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
        }
        _ = peer3.1.poll_next() => {
            panic!("peer3 received message")
        }
    }

    let res = peer3.1.poll_next().await;
    assert!(std::matches!(
        res.unwrap(),
        SyncingEvent::Message {
            peer: _,
            message: SyncMessage::HeaderList(_)
        }
    ));
}

#[ignore]
#[tokio::test]
async fn block_announcement_3_peers_tcp() {
    block_announcement_3_peers::<TestTransportTcp, DefaultNetworkingService<TcpTransportSocket>>()
        .await;
}

#[tokio::test]
#[ignore]
async fn block_announcement_3_peers_channels() {
    block_announcement_3_peers::<
        TestTransportChannel,
        DefaultNetworkingService<MpscChannelTransport>,
    >()
    .await;
}

#[ignore]
#[tokio::test]
async fn block_announcement_3_peers_noise() {
    block_announcement_3_peers::<TestTransportNoise, DefaultNetworkingService<NoiseTcpTransport>>()
        .await;
}
