// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(unused)]
extern crate test_utils;

use common::chain::{
    block::{consensus_data::ConsensusData, Block},
    transaction::Transaction,
};
use libp2p::{multiaddr::Protocol, Multiaddr};
use p2p::{
    error::{Libp2pError, P2pError, ProtocolError},
    message::{self, MessageType, PubSubMessage, SyncingMessage, SyncingRequest},
    net::{
        self,
        libp2p::{Libp2pConnectivityHandle, Libp2pDiscoveryStrategy, Libp2pService},
        ConnectivityEvent, ConnectivityService, NetworkService, PubSubEvent, PubSubService,
        PubSubTopic,
    },
};
use std::sync::Arc;

// verify that libp2p gossipsub works
#[tokio::test]
async fn test_libp2p_gossipsub() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut pubsub1, _) = Libp2pService::start(
        addr1,
        &[],
        &[PubSubTopic::Blocks],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn2, mut pubsub2, _) = Libp2pService::start(
        addr2,
        &[],
        &[PubSubTopic::Blocks],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let (conn1_res, conn2_res) =
        tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let conn1_id = match conn2_res {
        ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
    loop {
        let res = pubsub1
            .publish(message::Message {
                magic: [0, 1, 2, 3],
                msg: MessageType::PubSub(PubSubMessage::Block(
                    Block::new(vec![], None, 1337u32, ConsensusData::None).unwrap(),
                )),
            })
            .await;

        if res.is_ok() {
            break;
        } else {
            // TODO: refactor error code
            assert_eq!(
                res,
                Err(P2pError::Libp2pError(Libp2pError::PublishError(
                    "NoPeers".to_string()
                )))
            );
        }
    }

    // poll an event from the network for server2
    let res2: Result<PubSubEvent<Libp2pService>, _> = pubsub2.poll_next().await;
    if let PubSubEvent::MessageReceived {
        peer_id: _,
        message:
            message::Message {
                msg: MessageType::PubSub(PubSubMessage::Block(block)),
                ..
            },
        message_id: _,
    } = res2.unwrap()
    {
        assert_eq!(block.block_time(), 1337u32);
        pubsub2
            .publish(message::Message {
                magic: [0, 1, 2, 3],
                msg: MessageType::PubSub(PubSubMessage::Block(
                    Block::new(vec![], None, 1338u32, ConsensusData::None).unwrap(),
                )),
            })
            .await;
    } else {
        panic!("invalid message received");
    }

    let res1: Result<PubSubEvent<Libp2pService>, _> = pubsub1.poll_next().await;
    if let PubSubEvent::MessageReceived {
        peer_id: _,
        message:
            message::Message {
                msg: MessageType::PubSub(PubSubMessage::Block(block)),
                ..
            },
        message_id: _,
    } = res1.unwrap()
    {
        assert_eq!(block.block_time(), 1338u32);
    } else {
        panic!("invalid message received");
    }
}

async fn connect_peers(
    peer1: &mut Libp2pConnectivityHandle<Libp2pService>,
    peer2: &mut Libp2pConnectivityHandle<Libp2pService>,
) {
    let (peer1_res, peer2_res) =
        tokio::join!(peer1.connect(peer2.local_addr().clone()), peer2.poll_next());

    let peer2_res: ConnectivityEvent<Libp2pService> = peer2_res.unwrap();
    let peer1_id = match peer2_res {
        ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
}

// test libp2p gossipsub with multiple peers and verify that as our libp2p requires message
// validation, peers don't automatically forward the messages
#[tokio::test]
async fn test_libp2p_gossipsub_3_peers() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut pubsub1, _) = Libp2pService::start(
        addr1,
        &[],
        &[PubSubTopic::Blocks],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let (mut peer1, mut peer2, mut peer3) = {
        let mut peers = futures::future::join_all((0..3).map(|_| async {
            let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
            let res = Libp2pService::start(
                addr,
                &[],
                &[PubSubTopic::Blocks],
                Arc::clone(&config),
                std::time::Duration::from_secs(10),
            )
            .await
            .unwrap();
            (res.0, res.1)
        }))
        .await;

        (
            peers.pop().unwrap(),
            peers.pop().unwrap(),
            peers.pop().unwrap(),
        )
    };

    // connect peers into a partial mesh
    connect_peers(&mut conn1, &mut peer1.0).await;
    connect_peers(&mut peer1.0, &mut peer2.0).await;
    connect_peers(&mut peer2.0, &mut peer3.0).await;

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
    loop {
        let res = pubsub1
            .publish(message::Message {
                magic: [0, 1, 2, 3],
                msg: MessageType::PubSub(PubSubMessage::Block(
                    Block::new(vec![], None, 1337u32, ConsensusData::None).unwrap(),
                )),
            })
            .await;

        if res.is_ok() {
            break;
        } else {
            // TODO: refactor error code
            assert_eq!(
                res,
                Err(P2pError::Libp2pError(Libp2pError::PublishError(
                    "NoPeers".to_string()
                )))
            );
        }
    }

    // verify that all peers received the message even though they weren't directy connected
    let res: Result<PubSubEvent<Libp2pService>, _> = peer1.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(PubSubEvent::MessageReceived {
        peer_id,
        message_id,
        ..
    }) = res
    {
        (peer_id, message_id)
    } else {
        panic!("invalid message received");
    };

    // try to poll the to other gossipsubs and verify that as `peer1` hasn't registered
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

    assert_eq!(
        peer1
            .1
            .report_validation_result(peer_id, message_id, net::ValidationResult::Accept)
            .await,
        Ok(())
    );

    // verify that the peer2 gets the message
    let res: Result<PubSubEvent<Libp2pService>, _> = peer2.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(PubSubEvent::MessageReceived {
        peer_id,
        message_id,
        ..
    }) = res
    {
        (peer_id, message_id)
    } else {
        panic!("invalid message received");
    };

    // verify that peer3 didn't get the message until peer2 validated it
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
        }
        _ = peer3.1.poll_next() => {
            panic!("peer3 received message")
        }
    }

    assert_eq!(
        peer2
            .1
            .report_validation_result(peer_id, message_id, net::ValidationResult::Accept)
            .await,
        Ok(())
    );

    let res: Result<PubSubEvent<Libp2pService>, _> = peer3.1.poll_next().await;
    assert!(std::matches!(
        res.unwrap(),
        PubSubEvent::MessageReceived { .. }
    ));
}

// try to publish something other than a transaction
#[tokio::test]
async fn test_libp2p_gossipsub_invalid_data() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut pubsub1, _) = Libp2pService::start(
        addr1,
        &[],
        &[PubSubTopic::Blocks],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    assert_eq!(
        pubsub1
            .publish(message::Message {
                magic: [0, 1, 2, 3],
                msg: MessageType::Syncing(SyncingMessage::Request(SyncingRequest::GetHeaders {
                    locator: vec![]
                })),
            })
            .await,
        Err(P2pError::ProtocolError(ProtocolError::InvalidMessage))
    );
}

#[tokio::test]
async fn test_libp2p_gossipsub_too_big_message() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let addr1: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn1, mut pubsub1, _) = Libp2pService::start(
        addr1,
        &[],
        &[PubSubTopic::Blocks],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();
    let addr2: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut conn2, mut pubsub2, _) = Libp2pService::start(
        addr2,
        &[],
        &[PubSubTopic::Blocks],
        Arc::clone(&config),
        std::time::Duration::from_secs(10),
    )
    .await
    .unwrap();

    let (conn1_res, conn2_res) =
        tokio::join!(conn1.connect(conn2.local_addr().clone()), conn2.poll_next());
    let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let conn1_id = match conn2_res {
        ConnectivityEvent::IncomingConnection { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };

    let txs = (0..(200_000))
        .map(|_| Transaction::new(0, vec![], vec![], 0).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        pubsub1
            .publish(message::Message {
                magic: [0, 1, 2, 3],
                msg: MessageType::PubSub(PubSubMessage::Block(
                    Block::new(txs, None, 1337u32, ConsensusData::None).unwrap(),
                )),
            })
            .await,
        // TODO: refactor error code
        Err(P2pError::Libp2pError(Libp2pError::PublishError(
            "MessageTooLarge".to_string()
        )))
    );
}
