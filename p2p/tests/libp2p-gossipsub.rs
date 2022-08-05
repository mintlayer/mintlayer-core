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

use p2p_test_utils::make_libp2p_addr;

use common::chain::{
    block::{consensus_data::ConsensusData, timestamp::BlockTimestamp, Block},
    transaction::Transaction,
};
use common::primitives::{Id, H256};
use p2p::{
    error::{P2pError, PublishError},
    message::Announcement,
    net::{
        self,
        libp2p::{Libp2pConnectivityHandle, Libp2pService},
        types::{ConnectivityEvent, PubSubEvent, PubSubTopic},
        ConnectivityService, NetworkingService, PubSubService,
    },
};
use serialization::Encode;
use std::sync::Arc;

// verify that libp2p gossipsub works
#[tokio::test]
async fn test_libp2p_gossipsub() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut pubsub1, _) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();
    let (mut conn2, mut pubsub2, _) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let (_conn1_res, conn2_res) = tokio::join!(
        conn1.connect(conn2.local_addr().await.unwrap().unwrap()),
        conn2.poll_next()
    );
    let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let _conn1_id = match conn2_res {
        ConnectivityEvent::InboundAccepted { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };

    pubsub1.subscribe(&[net::types::PubSubTopic::Blocks]).await.unwrap();
    pubsub2.subscribe(&[net::types::PubSubTopic::Blocks]).await.unwrap();

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
    loop {
        let res = pubsub1
            .publish(Announcement::Block(
                Block::new(
                    vec![],
                    Id::new(H256([0x01; 32])),
                    BlockTimestamp::from_int_seconds(1337u64),
                    ConsensusData::None,
                )
                .unwrap(),
            ))
            .await;

        if res.is_ok() {
            break;
        } else {
            assert_eq!(
                res,
                Err(P2pError::PublishError(PublishError::InsufficientPeers))
            );
        }
    }

    // poll an event from the network for server2
    let res2: Result<PubSubEvent<Libp2pService>, _> = pubsub2.poll_next().await;
    let PubSubEvent::Announcement {
        peer_id: _,
        message_id: _,
        announcement: Announcement::Block(block),
    } = res2.unwrap();
    assert_eq!(block.timestamp().as_int_seconds(), 1337u64);
    pubsub2
        .publish(Announcement::Block(
            Block::new(
                vec![],
                Id::new(H256([0x02; 32])),
                BlockTimestamp::from_int_seconds(1338u64),
                ConsensusData::None,
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let res1: Result<PubSubEvent<Libp2pService>, _> = pubsub1.poll_next().await;
    let PubSubEvent::Announcement {
        peer_id: _,
        message_id: _,
        announcement: Announcement::Block(block),
    } = res1.unwrap();
    assert_eq!(block.timestamp(), BlockTimestamp::from_int_seconds(1338u64));
}

async fn connect_peers(
    peer1: &mut Libp2pConnectivityHandle<Libp2pService>,
    peer2: &mut Libp2pConnectivityHandle<Libp2pService>,
) {
    let addr = peer2.local_addr().await.unwrap().unwrap();
    let (_peer1_res, peer2_res) = tokio::join!(peer1.connect(addr), peer2.poll_next());

    let peer2_res: ConnectivityEvent<Libp2pService> = peer2_res.unwrap();
    let _peer1_id = match peer2_res {
        ConnectivityEvent::InboundAccepted { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };
}

// test libp2p gossipsub with multiple peers and verify that as our libp2p requires message
// validation, peers don't automatically forward the messages
#[tokio::test]
async fn test_libp2p_gossipsub_3_peers() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut pubsub1, _) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let (mut peer1, mut peer2, mut peer3) = {
        let mut peers = futures::future::join_all((0..3).map(|_| async {
            let res =
                Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
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

    pubsub1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    peer1.1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    peer2.1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    peer3.1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
    loop {
        let res = pubsub1
            .publish(Announcement::Block(
                Block::new(
                    vec![],
                    Id::new(H256([0x03; 32])),
                    BlockTimestamp::from_int_seconds(1337u64),
                    ConsensusData::None,
                )
                .unwrap(),
            ))
            .await;

        if res.is_ok() {
            break;
        } else {
            assert_eq!(
                res,
                Err(P2pError::PublishError(PublishError::InsufficientPeers))
            );
        }
    }

    // verify that all peers received the message even though they weren't directy connected
    let res: Result<PubSubEvent<Libp2pService>, _> = peer1.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(PubSubEvent::Announcement {
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
            .report_validation_result(peer_id, message_id, net::types::ValidationResult::Accept)
            .await,
        Ok(())
    );

    // verify that the peer2 gets the message
    let res: Result<PubSubEvent<Libp2pService>, _> = peer2.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(PubSubEvent::Announcement {
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
            .report_validation_result(peer_id, message_id, net::types::ValidationResult::Accept)
            .await,
        Ok(())
    );

    let res: Result<PubSubEvent<Libp2pService>, _> = peer3.1.poll_next().await;
    assert!(std::matches!(
        res.unwrap(),
        PubSubEvent::Announcement { .. }
    ));
}

#[tokio::test]
async fn test_libp2p_gossipsub_too_big_message() {
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut pubsub1, _) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let (mut conn2, mut pubsub2, _) =
        Libp2pService::start(make_libp2p_addr(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let (_conn1_res, conn2_res) = tokio::join!(
        conn1.connect(conn2.local_addr().await.unwrap().unwrap()),
        conn2.poll_next()
    );
    let conn2_res: ConnectivityEvent<Libp2pService> = conn2_res.unwrap();
    let _conn1_id = match conn2_res {
        ConnectivityEvent::InboundAccepted { peer_info, .. } => peer_info.peer_id,
        _ => panic!("invalid event received, expected incoming connection"),
    };

    pubsub1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    pubsub2.subscribe(&[PubSubTopic::Blocks]).await.unwrap();

    let txs = (0..200_000)
        .map(|_| Transaction::new(0, vec![], vec![], 0).unwrap())
        .collect::<Vec<_>>();
    let message = Announcement::Block(
        Block::new(
            txs,
            Id::new(H256([0x04; 32])),
            BlockTimestamp::from_int_seconds(1337u64),
            ConsensusData::None,
        )
        .unwrap(),
    );
    let encoded_size = message.encode().len();
    // TODO: move this to a spec.rs so it's accessible everywhere
    const MAXIMUM_SIZE: usize = 2 * 1024 * 1024;

    assert_eq!(
        pubsub1.publish(message).await,
        Err(P2pError::PublishError(PublishError::MessageTooLarge(
            Some(encoded_size),
            Some(MAXIMUM_SIZE)
        )))
    );
}
