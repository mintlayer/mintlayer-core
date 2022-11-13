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

use tokio::{pin, select, time::Duration};

use common::{
    chain::{
        block::{consensus_data::ConsensusData, timestamp::BlockTimestamp, Block, BlockReward},
        transaction::signed_transaction::SignedTransaction,
        transaction::Transaction,
    },
    primitives::{Id, H256},
};
use serialization::Encode;

use p2p::{
    error::{P2pError, PublishError},
    message::Announcement,
    net::{
        libp2p::Libp2pService,
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            MockService,
        },
        types::{PubSubTopic, SyncingEvent, ValidationResult},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
};
use p2p_test_utils::{
    connect_services, MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress,
};

async fn block_announcement<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();
    let (mut conn2, mut sync2) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    connect_services::<S>(&mut conn1, &mut conn2).await;

    sync1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    sync2.subscribe(&[PubSubTopic::Blocks]).await.unwrap();

    // Spam the message until until we have a peer.
    loop {
        let res = sync1
            .make_announcement(Announcement::Block(
                Block::new(
                    vec![],
                    Id::new(H256([0x01; 32])),
                    BlockTimestamp::from_int_seconds(1337u64),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
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

    // Poll an event from the network for server2.
    let block = match sync2.poll_next().await.unwrap() {
        SyncingEvent::Announcement {
            peer_id: _,
            message_id: _,
            announcement: Announcement::Block(block),
        } => block,
        _ => panic!("Unexpected event"),
    };
    assert_eq!(block.timestamp().as_int_seconds(), 1337u64);
    sync2
        .make_announcement(Announcement::Block(
            Block::new(
                vec![],
                Id::new(H256([0x02; 32])),
                BlockTimestamp::from_int_seconds(1338u64),
                ConsensusData::None,
                BlockReward::new(Vec::new()),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let block = match sync1.poll_next().await.unwrap() {
        SyncingEvent::Announcement {
            peer_id: _,
            message_id: _,
            announcement: Announcement::Block(block),
        } => block,
        _ => panic!("Unexpected event"),
    };
    assert_eq!(block.timestamp(), BlockTimestamp::from_int_seconds(1338u64));
}

#[tokio::test]
async fn block_announcement_libp2p() {
    block_announcement::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn block_announcement_tcp() {
    block_announcement::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn block_announcement_channels() {
    block_announcement::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

async fn block_announcement_no_subscription<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();
    let (mut conn2, _sync2) = S::start(A::make_address(), Arc::clone(&config), Default::default())
        .await
        .unwrap();

    connect_services::<S>(&mut conn1, &mut conn2).await;

    let timeout = tokio::time::sleep(Duration::from_secs(1));
    pin!(timeout);
    loop {
        select! {
            res = sync1.make_announcement(Announcement::Block(
                Block::new(
                    vec![],
                    Id::new(H256([0x01; 32])),
                    BlockTimestamp::from_int_seconds(1337u64),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
                )
                .unwrap(),
            )) => {
                assert_eq!(Err(P2pError::PublishError(PublishError::InsufficientPeers)), res);
            }
            _ = &mut timeout => break,
        }
    }
}

#[tokio::test]
async fn block_announcement_no_subscription_libp2p() {
    block_announcement_no_subscription::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn block_announcement_no_subscription_tcp() {
    block_announcement_no_subscription::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn block_announcement_no_subscription_channels() {
    block_announcement_no_subscription::<MakeChannelAddress, MockService<ChannelMockTransport>>()
        .await;
}

// Test announcements with multiple peers and verify that the message validation is done and peers
// don't automatically forward the messages.
async fn block_announcement_3_peers<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let (mut peer1, mut peer2, mut peer3) = {
        let mut peers = futures::future::join_all((0..3).map(|_| async {
            let res = S::start(A::make_address(), Arc::clone(&config), Default::default())
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

    // Connect peers into a partial mesh.
    connect_services::<S>(&mut conn1, &mut peer1.0).await;
    connect_services::<S>(&mut peer1.0, &mut peer2.0).await;
    connect_services::<S>(&mut peer2.0, &mut peer3.0).await;

    sync1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    peer1.1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    peer2.1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    peer3.1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();

    // Spam the message until we have a peer.
    loop {
        let res = sync1
            .make_announcement(Announcement::Block(
                Block::new(
                    vec![],
                    Id::new(H256([0x03; 32])),
                    BlockTimestamp::from_int_seconds(1337u64),
                    ConsensusData::None,
                    BlockReward::new(Vec::new()),
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

    // Verify that all peers received the message even though they weren't directly connected.
    let res = peer1.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(SyncingEvent::Announcement {
        peer_id,
        message_id,
        ..
    }) = res
    {
        (peer_id, message_id)
    } else {
        panic!("invalid message received");
    };

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

    assert_eq!(
        peer1
            .1
            .report_validation_result(peer_id, message_id, ValidationResult::Accept)
            .await,
        Ok(())
    );

    // verify that the peer2 gets the message
    let res = peer2.1.poll_next().await;
    let (peer_id, message_id) = if let Ok(SyncingEvent::Announcement {
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
            .report_validation_result(peer_id, message_id, ValidationResult::Accept)
            .await,
        Ok(())
    );

    let res = peer3.1.poll_next().await;
    assert!(std::matches!(
        res.unwrap(),
        SyncingEvent::Announcement { .. }
    ));
}

#[tokio::test]
async fn block_announcement_3_peers_libp2p() {
    block_announcement_3_peers::<MakeP2pAddress, Libp2pService>().await;
}

// TODO: Implement announcements resending in partially connected networks.
#[ignore]
#[tokio::test]
async fn block_announcement_3_peers_tcp() {
    block_announcement_3_peers::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

// TODO: Implement announcements resending in partially connected networks.
#[tokio::test]
#[ignore]
async fn block_announcement_3_peers_channels() {
    block_announcement_3_peers::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}

async fn block_announcement_too_big_message<A, S>()
where
    A: MakeTestAddress<Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    let (mut conn2, mut sync2) =
        S::start(A::make_address(), Arc::clone(&config), Default::default())
            .await
            .unwrap();

    connect_services::<S>(&mut conn1, &mut conn2).await;

    sync1.subscribe(&[PubSubTopic::Blocks]).await.unwrap();
    sync2.subscribe(&[PubSubTopic::Blocks]).await.unwrap();

    let txs = (0..200_000)
        .map(|_| {
            SignedTransaction::new(Transaction::new(0, vec![], vec![], 0).unwrap(), vec![])
                .expect("invalid witness count")
        })
        .collect::<Vec<_>>();
    let message = Announcement::Block(
        Block::new(
            txs,
            Id::new(H256([0x04; 32])),
            BlockTimestamp::from_int_seconds(1337u64),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .unwrap(),
    );
    let encoded_size = message.encode().len();
    // TODO: move this to a spec.rs so it's accessible everywhere
    const MAXIMUM_SIZE: usize = 2 * 1024 * 1024;

    assert_eq!(
        sync1.make_announcement(message).await,
        Err(P2pError::PublishError(PublishError::MessageTooLarge(
            Some(encoded_size),
            Some(MAXIMUM_SIZE)
        )))
    );
}

#[tokio::test]
async fn block_announcement_too_big_message_libp2p() {
    block_announcement_too_big_message::<MakeP2pAddress, Libp2pService>().await;
}

#[tokio::test]
async fn block_announcement_too_big_message_tcp() {
    block_announcement_too_big_message::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn block_announcement_too_big_message_channels() {
    block_announcement_too_big_message::<MakeChannelAddress, MockService<ChannelMockTransport>>()
        .await;
}
