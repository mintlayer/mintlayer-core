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

use common::{
    chain::block::{consensus_data::ConsensusData, timestamp::BlockTimestamp, Block, BlockReward},
    primitives::{Id, H256},
};

use p2p::{
    error::{P2pError, PublishError},
    message::Announcement,
    net::{
        libp2p::Libp2pService,
        mock::{
            transport::{MockChannelTransport, TcpTransportSocket},
            MockService,
        },
        types::{PubSubTopic, SyncingEvent, ValidationResult},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    peer_manager::helpers::connect_services,
};
use p2p_test_utils::{MakeChannelAddress, MakeP2pAddress, MakeTcpAddress, MakeTestAddress};

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
    block_announcement_3_peers::<MakeTcpAddress, MockService<TcpTransportSocket>>().await;
}

// TODO: Implement announcements resending in partially connected networks.
#[tokio::test]
#[ignore]
async fn block_announcement_3_peers_channels() {
    block_announcement_3_peers::<MakeChannelAddress, MockService<MockChannelTransport>>().await;
}
