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
        mock::{
            transport::{ChannelMockTransport, TcpMockTransport},
            MockService,
        },
        types::{PubSubTopic, SyncingEvent},
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
};
use p2p_test_utils::{connect_services, MakeChannelAddress, MakeTcpAddress, MakeTestAddress};

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

    // spam the message on the pubsubsub until it succeeds (= until we have a peer)
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

    // poll an event from the network for server2
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
async fn block_announcement_tcp() {
    block_announcement::<MakeTcpAddress, MockService<TcpMockTransport>>().await;
}

#[tokio::test]
async fn block_announcement_channels() {
    block_announcement::<MakeChannelAddress, MockService<ChannelMockTransport>>().await;
}
