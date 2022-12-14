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
        signature::{
            inputsig::{InputWitness, StandardInputSignature},
            sighashtype,
        },
        transaction::signed_transaction::SignedTransaction,
        transaction::Transaction,
        TxInput,
    },
    primitives::{Id, H256},
};
use serialization::Encode;

use p2p::testing_utils::TestTransportMaker;
use p2p::{
    config::{NodeType, P2pConfig},
    error::{P2pError, PublishError},
    message::Announcement,
    net::{
        mock::constants::ANNOUNCEMENT_MAX_SIZE, types::SyncingEvent, ConnectivityService,
        NetworkingService, SyncingMessagingService,
    },
    peer_manager::helpers::connect_services,
};

tests![
    block_announcement,
    block_announcement_no_subscription,
    block_announcement_too_big_message,
];

async fn block_announcement<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();
    let (mut conn2, mut sync2) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    connect_services::<S>(&mut conn1, &mut conn2).await;

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

        match res {
            Ok(()) => break,
            Err(e) => assert_eq!(e, P2pError::PublishError(PublishError::InsufficientPeers)),
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

async fn block_announcement_no_subscription<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let chain_config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(P2pConfig {
        bind_address: Default::default(),
        ban_threshold: Default::default(),
        outbound_connection_timeout: Default::default(),
        mdns_config: Default::default(),
        request_timeout: Default::default(),
        node_type: NodeType::Inactive.into(),
    });
    let (mut conn1, mut sync1) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();
    let (mut conn2, _sync2) = S::start(
        A::make_transport(),
        A::make_address(),
        chain_config,
        p2p_config,
    )
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

async fn block_announcement_too_big_message<A, S>()
where
    A: TestTransportMaker<Transport = S::Transport, Address = S::Address>,
    S: NetworkingService + Debug,
    S::SyncingMessagingHandle: SyncingMessagingService<S>,
    S::ConnectivityHandle: ConnectivityService<S>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    let (mut conn2, _sync2) = S::start(
        A::make_transport(),
        A::make_address(),
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    connect_services::<S>(&mut conn1, &mut conn2).await;

    let input = TxInput::new(config.genesis_block_id().into(), 0);
    let signature = (0..ANNOUNCEMENT_MAX_SIZE).into_iter().map(|_| 0).collect::<Vec<u8>>();
    let signatures = vec![InputWitness::Standard(StandardInputSignature::new(
        sighashtype::SigHashType::try_from(sighashtype::SigHashType::ALL).unwrap(),
        signature,
    ))];
    let txs = vec![SignedTransaction::new(
        Transaction::new(0, vec![input], vec![], 0).unwrap(),
        signatures,
    )
    .expect("invalid witness count")];

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

    assert_eq!(
        sync1.make_announcement(message).await,
        Err(P2pError::PublishError(PublishError::MessageTooLarge(
            Some(encoded_size),
            Some(ANNOUNCEMENT_MAX_SIZE)
        )))
    );
}
