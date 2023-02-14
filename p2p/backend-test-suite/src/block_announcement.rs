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
    chain::{
        block::{
            consensus_data::{ConsensusData, PoSData},
            timestamp::BlockTimestamp,
            Block, BlockReward,
        },
        signature::{
            inputsig::{InputWitness, StandardInputSignature},
            sighashtype,
        },
        transaction::signed_transaction::SignedTransaction,
        transaction::Transaction,
        TxInput,
    },
    primitives::{Compact, Id, H256},
    Uint256,
};
use serialization::Encode;

use p2p::{
    config::{NodeType, P2pConfig},
    error::{P2pError, PublishError},
    message::Announcement,
    net::{
        default_backend::constants::ANNOUNCEMENT_MAX_SIZE, types::SyncingEvent,
        ConnectivityService, NetworkingService, SyncingMessagingService,
    },
    testing_utils::{connect_services, TestTransportMaker},
};

tests![
    block_announcement,
    block_announcement_no_subscription,
    block_announcement_too_big_message,
];

async fn block_announcement<T, N, A>()
where
    T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
    N: NetworkingService + Debug,
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();
    let (mut conn2, mut sync2) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    connect_services::<N>(&mut conn1, &mut conn2).await;

    let block = Block::new(
        vec![],
        Id::new(H256([0x01; 32])),
        BlockTimestamp::from_int_seconds(1337u64),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    sync1.make_announcement(Announcement::Block(block.header().clone())).unwrap();

    // Poll an event from the network for server2.
    let header = match sync2.poll_next().await.unwrap() {
        SyncingEvent::Announcement {
            peer: _,
            announcement: Announcement::Block(block),
        } => block,
        _ => panic!("Unexpected event"),
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
    sync2.make_announcement(Announcement::Block(block.header().clone())).unwrap();

    let header = match sync1.poll_next().await.unwrap() {
        SyncingEvent::Announcement {
            peer: _,
            announcement: Announcement::Block(block),
        } => block,
        _ => panic!("Unexpected event"),
    };
    assert_eq!(block.timestamp(), BlockTimestamp::from_int_seconds(1338u64));
    assert_eq!(&header, block.header());
}

async fn block_announcement_no_subscription<T, N, A>()
where
    T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
    N: NetworkingService + Debug,
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let chain_config = Arc::new(common::chain::config::create_mainnet());
    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Vec::new(),
        added_nodes: Vec::new(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        node_type: NodeType::Inactive.into(),
        allow_discover_private_ips: Default::default(),
        header_count_limit: Default::default(),
        max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
    });
    let (mut conn1, mut sync1) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
    )
    .await
    .unwrap();
    let (mut conn2, _sync2) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        chain_config,
        p2p_config,
    )
    .await
    .unwrap();

    connect_services::<N>(&mut conn1, &mut conn2).await;

    let block = Block::new(
        vec![],
        Id::new(H256([0x01; 32])),
        BlockTimestamp::from_int_seconds(1337u64),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    sync1.make_announcement(Announcement::Block(block.header().clone())).unwrap();
}

async fn block_announcement_too_big_message<T, N, A>()
where
    T: TestTransportMaker<Transport = N::Transport, Address = N::Address>,
    N: NetworkingService + Debug,
    N::SyncingMessagingHandle: SyncingMessagingService<N>,
    N::ConnectivityHandle: ConnectivityService<N>,
{
    let config = Arc::new(common::chain::config::create_mainnet());
    let (mut conn1, mut sync1) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    let (mut conn2, _sync2) = N::start(
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&config),
        Default::default(),
    )
    .await
    .unwrap();

    connect_services::<N>(&mut conn1, &mut conn2).await;

    let signature = (0..ANNOUNCEMENT_MAX_SIZE).into_iter().map(|_| 0).collect::<Vec<u8>>();
    let signatures = vec![InputWitness::Standard(StandardInputSignature::new(
        sighashtype::SigHashType::try_from(sighashtype::SigHashType::ALL).unwrap(),
        signature,
    ))];
    let pos = PoSData::new(Vec::new(), signatures, Compact::from(Uint256::from_u64(0)));
    let block = Block::new(
        Vec::new(),
        Id::new(H256([0x04; 32])),
        BlockTimestamp::from_int_seconds(1337u64),
        ConsensusData::PoS(pos),
        BlockReward::new(Vec::new()),
    )
    .unwrap();
    let message = Announcement::Block(block.header().clone());
    let encoded_size = message.encode().len();

    assert_eq!(
        sync1.make_announcement(message),
        Err(P2pError::PublishError(PublishError::MessageTooLarge(
            encoded_size,
            ANNOUNCEMENT_MAX_SIZE
        )))
    );
}
