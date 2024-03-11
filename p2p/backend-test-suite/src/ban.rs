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

use chainstate::{ban_score::BanScore, BlockError, ChainstateError, CheckBlockError};
use common::{
    chain::block::{timestamp::BlockTimestamp, Block, BlockReward, ConsensusData},
    primitives::Idable,
    time_getter::TimeGetter,
};
use p2p::{
    error::P2pError,
    message::{BlockSyncMessage, HeaderList},
    net::{
        types::SyncingEvent, ConnectivityService, MessagingService, NetworkingService,
        SyncingEventReceiver,
    },
    sync::SyncManager,
    testing_utils::{connect_and_accept_services, test_p2p_config, TestTransportMaker},
    PeerManagerEvent,
};
use utils::atomics::SeqCstAtomicBool;

tests![invalid_pubsub_block,];

// Start two network services, spawn a `SyncMessageHandler` for the first service, publish an
// invalid block from the first service and verify that the `SyncManager` of the first service
// receives a `AdjustPeerScore` event which bans the peer of the second service.
#[allow(clippy::extra_unused_type_parameters)]
#[tracing::instrument]
async fn invalid_pubsub_block<T, N>()
where
    T: TestTransportMaker<Transport = N::Transport>,
    N: NetworkingService + Debug + 'static,
    N::ConnectivityHandle: ConnectivityService<N>,
    N::MessagingHandle: MessagingService,
    N::SyncingEventReceiver: SyncingEventReceiver,
{
    let (peer_mgr_event_sender, mut peer_mgr_event_receiver) = mpsc::unbounded_channel();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let (chainstate, mempool, shutdown_trigger, subsystem_manager_handle) =
        p2p_test_utils::start_subsystems(Arc::clone(&chain_config));
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();

    let time_getter = TimeGetter::default();

    let (mut conn1, messaging_handle, sync_event_receiver, _) = N::start(
        true,
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&chain_config),
        Arc::new(test_p2p_config()),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let sync1 = SyncManager::<N>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        messaging_handle,
        sync_event_receiver,
        chainstate,
        mempool,
        peer_mgr_event_sender,
        time_getter.clone(),
    );

    let (_shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (_subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (mut conn2, mut messaging_handle_2, mut sync2, _) = N::start(
        true,
        T::make_transport(),
        vec![T::make_address()],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        time_getter,
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();

    let (_address, _peer_info1, peer_info2) =
        connect_and_accept_services::<N>(&mut conn1, &mut conn2).await;

    // Create a block with an invalid timestamp.
    let block = Block::new(
        Vec::new(),
        chain_config.genesis_block().get_id().into(),
        BlockTimestamp::from_int_seconds(1),
        ConsensusData::None,
        BlockReward::new(Vec::new()),
    )
    .unwrap();

    let sync1_handle = logging::spawn_in_current_span(async move { sync1.run().await });

    // spawn `sync2` into background and spam an orphan block on the network
    logging::spawn_in_current_span(async move {
        let (peer, mut block_sync_msg_receiver) = match sync2.poll_next().await.unwrap() {
            SyncingEvent::Connected {
                peer_id,
                common_services: _,
                protocol_version: _,
                block_sync_msg_receiver,
                transaction_sync_msg_receiver: _,
            } => (peer_id, block_sync_msg_receiver),
            e => panic!("Unexpected event type: {e:?}"),
        };
        match block_sync_msg_receiver.recv().await.unwrap() {
            BlockSyncMessage::HeaderListRequest(_) => {}
            e => panic!("Unexpected event type: {e:?}"),
        };
        messaging_handle_2
            .send_block_sync_message(
                peer,
                BlockSyncMessage::HeaderList(HeaderList::new(Vec::new())),
            )
            .unwrap();
        messaging_handle_2
            .send_block_sync_message(
                peer,
                BlockSyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
            )
            .unwrap();
    });

    match peer_mgr_event_receiver.recv().await {
        Some(PeerManagerEvent::AdjustPeerScore(peer_id, score, _)) => {
            assert_eq!(peer_id, peer_info2.peer_id);
            assert_eq!(
                score,
                P2pError::ChainstateError(ChainstateError::ProcessBlockError(
                    BlockError::CheckBlockFailed(CheckBlockError::BlockTimeOrderInvalid(
                        BlockTimestamp::from_int_seconds(4),
                        BlockTimestamp::from_int_seconds(5),
                    ))
                ))
                .ban_score()
            );
        }
        e => panic!("invalid event received: {e:?}"),
    }

    shutdown.store(true);
    let _ = shutdown_sender.send(());
    let _ = sync1_handle.await.unwrap();
    shutdown_trigger.initiate();
    subsystem_manager_handle.join().await;
}
