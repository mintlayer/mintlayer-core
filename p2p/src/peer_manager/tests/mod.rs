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

mod addresses;
mod ban;
mod connections;
mod peer_types;
mod ping;
mod utils;

use std::{sync::Arc, time::Duration};

use p2p_test_utils::expect_recv;
use tokio::sync::{mpsc, oneshot};

use ::utils::atomics::SeqCstAtomicBool;
use common::time_getter::TimeGetter;
use crypto::random::Rng;
use p2p_types::socket_address::SocketAddress;
use test_utils::assert_matches_return_val;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::timeout,
};

use crate::{
    interface::types::ConnectedPeer,
    message::{PeerManagerMessage, PingRequest, PingResponse},
    net::{
        default_backend::types::Command, types::ConnectivityEvent, ConnectivityService,
        NetworkingService,
    },
    peer_manager::PeerManager,
    testing_utils::{peerdb_inmemory_store, test_p2p_config},
    types::peer_id::PeerId,
    utils::oneshot_nofail,
    P2pConfig, P2pEventHandler, PeerManagerEvent,
};

use self::utils::cmd_to_peer_man_msg;

use super::peerdb::storage::PeerDbStorage;

async fn make_peer_manager_custom<T>(
    transport: T::Transport,
    addr: SocketAddress,
    chain_config: Arc<common::chain::ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    time_getter: TimeGetter,
) -> (
    PeerManager<T, impl PeerDbStorage>,
    UnboundedSender<PeerManagerEvent>,
    oneshot::Sender<()>,
    UnboundedSender<P2pEventHandler>,
)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let shutdown = Arc::new(SeqCstAtomicBool::new(false));
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let (subscribers_sender, subscribers_receiver) = mpsc::unbounded_channel();
    let (conn, _, _, _) = T::start(
        transport,
        vec![addr],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        time_getter.clone(),
        Arc::clone(&shutdown),
        shutdown_receiver,
        subscribers_receiver,
    )
    .await
    .unwrap();
    let (peer_mgr_event_sender, peer_mgr_event_receiver) = tokio::sync::mpsc::unbounded_channel();

    let peer_manager = PeerManager::<T, _>::new(
        chain_config,
        p2p_config,
        conn,
        peer_mgr_event_receiver,
        time_getter,
        peerdb_inmemory_store(),
    )
    .unwrap();

    (
        peer_manager,
        peer_mgr_event_sender,
        shutdown_sender,
        subscribers_sender,
    )
}

async fn make_peer_manager<T>(
    transport: T::Transport,
    addr: SocketAddress,
    chain_config: Arc<common::chain::ChainConfig>,
) -> (
    PeerManager<T, impl PeerDbStorage>,
    oneshot::Sender<()>,
    UnboundedSender<P2pEventHandler>,
)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let p2p_config = Arc::new(test_p2p_config());
    let (peer_manager, _peer_mgr_event_sender, shutdown_sender, subscribers_sender) =
        make_peer_manager_custom::<T>(
            transport,
            addr,
            chain_config,
            p2p_config,
            Default::default(),
        )
        .await;
    (peer_manager, shutdown_sender, subscribers_sender)
}

async fn run_peer_manager<T>(
    transport: T::Transport,
    addr: SocketAddress,
    chain_config: Arc<common::chain::ChainConfig>,
    p2p_config: Arc<P2pConfig>,
    time_getter: TimeGetter,
) -> (
    UnboundedSender<PeerManagerEvent>,
    oneshot::Sender<()>,
    UnboundedSender<P2pEventHandler>,
)
where
    T: NetworkingService + 'static,
    T::ConnectivityHandle: ConnectivityService<T>,
{
    let (peer_manager, tx, shutdown_sender, subscribers_sender) =
        make_peer_manager_custom::<T>(transport, addr, chain_config, p2p_config, time_getter).await;
    logging::spawn_in_current_span(async move {
        peer_manager.run().await.unwrap();
    });
    (tx, shutdown_sender, subscribers_sender)
}

async fn get_connected_peers(tx: &UnboundedSender<PeerManagerEvent>) -> Vec<ConnectedPeer> {
    let (response_sender, response_receiver) = oneshot_nofail::channel();
    tx.send(PeerManagerEvent::GetConnectedPeers(response_sender)).unwrap();
    timeout(Duration::from_secs(1), response_receiver).await.unwrap().unwrap()
}

/// Send some message to PeerManager and ensure it's processed
async fn send_and_sync(
    peer_id: PeerId,
    message: PeerManagerMessage,
    conn_event_sender: &UnboundedSender<ConnectivityEvent>,
    cmd_receiver: &mut UnboundedReceiver<Command>,
) {
    conn_event_sender.send(ConnectivityEvent::Message { peer_id, message }).unwrap();

    let sent_nonce = crypto::random::make_pseudo_rng().gen();
    conn_event_sender
        .send(ConnectivityEvent::Message {
            peer_id,
            message: PeerManagerMessage::PingRequest(PingRequest { nonce: sent_nonce }),
        })
        .unwrap();

    let cmd = expect_recv!(cmd_receiver);
    let (peer_id_from_msg, peer_msg) = cmd_to_peer_man_msg(cmd);
    let nonce = assert_matches_return_val!(
        peer_msg,
        PeerManagerMessage::PingResponse(PingResponse { nonce }),
        nonce
    );
    assert_eq!(peer_id_from_msg, peer_id);
    conn_event_sender
        .send(ConnectivityEvent::Message {
            peer_id,
            message: PeerManagerMessage::PingResponse(PingResponse { nonce }),
        })
        .unwrap();
    assert_eq!(nonce, sent_nonce);
}
