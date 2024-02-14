// Copyright (c) 2023 RBB S.r.l
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

use std::{collections::BTreeSet, time::Duration};

use common::{chain::ChainConfig, primitives::user_agent::mintlayer_core_user_agent};
use logging::log;
use tokio::sync::mpsc;

use p2p_test_utils::{wait_for_recv, P2pBasicTestTimeGetter};
use p2p_types::{
    bannable_address::BannableAddress, services::Service, socket_address::SocketAddress, PeerId,
};
use test_utils::assert_matches_return_val;
use utils_networking::IpOrSocketAddress;

use crate::{
    config::NodeType,
    message::PeerManagerMessage,
    net::{
        default_backend::types::{CategorizedMessage, Command},
        types::{ConnectivityEvent, PeerInfo},
    },
    peer_manager::PeerManagerInterface,
    testing_utils::TEST_PROTOCOL_VERSION,
    tests::helpers::PeerManagerNotification,
    utils::oneshot_nofail,
    PeerManagerEvent,
};

pub fn cmd_to_peer_man_msg(cmd: Command) -> (PeerId, PeerManagerMessage) {
    let (peer_id, msg) = assert_matches_return_val!(
        cmd,
        Command::SendMessage { peer_id, message },
        (peer_id, message)
    );

    let msg = msg.categorize();
    let msg = assert_matches_return_val!(msg, CategorizedMessage::PeerManagerMessage(msg), msg);
    (peer_id, msg)
}

pub async fn recv_command_advance_time(
    cmd_receiver: &mut mpsc::UnboundedReceiver<Command>,
    time_getter: &P2pBasicTestTimeGetter,
    advance_duration: Duration,
) -> Result<Command, mpsc::error::TryRecvError> {
    loop {
        match cmd_receiver.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => {
                time_getter.advance_time(advance_duration);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            other => {
                break other;
            }
        }
    }
}

pub fn make_full_relay_peer_info(peer_id: PeerId, chain_config: &ChainConfig) -> PeerInfo {
    PeerInfo {
        peer_id,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: NodeType::Full.into(),
    }
}

pub fn make_block_relay_peer_info(peer_id: PeerId, chain_config: &ChainConfig) -> PeerInfo {
    PeerInfo {
        peer_id,
        protocol_version: TEST_PROTOCOL_VERSION,
        network: *chain_config.magic_bytes(),
        software_version: *chain_config.software_version(),
        user_agent: mintlayer_core_user_agent(),
        common_services: [Service::Blocks].as_slice().into(),
    }
}

pub fn expect_cmd_connect_to_one_of(
    cmd: &Command,
    addresses: &mut BTreeSet<SocketAddress>,
) -> SocketAddress {
    match cmd {
        Command::Connect {
            address,
            local_services_override: _,
        } => {
            log::debug!("Connection attempt to {address} detected");
            assert!(addresses.contains(address));
            addresses.remove(address);
            *address
        }
        cmd => {
            panic!("Unexpected command received: {cmd:?}");
        }
    }
}

pub fn expect_cmd_connect_to(cmd: &Command, expected_address: &SocketAddress) {
    match cmd {
        Command::Connect {
            address,
            local_services_override: _,
        } => {
            assert_eq!(address, expected_address);
        }
        cmd => {
            panic!("Unexpected command received: {cmd:?}");
        }
    }
}

/// Send a ConnectivityEvent simulating a connection being accepted by the backend.
pub fn inbound_block_relay_peer_accepted_by_backend(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_address: SocketAddress,
    bind_address: SocketAddress,
    chain_config: &ChainConfig,
) -> PeerId {
    let peer_id = PeerId::new();
    conn_event_sender
        .send(ConnectivityEvent::InboundAccepted {
            peer_address,
            bind_address,
            peer_info: make_block_relay_peer_info(peer_id, chain_config),
            node_address_as_seen_by_peer: None,
        })
        .unwrap();

    peer_id
}

/// Send a ConnectivityEvent simulating a connection being accepted by the backend.
pub fn inbound_full_relay_peer_accepted_by_backend(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_address: SocketAddress,
    bind_address: SocketAddress,
    chain_config: &ChainConfig,
) -> PeerId {
    let peer_id = PeerId::new();
    conn_event_sender
        .send(ConnectivityEvent::InboundAccepted {
            peer_address,
            bind_address,
            peer_info: make_full_relay_peer_info(peer_id, chain_config),
            node_address_as_seen_by_peer: None,
        })
        .unwrap();

    peer_id
}

/// Send a ConnectivityEvent simulating a connection being accepted by the backend.
pub fn outbound_block_relay_peer_accepted_by_backend(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_address: SocketAddress,
    bind_address: SocketAddress,
    chain_config: &ChainConfig,
) -> PeerId {
    let peer_id = PeerId::new();
    conn_event_sender
        .send(ConnectivityEvent::OutboundAccepted {
            peer_address,
            bind_address,
            peer_info: make_block_relay_peer_info(peer_id, chain_config),
            node_address_as_seen_by_peer: None,
        })
        .unwrap();

    peer_id
}

/// Send a ConnectivityEvent simulating a connection being accepted by the backend.
pub fn outbound_full_relay_peer_accepted_by_backend(
    conn_event_sender: &mpsc::UnboundedSender<ConnectivityEvent>,
    peer_address: SocketAddress,
    bind_address: SocketAddress,
    chain_config: &ChainConfig,
) -> PeerId {
    let peer_id = PeerId::new();
    conn_event_sender
        .send(ConnectivityEvent::OutboundAccepted {
            peer_address,
            bind_address,
            peer_info: make_full_relay_peer_info(peer_id, chain_config),
            node_address_as_seen_by_peer: None,
        })
        .unwrap();

    peer_id
}

pub async fn wait_for_heartbeat(
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
) {
    wait_for_recv(
        peer_mgr_notification_receiver,
        &PeerManagerNotification::Heartbeat,
    )
    .await;
}

pub async fn query_peer_manager<F, R>(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    query_func: F,
) -> R
where
    F: FnOnce(&dyn PeerManagerInterface) -> R + Send + 'static,
    R: Send + 'static,
{
    let (response_sender, mut response_receiver) = mpsc::unbounded_channel();

    peer_mgr_event_sender
        .send(PeerManagerEvent::GenericQuery(Box::new(
            move |peer_mgr: &dyn PeerManagerInterface| {
                let res = query_func(peer_mgr);
                response_sender.send(res).unwrap();
            },
        )))
        .unwrap();

    response_receiver.recv().await.unwrap()
}

pub async fn mutate_peer_manager<F, R>(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    mut_func: F,
) -> R
where
    F: FnOnce(&mut dyn PeerManagerInterface) -> R + Send + 'static,
    R: Send + 'static,
{
    let (response_sender, mut response_receiver) = mpsc::unbounded_channel();

    peer_mgr_event_sender
        .send(PeerManagerEvent::GenericMut(Box::new(
            move |peer_mgr: &mut dyn PeerManagerInterface| {
                let res = mut_func(peer_mgr);
                response_sender.send(res).unwrap();
            },
        )))
        .unwrap();

    response_receiver.recv().await.unwrap()
}

pub fn start_manually_connecting(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    addr: SocketAddress,
) -> oneshot_nofail::Receiver<crate::Result<()>> {
    let (result_sender, result_receiver) = oneshot_nofail::channel();

    let addr = IpOrSocketAddress::new_socket_address(addr.socket_addr());
    peer_mgr_event_sender
        .send(PeerManagerEvent::Connect(addr, result_sender))
        .unwrap();

    result_receiver
}

pub async fn adjust_peer_score(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    peer_id: PeerId,
    score_adjustment: u32,
) {
    let (result_sender, result_receiver) = oneshot_nofail::channel();

    peer_mgr_event_sender
        .send(PeerManagerEvent::AdjustPeerScore(
            peer_id,
            score_adjustment,
            result_sender,
        ))
        .unwrap();

    result_receiver.await.unwrap().unwrap();
}

pub async fn ban_peer_manually(
    peer_mgr_event_sender: &mpsc::UnboundedSender<PeerManagerEvent>,
    peer_addr: BannableAddress,
    duration: Duration,
) {
    let (result_sender, result_receiver) = oneshot_nofail::channel();

    peer_mgr_event_sender
        .send(PeerManagerEvent::Ban(peer_addr, duration, result_sender))
        .unwrap();

    result_receiver.await.unwrap().unwrap();
}
