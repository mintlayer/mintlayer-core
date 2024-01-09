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
use p2p_types::{services::Service, socket_address::SocketAddress, PeerId};
use test_utils::assert_matches_return_val;

use crate::{
    config::NodeType,
    message::PeerManagerMessage,
    net::{
        default_backend::types::{CategorizedMessage, Command},
        types::PeerInfo,
    },
    testing_utils::TEST_PROTOCOL_VERSION,
    tests::helpers::PeerManagerNotification,
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

pub fn expect_connect_cmd(cmd: &Command, addresses: &mut BTreeSet<SocketAddress>) -> SocketAddress {
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

pub async fn wait_for_heartbeat(
    peer_mgr_notification_receiver: &mut mpsc::UnboundedReceiver<PeerManagerNotification>,
) {
    wait_for_recv(
        peer_mgr_notification_receiver,
        &PeerManagerNotification::Heartbeat,
    )
    .await;
}
