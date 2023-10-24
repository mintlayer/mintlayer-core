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

use std::{sync::Arc, time::Duration};

use common::{chain::config, primitives::user_agent::mintlayer_core_user_agent};
use p2p_test_utils::{expect_recv, P2pBasicTestTimeGetter};
use test_utils::{assert_matches, assert_matches_return_val};

use crate::{
    config::{NodeType, P2pConfig},
    message::{PeerManagerMessage, PingRequest, PingResponse},
    net::{
        default_backend::{
            transport::TcpTransportSocket, types::Command, ConnectivityHandle,
            DefaultNetworkingService,
        },
        types::{ConnectivityEvent, PeerInfo},
    },
    peer_manager::{
        tests::{send_and_sync, utils::cmd_to_peer_man_msg},
        PeerManager,
    },
    testing_utils::{peerdb_inmemory_store, TEST_PROTOCOL_VERSION},
    types::peer_id::PeerId,
    PeerManagerEvent,
};

#[tracing::instrument]
#[tokio::test]
async fn ping_timeout() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_mainnet());
    let p2p_config: Arc<P2pConfig> = Arc::new(P2pConfig {
        ping_check_period: Duration::from_secs(1).into(),
        ping_timeout: Duration::from_secs(5).into(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        sync_stalling_timeout: Default::default(),
        enable_block_relay_peers: Default::default(),
        connection_count_limits: Default::default(),
    });
    let ping_check_period = *p2p_config.ping_check_period;
    let ping_timeout = *p2p_config.ping_timeout;

    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = P2pBasicTestTimeGetter::new();
    let connectivity_handle =
        ConnectivityHandle::<TestNetworkingService>::new(vec![], cmd_tx, conn_rx);

    let peer_manager = PeerManager::<TestNetworkingService, _>::new(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_rx,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    logging::spawn_in_current_span(async move {
        let _ = peer_manager.run().await;
    });

    // Notify about new inbound connection
    conn_tx
        .send(ConnectivityEvent::InboundAccepted {
            address: "123.123.123.123:12345".parse().unwrap(),
            peer_info: PeerInfo {
                peer_id: PeerId::new(),
                protocol_version: TEST_PROTOCOL_VERSION,
                network: *chain_config.magic_bytes(),
                software_version: *chain_config.software_version(),
                user_agent: p2p_config.user_agent.clone(),
                common_services: NodeType::Full.into(),
            },
            receiver_address: None,
        })
        .unwrap();

    let event = expect_recv!(cmd_rx);
    match event {
        Command::Accept { peer_id: _ } => {}
        _ => panic!("unexpected event: {event:?}"),
    }

    // Receive ping requests and send responses normally
    for _ in 0..5 {
        time_getter.advance_time(ping_check_period);

        let cmd = expect_recv!(cmd_rx);
        let (peer_id, peer_msg) = cmd_to_peer_man_msg(cmd);
        let nonce = assert_matches_return_val!(
            peer_msg,
            PeerManagerMessage::PingRequest(PingRequest { nonce },),
            nonce
        );
        send_and_sync(
            peer_id,
            PeerManagerMessage::PingResponse(PingResponse { nonce }),
            &conn_tx,
            &mut cmd_rx,
        )
        .await;
    }

    // Receive one more ping request but do not send a ping response
    time_getter.advance_time(ping_check_period);
    let cmd = expect_recv!(cmd_rx);
    let (_, peer_msg) = cmd_to_peer_man_msg(cmd);
    assert_matches!(
        peer_msg,
        PeerManagerMessage::PingRequest(PingRequest { nonce: _ })
    );

    time_getter.advance_time(ping_timeout);

    // PeerManager should ask backend to close connection
    let event = expect_recv!(cmd_rx);
    match event {
        Command::Disconnect { peer_id } => {
            conn_tx.send(ConnectivityEvent::ConnectionClosed { peer_id }).unwrap();
        }
        _ => panic!("unexpected event: {event:?}"),
    }
}
