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
use networking::test_helpers::{TestTransportMaker, TestTransportTcp};
use networking::transport::TcpTransportSocket;
use p2p_test_utils::expect_recv;
use test_utils::{assert_matches, assert_matches_return_val, BasicTestTimeGetter};

use crate::{
    config::{NodeType, P2pConfig},
    disconnection_reason::DisconnectionReason,
    message::{PeerManagerMessage, PingRequest, PingResponse},
    net::{
        default_backend::{types::Command, ConnectivityHandle, DefaultNetworkingService},
        types::{ConnectivityEvent, PeerInfo},
    },
    peer_manager::{
        tests::{send_and_sync, utils::cmd_to_peer_man_msg},
        PeerManager,
    },
    test_helpers::{peerdb_inmemory_store, TEST_PROTOCOL_VERSION},
    types::peer_id::PeerId,
    PeerManagerEvent,
};

#[tracing::instrument]
#[tokio::test]
async fn ping_timeout() {
    type TestNetworkingService = DefaultNetworkingService<TcpTransportSocket>;

    let chain_config = Arc::new(config::create_unit_test_config());
    let p2p_config: Arc<P2pConfig> = Arc::new(P2pConfig {
        ping_check_period: Duration::from_secs(1).into(),
        ping_timeout: Duration::from_secs(5).into(),

        bind_addresses: Default::default(),
        socks5_proxy: None,
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        outbound_connection_timeout: Default::default(),
        peer_handshake_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
    });
    let ping_check_period = *p2p_config.ping_check_period;
    let ping_timeout = *p2p_config.ping_timeout;

    let (cmd_sender, mut cmd_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (conn_event_sender, conn_event_receiver) = tokio::sync::mpsc::unbounded_channel();
    let (_peer_mgr_event_sender, peer_mgr_event_receiver) =
        tokio::sync::mpsc::unbounded_channel::<PeerManagerEvent>();
    let time_getter = BasicTestTimeGetter::new();
    let bind_address = TestTransportTcp::make_address().into();
    let connectivity_handle = ConnectivityHandle::<TestNetworkingService>::new(
        vec![bind_address],
        cmd_sender,
        conn_event_receiver,
    );

    let peer_manager = PeerManager::<TestNetworkingService, _>::new(
        true,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        connectivity_handle,
        peer_mgr_event_receiver,
        time_getter.get_time_getter(),
        peerdb_inmemory_store(),
    )
    .unwrap();

    logging::spawn_in_current_span(async move {
        let _ = peer_manager.run().await;
    });

    // Notify about new inbound connection
    conn_event_sender
        .send(ConnectivityEvent::InboundAccepted {
            peer_address: "123.123.123.123:12345".parse().unwrap(),
            bind_address,
            peer_info: PeerInfo {
                peer_id: PeerId::new(),
                protocol_version: TEST_PROTOCOL_VERSION,
                network: *chain_config.magic_bytes(),
                software_version: *chain_config.software_version(),
                user_agent: p2p_config.user_agent.clone(),
                common_services: NodeType::Full.into(),
            },
            node_address_as_seen_by_peer: None,
        })
        .unwrap();

    let event = expect_recv!(cmd_receiver);
    match event {
        Command::Accept { peer_id: _ } => {}
        _ => panic!("unexpected event: {event:?}"),
    }

    // Receive ping requests and send responses normally
    for _ in 0..5 {
        time_getter.advance_time(ping_check_period);

        let cmd = expect_recv!(cmd_receiver);
        let (peer_id, peer_msg) = cmd_to_peer_man_msg(cmd);
        let nonce = assert_matches_return_val!(
            peer_msg,
            PeerManagerMessage::PingRequest(PingRequest { nonce },),
            nonce
        );
        send_and_sync(
            peer_id,
            PeerManagerMessage::PingResponse(PingResponse { nonce }),
            &conn_event_sender,
            &mut cmd_receiver,
        )
        .await;
    }

    // Receive one more ping request but do not send a ping response
    time_getter.advance_time(ping_check_period);
    let cmd = expect_recv!(cmd_receiver);
    let (_, peer_msg) = cmd_to_peer_man_msg(cmd);
    assert_matches!(
        peer_msg,
        PeerManagerMessage::PingRequest(PingRequest { nonce: _ })
    );

    time_getter.advance_time(ping_timeout);

    // PeerManager should ask backend to close connection
    let event = expect_recv!(cmd_receiver);
    match event {
        Command::Disconnect { peer_id, reason } => {
            assert_eq!(reason, Some(DisconnectionReason::PingIgnored));
            conn_event_sender.send(ConnectivityEvent::ConnectionClosed { peer_id }).unwrap();
        }
        _ => panic!("unexpected event: {event:?}"),
    }
}
