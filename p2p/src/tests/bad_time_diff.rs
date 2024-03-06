// Copyright (c) 2021-2024 RBB S.r.l
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

use common::primitives::{time::Time, user_agent::mintlayer_core_user_agent};
use p2p_test_utils::{run_with_timeout, P2pBasicTestTimeGetter};
use test_utils::assert_matches;

use crate::{
    config::P2pConfig,
    disconnection_reason::DisconnectionReason,
    message::WillDisconnectMessage,
    net::default_backend::{
        transport::{BufferedTranscoder, TransportListener, TransportSocket},
        types::{HandshakeMessage, Message, P2pTimestamp},
    },
    protocol::SupportedProtocolVersion,
    testing_utils::{
        TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
    },
    tests::helpers::TestNode,
};

// Check that a handshake is rejected if the time difference between the peers is too big.
// Also check that the WillDisconnect message is sent if the protocol version is big enough.

async fn bad_time_diff_outgoing<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    for protocol_version in [SupportedProtocolVersion::V2, SupportedProtocolVersion::V3] {
        let time_getter = P2pBasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let max_clock_diff = Duration::from_secs(1);
        let p2p_config = Arc::new(P2pConfig {
            max_clock_diff: max_clock_diff.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
        });

        let test_node = TestNode::<TTM::Transport>::start(
            time_getter.clone(),
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            TTM::make_transport(),
            TTM::make_address(),
            protocol_version.into(),
            None,
        )
        .await;

        let transport = TTM::make_transport();
        let mut listener = transport.bind(vec![TTM::make_address()]).await.unwrap();

        let address = listener.local_addresses().unwrap()[0];
        let connect_result_receiver = test_node.start_connecting(address);

        let (stream, _) = listener.accept().await.unwrap();

        let mut msg_stream =
            BufferedTranscoder::new(stream, *p2p_config.protocol_config.max_message_size);

        let msg = msg_stream.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

        let cur_time = time_getter.get_time_getter().get_time();
        let peer_time =
            P2pTimestamp::from_time(cur_time.saturating_duration_add(Duration::from_secs(1000)));

        msg_stream
            .send(Message::Handshake(HandshakeMessage::HelloAck {
                protocol_version: protocol_version.into(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: peer_time,
            }))
            .await
            .unwrap();

        // connect_result should indicate a failed connection
        let connect_result = connect_result_receiver.await.unwrap();
        assert!(connect_result.is_err());

        if protocol_version >= SupportedProtocolVersion::V3 {
            // WillDisconnect should be sent.
            let msg = msg_stream.recv().await.unwrap();
            assert_eq!(
                msg,
                Message::WillDisconnect(WillDisconnectMessage {
                    reason: (DisconnectionReason::TimeDiff {
                        remote_time: Time::from_duration_since_epoch(
                            peer_time.as_duration_since_epoch()
                        ),
                        accepted_peer_time: std::ops::RangeInclusive::new(
                            cur_time.saturating_duration_sub(max_clock_diff),
                            cur_time.saturating_duration_add(max_clock_diff)
                        ),
                    })
                    .to_string()
                })
            );
        }

        // The connection should be closed.
        msg_stream.recv().await.unwrap_err();

        test_node.join().await;
    }
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_time_diff_outgoing_tcp() {
    run_with_timeout(bad_time_diff_outgoing::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_time_diff_outgoing_channels() {
    run_with_timeout(bad_time_diff_outgoing::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_time_diff_outgoing_noise() {
    run_with_timeout(bad_time_diff_outgoing::<TestTransportNoise>()).await;
}

async fn bad_time_diff_incoming<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    for protocol_version in [SupportedProtocolVersion::V2, SupportedProtocolVersion::V3] {
        let time_getter = P2pBasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let max_clock_diff = Duration::from_secs(1);
        let p2p_config = Arc::new(P2pConfig {
            max_clock_diff: max_clock_diff.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
        });

        let test_node = TestNode::<TTM::Transport>::start(
            time_getter.clone(),
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            TTM::make_transport(),
            TTM::make_address(),
            protocol_version.into(),
            None,
        )
        .await;

        let transport = TTM::make_transport();

        let stream = transport.connect(*test_node.local_address()).await.unwrap();

        let mut msg_stream =
            BufferedTranscoder::new(stream, *p2p_config.protocol_config.max_message_size);

        let cur_time = time_getter.get_time_getter().get_time();
        let peer_time =
            P2pTimestamp::from_time(cur_time.saturating_duration_add(Duration::from_secs(1000)));

        msg_stream
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: protocol_version.into(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: peer_time,
                handshake_nonce: 0,
            }))
            .await
            .unwrap();

        if protocol_version >= SupportedProtocolVersion::V3 {
            // WillDisconnect should be sent.
            let msg = msg_stream.recv().await.unwrap();
            assert_eq!(
                msg,
                Message::WillDisconnect(WillDisconnectMessage {
                    reason: (DisconnectionReason::TimeDiff {
                        remote_time: Time::from_duration_since_epoch(
                            peer_time.as_duration_since_epoch()
                        ),
                        accepted_peer_time: std::ops::RangeInclusive::new(
                            cur_time.saturating_duration_sub(max_clock_diff),
                            cur_time.saturating_duration_add(max_clock_diff)
                        ),
                    })
                    .to_string()
                })
            );
        }

        // The connection should be closed.
        msg_stream.recv().await.unwrap_err();

        test_node.join().await;
    }
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_time_diff_incoming_tcp() {
    run_with_timeout(bad_time_diff_incoming::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_time_diff_incoming_channels() {
    run_with_timeout(bad_time_diff_incoming::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_time_diff_incoming_noise() {
    run_with_timeout(bad_time_diff_incoming::<TestTransportNoise>()).await;
}
