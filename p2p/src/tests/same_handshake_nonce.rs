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

use std::sync::Arc;

use networking::test_helpers::{
    TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
};
use networking::transport::{BufferedTranscoder, TransportListener, TransportSocket};
use p2p_test_utils::run_with_timeout;
use test_utils::{assert_matches, BasicTestTimeGetter};

use crate::{
    disconnection_reason::DisconnectionReason,
    message::WillDisconnectMessage,
    net::default_backend::types::{HandshakeMessage, Message, P2pTimestamp},
    protocol::SupportedProtocolVersion,
    test_helpers::test_p2p_config,
    tests::helpers::TestNode,
};

// Simulate a self-connection by sending the same nonce in Hello.
// Check that the WillDisconnect message is sent if the protocol version is big enough.
async fn same_handshake_nonce<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    for protocol_version in [SupportedProtocolVersion::V2, SupportedProtocolVersion::V3] {
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let p2p_config = Arc::new(test_p2p_config());

        let test_node = TestNode::<TTM::Transport>::start(
            true,
            time_getter.clone(),
            Arc::clone(&chain_config),
            Arc::clone(&p2p_config),
            TTM::make_transport(),
            TTM::make_address().into(),
            protocol_version.into(),
            None,
        )
        .await;

        let transport = TTM::make_transport();
        let mut listener = transport.bind(vec![TTM::make_address()]).await.unwrap();

        let outgoing_conn_address = listener.local_addresses().unwrap()[0].into();
        let _outgoing_connect_result_receiver = test_node.start_connecting(outgoing_conn_address);

        let (outgoing_conn_stream, _) = listener.accept().await.unwrap();

        let mut outgoing_conn_msg_stream = BufferedTranscoder::new(
            outgoing_conn_stream,
            Some(*p2p_config.protocol_config.max_message_size),
        );

        let msg = outgoing_conn_msg_stream.recv().await.unwrap();
        let Message::Handshake(HandshakeMessage::Hello {
            protocol_version: _,
            network: _,
            services: _,
            user_agent: _,
            software_version: _,
            receiver_address: _,
            current_time: _,
            handshake_nonce,
        }) = msg
        else {
            panic!("Unexpected message: {msg:?}");
        };
        assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

        let incoming_conn_stream =
            transport.connect(test_node.local_address().socket_addr()).await.unwrap();

        let mut incoming_conn_msg_stream = BufferedTranscoder::new(
            incoming_conn_stream,
            Some(*p2p_config.protocol_config.max_message_size),
        );

        incoming_conn_msg_stream
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: protocol_version.into(),
                network: *chain_config.magic_bytes(),
                user_agent: p2p_config.user_agent.clone(),
                software_version: *chain_config.software_version(),
                services: (*p2p_config.node_type).into(),
                receiver_address: None,
                current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
                handshake_nonce,
            }))
            .await
            .unwrap();

        let msg = incoming_conn_msg_stream.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

        if protocol_version >= SupportedProtocolVersion::V3 {
            // WillDisconnect should be sent.
            let msg = incoming_conn_msg_stream.recv().await.unwrap();
            assert_eq!(
                msg,
                Message::WillDisconnect(WillDisconnectMessage {
                    reason: (DisconnectionReason::ConnectionFromSelf).to_string()
                })
            );
        }

        // The connection should be closed.
        incoming_conn_msg_stream.recv().await.unwrap_err();

        test_node.join().await;
    }
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_handshake_nonce_tcp() {
    run_with_timeout(same_handshake_nonce::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_handshake_nonce_channels() {
    run_with_timeout(same_handshake_nonce::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_handshake_nonce_noise() {
    run_with_timeout(same_handshake_nonce::<TestTransportNoise>()).await;
}
