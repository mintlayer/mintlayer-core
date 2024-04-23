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

use chainstate::{ChainstateConfig, Locator};
use networking::test_helpers::{
    TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
};
use networking::transport::{BufferedTranscoder, TransportSocket};
use p2p_test_utils::run_with_timeout;
use test_utils::{assert_matches, BasicTestTimeGetter};

use crate::{
    message::{HeaderList, HeaderListRequest, WillDisconnectMessage},
    net::default_backend::types::{HandshakeMessage, Message, P2pTimestamp},
    protocol::SupportedProtocolVersion,
    test_helpers::test_p2p_config,
    tests::helpers::TestNode,
};

// In this test we want a version that would result in the WillDisconnect message being sent.
const TEST_PROTOCOL_VERSION: SupportedProtocolVersion = SupportedProtocolVersion::V3;

// Check that the node will also initiate disconnection when it receives the WillDisconnect message.
async fn disconnect_on_will_disconnect_msg<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let time_getter = BasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        Arc::clone(&p2p_config),
        TTM::make_transport(),
        TTM::make_address().into(),
        TEST_PROTOCOL_VERSION.into(),
        None,
    )
    .await;

    let transport = TTM::make_transport();

    let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();

    let mut msg_stream =
        BufferedTranscoder::new(stream, Some(*p2p_config.protocol_config.max_message_size));

    msg_stream
        .send(Message::Handshake(HandshakeMessage::Hello {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            services: (*p2p_config.node_type).into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
            handshake_nonce: 0,
        }))
        .await
        .unwrap();

    let msg = msg_stream.recv().await.unwrap();
    assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

    // Handshake has completed successfully; the node requests for headers.
    let msg = msg_stream.recv().await.unwrap();
    assert_matches!(msg, Message::HeaderListRequest(HeaderListRequest { .. }));

    // The peer sends WillDisconnect, but then continues working as if nothing has happened.
    msg_stream
        .send(Message::WillDisconnect(WillDisconnectMessage {
            reason: "foo".to_owned(),
        }))
        .await
        .unwrap();

    // The peer responds with a header list and sends its own header list request.
    // Note that we don't check results of subsequent send calls, because the connection may be
    // dropped by the node at any moment.
    let _ = msg_stream.send(Message::HeaderList(HeaderList::new(vec![]))).await;
    // Note: if we send HeaderListRequest right away, there's a chance that the message will be
    // handled by the sync manager before the disconnection command reaches backend.
    std::thread::sleep(Duration::from_secs(1));
    let _ = msg_stream
        .send(Message::HeaderListRequest(HeaderListRequest::new(
            Locator::new(vec![]),
        )))
        .await;

    // The node shouldn't respond with headers; instead, the connection should be closed.
    msg_stream.recv().await.unwrap_err();

    test_node.join().await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_on_will_disconnect_msg_tcp() {
    run_with_timeout(disconnect_on_will_disconnect_msg::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_on_will_disconnect_msg_channels() {
    run_with_timeout(disconnect_on_will_disconnect_msg::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_on_will_disconnect_msg_noise() {
    run_with_timeout(disconnect_on_will_disconnect_msg::<TestTransportNoise>()).await;
}
