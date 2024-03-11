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

use std::sync::Arc;

use p2p_test_utils::{run_with_timeout, P2pBasicTestTimeGetter};
use test_utils::assert_matches;

use crate::{
    net::default_backend::{
        transport::{BufferedTranscoder, TransportListener, TransportSocket},
        types::{HandshakeMessage, Message, P2pTimestamp},
    },
    protocol::ProtocolVersion,
    testing_utils::{
        test_p2p_config, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp, TEST_PROTOCOL_VERSION,
    },
    tests::helpers::TestNode,
};

async fn unsupported_version_outgoing<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TTM::make_transport(),
        TTM::make_address(),
        TEST_PROTOCOL_VERSION.into(),
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

    // Send HelloAck with zero protocol version
    msg_stream
        .send(Message::Handshake(HandshakeMessage::HelloAck {
            protocol_version: ProtocolVersion::new(0),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            services: (*p2p_config.node_type).into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
        }))
        .await
        .unwrap();

    // connect_result should indicate a failed connection
    let connect_result = connect_result_receiver.await.unwrap();
    assert!(connect_result.is_err());

    // The connection should be closed.
    msg_stream.recv().await.unwrap_err();

    // Note: no peer discouragement here, because peers are not discouraged during
    // "manual outbound" connections.
    let test_node_remnants = test_node.join().await;
    assert_eq!(
        test_node_remnants.peer_mgr.peerdb().list_discouraged().count(),
        0
    );
    assert_eq!(
        test_node_remnants.peer_mgr.peerdb().list_banned().count(),
        0
    );
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_outgoing_tcp() {
    run_with_timeout(unsupported_version_outgoing::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_outgoing_channels() {
    run_with_timeout(unsupported_version_outgoing::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_outgoing_noise() {
    run_with_timeout(unsupported_version_outgoing::<TestTransportNoise>()).await;
}

async fn unsupported_version_incoming<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TTM::make_transport(),
        TTM::make_address(),
        TEST_PROTOCOL_VERSION.into(),
        None,
    )
    .await;

    let transport = TTM::make_transport();

    let stream = transport.connect(*test_node.local_address()).await.unwrap();

    let mut msg_stream =
        BufferedTranscoder::new(stream, *p2p_config.protocol_config.max_message_size);

    // Send Hello with zero protocol version
    msg_stream
        .send(Message::Handshake(HandshakeMessage::Hello {
            protocol_version: ProtocolVersion::new(0),
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

    // The connection should be closed.
    msg_stream.recv().await.unwrap_err();

    // Note: no peer discouragement here, because the UnsupportedProtocol error has zero ban score.
    let test_node_remnants = test_node.join().await;
    assert_eq!(
        test_node_remnants.peer_mgr.peerdb().list_discouraged().count(),
        0
    );
    assert_eq!(
        test_node_remnants.peer_mgr.peerdb().list_banned().count(),
        0
    );
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_incoming_tcp() {
    run_with_timeout(unsupported_version_incoming::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_incoming_channels() {
    run_with_timeout(unsupported_version_incoming::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_incoming_noise() {
    run_with_timeout(unsupported_version_incoming::<TestTransportNoise>()).await;
}

// Here we have a peer with an unsupported version and a normal peer connected at the same time.
// The unsupported peer should be disconnected, while the normal one should remain connected.
async fn unsupported_version_two_peers<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let time_getter = P2pBasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TTM::make_transport(),
        TTM::make_address(),
        TEST_PROTOCOL_VERSION.into(),
        None,
    )
    .await;

    let transport1 = TTM::make_transport();
    let mut listener1 = transport1.bind(vec![TTM::make_address()]).await.unwrap();

    let address1 = listener1.local_addresses().unwrap()[0];
    let connect_result_receiver1 = test_node.start_connecting(address1);

    let (stream1, _) = listener1.accept().await.unwrap();
    let mut msg_stream1 =
        BufferedTranscoder::new(stream1, *p2p_config.protocol_config.max_message_size);

    let transport2 = TTM::make_transport();
    let mut listener2 = transport2.bind(vec![TTM::make_address()]).await.unwrap();

    let address2 = listener2.local_addresses().unwrap()[0];
    let connect_result_receiver2 = test_node.start_connecting(address2);

    let (stream2, _) = listener2.accept().await.unwrap();
    let mut msg_stream2 =
        BufferedTranscoder::new(stream2, *p2p_config.protocol_config.max_message_size);

    let msg = msg_stream2.recv().await.unwrap();
    assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

    // Send normal HelloAck from peer 1
    msg_stream1
        .send(Message::Handshake(HandshakeMessage::HelloAck {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            services: (*p2p_config.node_type).into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
        }))
        .await
        .unwrap();

    // Send HelloAck with zero protocol version from peer 2
    msg_stream2
        .send(Message::Handshake(HandshakeMessage::HelloAck {
            protocol_version: ProtocolVersion::new(0),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            services: (*p2p_config.node_type).into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(time_getter.get_time_getter().get_time()),
        }))
        .await
        .unwrap();

    // connect_result2 should indicate a failed connection
    let connect_result2 = connect_result_receiver2.await.unwrap();
    assert!(connect_result2.is_err());

    // The connection should be closed.
    msg_stream2.recv().await.unwrap_err();

    // But connect_result1 should still be fine.
    let connect_result1 = connect_result_receiver1.await.unwrap();
    assert!(connect_result1.is_ok());
    let _msg = msg_stream1.recv().await.unwrap();

    test_node.join().await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_two_peers_tcp() {
    run_with_timeout(unsupported_version_two_peers::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_two_peers_channels() {
    run_with_timeout(unsupported_version_two_peers::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_version_two_peers_noise() {
    run_with_timeout(unsupported_version_two_peers::<TestTransportNoise>()).await;
}
