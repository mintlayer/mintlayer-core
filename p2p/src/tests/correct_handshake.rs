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

use networking::test_helpers::{
    TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
};
use networking::transport::{BufferedTranscoder, TransportListener, TransportSocket};
use p2p_test_utils::run_with_timeout;
use test_utils::{assert_matches, BasicTestTimeGetter};

use crate::{
    net::default_backend::types::{HandshakeMessage, Message, P2pTimestamp},
    peer_manager::PeerManagerInterface,
    test_helpers::{test_p2p_config, TEST_PROTOCOL_VERSION},
    tests::helpers::TestNode,
};

// Note: these tests are mainly a sanity check to ensure that the corresponding test harness
// is working properly.

async fn correct_handshake_outgoing<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let time_getter = BasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let mut test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TTM::make_transport(),
        TTM::make_address().into(),
        TEST_PROTOCOL_VERSION.into(),
        None,
    )
    .await;

    let transport = TTM::make_transport();
    let mut listener = transport.bind(vec![TTM::make_address()]).await.unwrap();

    let connect_result_receiver =
        test_node.start_connecting(listener.local_addresses().unwrap()[0].into());

    let (stream, _) = listener.accept().await.unwrap();

    let mut msg_stream =
        BufferedTranscoder::new(stream, Some(*p2p_config.protocol_config.max_message_size));

    let msg = msg_stream.recv().await.unwrap();
    assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

    msg_stream
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

    let connect_result = connect_result_receiver.await.unwrap();
    assert!(connect_result.is_ok());

    // Check that the connection is still up and we can receive the next message (we don't care
    // which one it is though).
    let _msg = msg_stream.recv().await.unwrap();

    // This is mainly needed to ensure that the corresponding events, if any, reach
    // peer manager before we end the test.
    test_node.expect_no_punishment().await;

    let test_node_remnants = test_node.join().await;

    let bans_count = test_node_remnants.peer_mgr.peerdb().list_banned().count();
    assert_eq!(bans_count, 0);
    let discouragements_count = test_node_remnants.peer_mgr.peerdb().list_discouraged().count();
    assert_eq!(discouragements_count, 0);

    assert_eq!(test_node_remnants.peer_mgr.peers().len(), 1);
    let peer_score = test_node_remnants.peer_mgr.peers().first_key_value().unwrap().1.score;
    assert_eq!(peer_score, 0);
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_handshake_outgoing_tcp() {
    run_with_timeout(correct_handshake_outgoing::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_handshake_outgoing_channels() {
    run_with_timeout(correct_handshake_outgoing::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_handshake_outgoing_noise() {
    run_with_timeout(correct_handshake_outgoing::<TestTransportNoise>()).await;
}

async fn correct_handshake_incoming<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let time_getter = BasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let mut test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
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

    // Check that the connection is still up and we can receive the next message (we don't care
    // which one it is though).
    let _msg = msg_stream.recv().await.unwrap();

    // This is mainly needed to ensure that the corresponding events, if any, reach
    // peer manager before we end the test.
    test_node.expect_no_punishment().await;

    let test_node_remnants = test_node.join().await;

    let bans_count = test_node_remnants.peer_mgr.peerdb().list_banned().count();
    assert_eq!(bans_count, 0);
    let discouragements_count = test_node_remnants.peer_mgr.peerdb().list_discouraged().count();
    assert_eq!(discouragements_count, 0);

    assert_eq!(test_node_remnants.peer_mgr.peers().len(), 1);
    let peer_score = test_node_remnants.peer_mgr.peers().first_key_value().unwrap().1.score;
    assert_eq!(peer_score, 0);
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_handshake_incoming_tcp() {
    run_with_timeout(correct_handshake_incoming::<TestTransportTcp>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_handshake_incoming_channels() {
    run_with_timeout(correct_handshake_incoming::<TestTransportChannel>()).await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_handshake_incoming_noise() {
    run_with_timeout(correct_handshake_incoming::<TestTransportNoise>()).await;
}
