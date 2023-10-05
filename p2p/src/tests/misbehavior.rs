// Copyright (c) 2021-2023 RBB S.r.l
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

use chainstate::ban_score::BanScore;
use test_utils::assert_matches;

use crate::{
    error::{P2pError, ProtocolError},
    net::default_backend::{
        transport::{BufferedTranscoder, TransportSocket},
        types::{HandshakeMessage, Message, P2pTimestamp},
    },
    testing_utils::{
        test_p2p_config, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp, TEST_PROTOCOL_VERSION,
    },
    tests::helpers::{timeout, PeerManagerNotification, TestNode},
};

async fn unexpected_handshake_message<TTM>()
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());

    let mut test_node = TestNode::<TTM>::start(
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TTM::make_address(),
        TEST_PROTOCOL_VERSION.into(),
    )
    .await;

    let transport = TTM::make_transport();

    let stream = transport.connect(*test_node.local_address()).await.unwrap();

    let mut msg_stream = BufferedTranscoder::new(stream, *p2p_config.max_message_size);

    // Send the normal Hello
    msg_stream
        .send(Message::Handshake(HandshakeMessage::Hello {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            services: (*p2p_config.node_type).into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(
                test_node.time_getter().get_time_getter().get_time(),
            ),
            handshake_nonce: 0,
        }))
        .await
        .unwrap();

    let msg = msg_stream.recv().await.unwrap();
    assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

    // Check that the connection is still up and we can receive the next message (we don't care
    // which one it is though).
    let _msg = msg_stream.recv().await.unwrap();

    // Send an unexpected Hello
    msg_stream
        .send(Message::Handshake(HandshakeMessage::Hello {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            services: (*p2p_config.node_type).into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(
                test_node.time_getter().get_time_getter().get_time(),
            ),
            handshake_nonce: 0,
        }))
        .await
        .unwrap();

    // This is mainly needed to ensure that the corresponding event reaches peer manager before
    // we end the test.
    assert_matches!(
        test_node.expect_peer_mgr_notification().await,
        PeerManagerNotification::BanScoreAdjustment {
            address: _,
            new_score: _
        }
    );

    let test_node_remnants = test_node.join().await;

    assert_eq!(test_node_remnants.peer_mgr.peers().len(), 1);
    let peer_score = test_node_remnants.peer_mgr.peers().first_key_value().unwrap().1.score;
    let expected_score =
        P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned())).ban_score();
    assert_eq!(peer_score, expected_score);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unexpected_handshake_message_tcp() {
    timeout(unexpected_handshake_message::<TestTransportTcp>()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unexpected_handshake_message_channels() {
    timeout(unexpected_handshake_message::<TestTransportChannel>()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unexpected_handshake_message_noise() {
    timeout(unexpected_handshake_message::<TestTransportNoise>()).await;
}
