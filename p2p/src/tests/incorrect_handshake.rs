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

use test_utils::assert_matches;

use crate::{
    message::HeaderList,
    net::default_backend::{
        transport::{BufferedTranscoder, TransportListener, TransportSocket},
        types::{HandshakeMessage, Message},
    },
    testing_utils::{
        test_p2p_config, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp, TEST_PROTOCOL_VERSION,
    },
    tests::helpers::{timeout, PeerManagerNotification, TestNode},
};

async fn incorrect_handshake_outgoing<TTM>()
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
    let mut listener = transport.bind(vec![TTM::make_address()]).await.unwrap();

    let address = listener.local_addresses().unwrap()[0];
    let connect_result_rx = test_node.start_connecting(address);

    let (stream, _) = listener.accept().await.unwrap();

    let mut msg_stream = BufferedTranscoder::new(stream, *p2p_config.max_message_size);

    let msg = msg_stream.recv().await.unwrap();
    assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

    // Send some other message instead of HelloAck.
    msg_stream.send(Message::HeaderList(HeaderList::new(Vec::new()))).await.unwrap();

    // connect_result should indicate a failed connection
    let connect_result = connect_result_rx.await.unwrap();
    assert!(connect_result.is_err());

    // The connection should be closed.
    msg_stream.recv().await.unwrap_err();

    // This is mainly needed to ensure that the corresponding events, if any, reach
    // peer manager before we end the test.
    test_node.expect_no_banning().await;

    // Note: no peer ban here, because peers are not banned during "manual outbound" connections.
    let test_node_remnants = test_node.join().await;
    assert_eq!(
        test_node_remnants.peer_mgr.peerdb().list_banned().count(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_handshake_outgoing_tcp() {
    timeout(incorrect_handshake_outgoing::<TestTransportTcp>()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_handshake_outgoing_channels() {
    timeout(incorrect_handshake_outgoing::<TestTransportChannel>()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_handshake_outgoing_noise() {
    timeout(incorrect_handshake_outgoing::<TestTransportNoise>()).await;
}

async fn incorrect_handshake_incoming<TTM>()
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

    // Send some other message instead of Hello.
    msg_stream.send(Message::HeaderList(HeaderList::new(Vec::new()))).await.unwrap();

    // The connection should be closed.
    msg_stream.recv().await.unwrap_err();

    // This is mainly needed to ensure that the corresponding event reaches peer manager before
    // we end the test.
    assert_matches!(
        test_node.expect_peer_mgr_notification().await,
        PeerManagerNotification::BanScoreAdjustment {
            address: _,
            new_score: _
        }
    );

    // The peer address should be banned.
    let test_node_remnants = test_node.join().await;
    // TODO: check the actual address instead of the count, same in other places.
    assert!(test_node_remnants.peer_mgr.peerdb().list_banned().count() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_handshake_incoming_tcp() {
    timeout(incorrect_handshake_incoming::<TestTransportTcp>()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_handshake_incoming_channels() {
    timeout(incorrect_handshake_incoming::<TestTransportChannel>()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incorrect_handshake_incoming_noise() {
    timeout(incorrect_handshake_incoming::<TestTransportNoise>()).await;
}
