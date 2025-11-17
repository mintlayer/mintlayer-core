// Copyright (c) 2021-2025 RBB S.r.l
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

use chainstate::ChainstateConfig;
use common::{chain::Transaction, primitives::Id};
use networking::{
    test_helpers::{TestTransportChannel, TestTransportMaker},
    transport::{BufferedTranscoder, TransportSocket as _},
};
use p2p_test_utils::run_with_timeout;
use serialization::{Decode, Encode};
use test_utils::{
    assert_matches, assert_matches_return_val,
    random::{gen_random_bytes, Seed},
    BasicTestTimeGetter,
};

use crate::{
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, BlockListRequest, BlockResponse,
        HeaderList, HeaderListRequest, PingRequest, PingResponse, TransactionResponse,
        WillDisconnectMessage,
    },
    net::default_backend::types::{HandshakeMessage, P2pTimestamp},
    protocol::ProtocolConfig,
    test_helpers::{test_p2p_config_with_protocol_config, TEST_PROTOCOL_VERSION},
    tests::helpers::TestNode,
};

// A peer sends a message which
// a) can't be decoded due to having an unsupported enum variant;
// b) same as above, but it also exceeds the size limit.
// Expected result:
// 1) WillDisconnect is send to the peer, the message depends on whether it's case a or b;
// 2) The peer is discouraged with the ban score of 100 and this fact is reflected in the peer db.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_message(#[case] seed: Seed, #[values(false, true)] make_msg_too_big: bool) {
    run_with_timeout(unsupported_message_impl(seed, make_msg_too_big)).await;
}

async fn unsupported_message_impl(seed: Seed, make_msg_too_big: bool) {
    type Transport = <TestTransportChannel as TestTransportMaker>::Transport;

    let mut rng = test_utils::random::make_seedable_rng(seed);
    let time_getter = BasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let max_message_size = 1024;
    let max_message_size_for_peer = max_message_size * 2;
    let p2p_config = Arc::new(test_p2p_config_with_protocol_config(ProtocolConfig {
        max_message_size: max_message_size.into(),

        msg_header_count_limit: Default::default(),
        max_request_blocks_count: Default::default(),
        max_addr_list_response_address_count: Default::default(),
        msg_max_locator_count: Default::default(),
        max_peer_tx_announcements: Default::default(),
    }));

    let mut test_node = TestNode::<Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        Arc::clone(&p2p_config),
        TestTransportChannel::make_transport(),
        TestTransportChannel::make_address().into(),
        TEST_PROTOCOL_VERSION.into(),
        None,
    )
    .await;

    let transport = TestTransportChannel::make_transport();
    let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();

    let mut msg_stream = BufferedTranscoder::new(stream, Some(max_message_size_for_peer));

    msg_stream
        .send(TestMessage::Handshake(HandshakeMessage::Hello {
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
    assert_matches!(
        msg,
        TestMessage::Handshake(HandshakeMessage::HelloAck { .. })
    );

    // Handshake has completed successfully; the node requests for headers.
    let msg = msg_stream.recv().await.unwrap();
    assert_matches!(
        msg,
        TestMessage::HeaderListRequest(HeaderListRequest { .. })
    );

    let msg_data = if make_msg_too_big {
        gen_random_bytes(&mut rng, max_message_size, max_message_size_for_peer)
    } else {
        gen_random_bytes(&mut rng, 1, max_message_size / 2)
    };
    let msg = TestMessage::UnsupportedVariant(msg_data);
    let msg_size = msg.encoded_size();

    msg_stream.send(msg).await.unwrap();

    // The node should send WillDisconnect. Since the message size check happens first, sending
    // too big a message will produce a size-related reason even though UnsupportedVariant
    // is sent in both cases.
    let msg = msg_stream.recv().await.unwrap();
    let disconnection_reason = assert_matches_return_val!(
        msg,
        TestMessage::WillDisconnect(WillDisconnectMessage { reason }),
        reason
    );
    let expected_disconnection_reason = if make_msg_too_big {
        format!("Your message size {msg_size} exceeded the maximum size {max_message_size}")
    } else {
        "Your message cannot be decoded (Could not decode `Message`, variant doesn't exist)"
            .to_owned()
    };
    assert_eq!(disconnection_reason, expected_disconnection_reason);

    // The connection should be closed.
    msg_stream.recv().await.unwrap_err();

    let (_, ban_score) = test_node.wait_for_ban_score_adjustment().await;
    assert_eq!(ban_score, 100);

    let test_node_remnants = test_node.join().await;

    let bans_count = test_node_remnants.peer_mgr.peerdb().list_banned().count();
    assert_eq!(bans_count, 0);
    let discouragements_count = test_node_remnants.peer_mgr.peerdb().list_discouraged().count();
    assert_eq!(discouragements_count, 1);
}

// Same as Message, but with UnsupportedVariant
#[derive(Debug, Encode, Decode)]
pub enum TestMessage {
    #[codec(index = 0)]
    Handshake(HandshakeMessage),

    #[codec(index = 1)]
    PingRequest(PingRequest),
    #[codec(index = 2)]
    PingResponse(PingResponse),

    #[codec(index = 3)]
    NewTransaction(Id<Transaction>),
    #[codec(index = 4)]
    HeaderListRequest(HeaderListRequest),
    #[codec(index = 5)]
    HeaderList(HeaderList),
    #[codec(index = 6)]
    BlockListRequest(BlockListRequest),
    #[codec(index = 7)]
    BlockResponse(BlockResponse),
    #[codec(index = 11)]
    TransactionRequest(Id<Transaction>),
    #[codec(index = 12)]
    TransactionResponse(TransactionResponse),

    #[codec(index = 8)]
    AnnounceAddrRequest(AnnounceAddrRequest),
    #[codec(index = 9)]
    AddrListRequest(AddrListRequest),
    #[codec(index = 10)]
    AddrListResponse(AddrListResponse),

    #[codec(index = 13)]
    WillDisconnect(WillDisconnectMessage),

    #[codec(index = 222)]
    UnsupportedVariant(Vec<u8>),
}
