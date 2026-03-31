// Copyright (c) 2026 RBB S.r.l
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

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use rstest::rstest;
use strum::IntoEnumIterator as _;

use chainstate::{ChainstateConfig, Locator};
use common::primitives::Id;
use networking::{
    test_helpers::{TestTransportChannel, TestTransportMaker},
    transport::{new_message_stream, TransportListener, TransportSocket},
};
use p2p_test_utils::{run_with_timeout, MEDIUM_TIMEOUT, SHORT_TIMEOUT};
use p2p_types::peer_address::PeerAddress;
use randomness::{seq::IteratorRandom as _, Rng};
use test_utils::{
    assert_matches,
    random::{gen_random_alnum_string, make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    message::{
        AddrListRequest, AddrListResponse, AnnounceAddrRequest, BlockListRequest, BlockResponse,
        BlockSyncMessageTag, HeaderList, HeaderListRequest, PeerManagerMessageTag, PingRequest,
        PingResponse, TransactionResponse, TransactionSyncMessageTag, WillDisconnectMessage,
    },
    net::{
        default_backend::types::{HandshakeMessage, Message, P2pTimestamp},
        types::PeerManagerMessageExtTag,
    },
    sync::test_helpers::make_new_block,
    test_helpers::{test_p2p_config, TEST_PROTOCOL_VERSION},
    tests::helpers::{PeerManagerNotification, TestNode},
};

type Transport = <TestTransportChannel as TestTransportMaker>::Transport;

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
enum TestParamForFirstSyncMessageReceivedMustBeSent {
    BlockSyncMsg,
    TxSyncMsg,
    PeerMgrMsg,
}

// Check that once the peer sends us any block or transaction sync message, `PeerManagerMessageExt::FirstSyncMessageReceived`
// is sent to the peer manager.
// 1) Send a random message from the peer.
// 2) If the sent message was a sync one, expect that `PeerManagerNotification::MessageReceived` is emitted with
// the message equal to `PeerManagerMessageExtTag::FirstSyncMessageReceived`. If the sent message was not a sync one,
// expect that no such notification is emitted.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_sync_message_received_must_be_sent(
    #[case] seed: Seed,
    #[values(
        TestParamForFirstSyncMessageReceivedMustBeSent::BlockSyncMsg,
        TestParamForFirstSyncMessageReceivedMustBeSent::TxSyncMsg,
        TestParamForFirstSyncMessageReceivedMustBeSent::PeerMgrMsg
    )]
    param: TestParamForFirstSyncMessageReceivedMustBeSent,
) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let p2p_config = Arc::new(test_p2p_config());

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
            make_seedable_rng(rng.gen()),
        )
        .await;

        let transport = TestTransportChannel::make_transport();
        let mut listener =
            transport.bind(vec![TestTransportChannel::make_address()]).await.unwrap();

        let connect_result_receiver =
            test_node.start_connecting(listener.local_addresses().unwrap()[0].into());

        let (stream, _) = listener.accept().await.unwrap();

        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

        msg_writer
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

        connect_result_receiver.await.unwrap().unwrap();

        let (msg_to_send, is_sync_msg) = match param {
            TestParamForFirstSyncMessageReceivedMustBeSent::BlockSyncMsg => {
                let msg = match BlockSyncMessageTag::iter().choose(&mut rng).unwrap() {
                    BlockSyncMessageTag::HeaderListRequest => {
                        Message::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![
                            Id::random_using(&mut rng),
                        ])))
                    }
                    BlockSyncMessageTag::BlockListRequest => Message::BlockListRequest(
                        BlockListRequest::new(vec![Id::random_using(&mut rng)]),
                    ),
                    BlockSyncMessageTag::HeaderList => {
                        Message::HeaderList(HeaderList::new(Vec::new()))
                    }
                    BlockSyncMessageTag::BlockResponse => {
                        Message::BlockResponse(BlockResponse::new(make_new_block(
                            &chain_config,
                            None,
                            &time_getter.get_time_getter(),
                            &mut rng,
                        )))
                    }
                    BlockSyncMessageTag::TestSentinel => {
                        Message::TestBlockSyncMsgSentinel(Id::random_using(&mut rng))
                    }
                };

                (msg, true)
            }
            TestParamForFirstSyncMessageReceivedMustBeSent::TxSyncMsg => {
                let msg = match TransactionSyncMessageTag::iter().choose(&mut rng).unwrap() {
                    TransactionSyncMessageTag::NewTransaction => {
                        Message::NewTransaction(Id::random_using(&mut rng))
                    }
                    TransactionSyncMessageTag::TransactionRequest => {
                        Message::TransactionRequest(Id::random_using(&mut rng))
                    }
                    TransactionSyncMessageTag::TransactionResponse => Message::TransactionResponse(
                        TransactionResponse::NotFound(Id::random_using(&mut rng)),
                    ),
                };

                (msg, true)
            }
            TestParamForFirstSyncMessageReceivedMustBeSent::PeerMgrMsg => {
                let msg = match PeerManagerMessageTag::iter().choose(&mut rng).unwrap() {
                    PeerManagerMessageTag::AddrListRequest => {
                        Message::AddrListRequest(AddrListRequest {})
                    }
                    PeerManagerMessageTag::AnnounceAddrRequest => {
                        Message::AnnounceAddrRequest(AnnounceAddrRequest {
                            address: random_peer_addr(&mut rng),
                        })
                    }
                    PeerManagerMessageTag::PingRequest => {
                        Message::PingRequest(PingRequest { nonce: rng.gen() })
                    }
                    PeerManagerMessageTag::AddrListResponse => {
                        Message::AddrListResponse(AddrListResponse {
                            addresses: vec![random_peer_addr(&mut rng)],
                        })
                    }
                    PeerManagerMessageTag::PingResponse => {
                        Message::PingResponse(PingResponse { nonce: rng.gen() })
                    }
                    PeerManagerMessageTag::WillDisconnect => {
                        Message::WillDisconnect(WillDisconnectMessage {
                            reason: gen_random_alnum_string(&mut rng, 10, 20),
                        })
                    }
                };

                (msg, false)
            }
        };

        msg_writer.send(msg_to_send).await.unwrap();

        if is_sync_msg {
            tokio::time::timeout(
                MEDIUM_TIMEOUT,
                recv_first_sync_message_received(&mut test_node),
            )
            .await
            .unwrap();
        } else {
            tokio::time::timeout(
                SHORT_TIMEOUT,
                recv_first_sync_message_received(&mut test_node),
            )
            .await
            .unwrap_err();
        }

        test_node.join().await;
    })
    .await;
}

// Check that `PeerManagerMessageExt::FirstSyncMessageReceived` will be sent only once even if
// many sync messages are received from the peer.
// 1) Send a few `HeaderListRequest` and/or `NewTransaction` messages (i.e. some legit messages that a peer can send
// in any number).
// 2) Expect that only one `PeerManagerNotification::MessageReceived` with `PeerManagerMessageExtTag::FirstSyncMessageReceived`
// is produced.
#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_sync_message_received_must_be_sent_only_once(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    run_with_timeout(async {
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let p2p_config = Arc::new(test_p2p_config());

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
            make_seedable_rng(rng.gen()),
        )
        .await;

        let transport = TestTransportChannel::make_transport();
        let mut listener =
            transport.bind(vec![TestTransportChannel::make_address()]).await.unwrap();

        let connect_result_receiver =
            test_node.start_connecting(listener.local_addresses().unwrap()[0].into());

        let (stream, _) = listener.accept().await.unwrap();

        let (mut msg_reader, mut msg_writer) =
            new_message_stream(stream, Some(*p2p_config.protocol_config.max_message_size));

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::Hello { .. }));

        msg_writer
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

        connect_result_receiver.await.unwrap().unwrap();

        for _ in 5..10 {
            let msg = if rng.gen_bool(0.5) {
                Message::HeaderListRequest(HeaderListRequest::new(Locator::new(vec![
                    Id::random_using(&mut rng),
                ])))
            } else {
                Message::NewTransaction(Id::random_using(&mut rng))
            };

            msg_writer.send(msg).await.unwrap();
        }

        tokio::time::timeout(
            MEDIUM_TIMEOUT,
            recv_first_sync_message_received(&mut test_node),
        )
        .await
        .unwrap();

        tokio::time::timeout(
            SHORT_TIMEOUT,
            recv_first_sync_message_received(&mut test_node),
        )
        .await
        .unwrap_err();

        test_node.join().await;
    })
    .await;
}

fn random_peer_addr(rng: &mut impl Rng) -> PeerAddress {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen()),
        rng.gen(),
    ))
    .into()
}

async fn recv_first_sync_message_received<T: TransportSocket>(test_node: &mut TestNode<T>) {
    while let Some(notif) = test_node.peer_mgr_notification_receiver().recv().await {
        if let PeerManagerNotification::MessageReceived {
            peer_id: _,
            message_tag,
        } = notif
        {
            match message_tag {
                PeerManagerMessageExtTag::PeerManagerMessage(_) => {}
                PeerManagerMessageExtTag::FirstSyncMessageReceived => {
                    break;
                }
            }
        }
    }
}
