// Copyright (c) 2022-2026 RBB S.r.l
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
    time::Duration,
};

use futures::FutureExt;

use chainstate::Locator;
use common::chain::config::MagicBytes;
use networking::{
    test_helpers::{
        get_two_connected_sockets, TestTransportChannel, TestTransportMaker, TestTransportNoise,
        TestTransportTcp,
    },
    transport::{MpscChannelTransport, NoiseTcpTransport, TcpTransportSocket},
};
use test_utils::{
    assert_matches,
    mock_time_getter::{mocked_time_getter_milliseconds, mocked_time_getter_seconds},
};
use utils::{atomics::SeqCstAtomicU64, tokio_spawn_in_current_tracing_span};

use crate::{
    error::ConnectionValidationError,
    message::HeaderListRequest,
    net::{
        default_backend::types::{peer_event, HandshakeMessage, P2pTimestamp},
        types::services::Service,
    },
    test_helpers::{test_p2p_config, TEST_PROTOCOL_VERSION},
};

use super::*;

const TEST_CHAN_BUF_SIZE: usize = 100;

async fn expect_peer_info_received_event(
    peer_event_receiver: &mut mpsc::Receiver<PeerEvent>,
    expected_info: &peer_event::PeerInfo,
) {
    let peer_event = peer_event_receiver.recv().await.unwrap();
    match peer_event {
        PeerEvent::PeerInfoReceived(info) => {
            assert_eq!(&info, expected_info);
        }
        _ => {
            panic!("Unexpected peer event: {peer_event:?}")
        }
    }
}

// Same as expect_peer_info_received, but we don't care about the actual info.
async fn expect_some_peer_info_received_event(peer_event_receiver: &mut mpsc::Receiver<PeerEvent>) {
    let peer_event = peer_event_receiver.recv().await.unwrap();
    assert_matches!(peer_event, PeerEvent::PeerInfoReceived(_));
}

async fn expect_sync_event(peer_event_receiver: &mut mpsc::Receiver<PeerEvent>) {
    let peer_event = peer_event_receiver.recv().await.unwrap();
    match peer_event {
        PeerEvent::Sync {
            event_received_confirmation_sender,
        } => {
            let _ = event_received_confirmation_sender.send(());
        }
        _ => {
            panic!("Unexpected peer event: {peer_event:?}")
        }
    }
}

async fn handshake_inbound<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let (peer_event_sender, mut peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
    let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
    let time_getter = mocked_time_getter_seconds(cur_time);

    let (mut socket1_reader, mut socket1_writer) =
        new_message_stream(socket1, Some(*p2p_config.protocol_config.max_message_size));
    let handshake_handler = HandshakeHandler::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into(),
        ConnectionInfo::Inbound,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TEST_PROTOCOL_VERSION.into(),
        time_getter,
    );

    let handle = tokio_spawn_in_current_tracing_span(
        async move {
            handshake_handler
                .run_handshake(&peer_event_sender, &mut socket1_reader, &mut socket1_writer)
                .await
        },
        "",
    );

    let (mut socket2_reader, mut socket2_writer) =
        new_message_stream(socket2, Some(*p2p_config.protocol_config.max_message_size));
    assert!(socket2_reader.recv().now_or_never().is_none());
    assert!(socket2_writer
        .send(Message::Handshake(HandshakeMessage::Hello {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            software_version: *chain_config.software_version(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            services: [Service::Blocks, Service::Transactions].as_slice().into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_int_seconds(123456),
            handshake_nonce: 123,
        }))
        .await
        .is_ok());

    expect_peer_info_received_event(
        &mut peer_event_receiver,
        &peer_event::PeerInfo {
            protocol_version: TEST_PROTOCOL_VERSION,
            network: *chain_config.magic_bytes(),
            common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            node_address_as_seen_by_peer: None,
            handshake_nonce: 123,
        },
    )
    .await;
    expect_sync_event(&mut peer_event_receiver).await;

    let common_protocol_version = handle.await.unwrap().unwrap();
    assert_eq!(common_protocol_version.0, TEST_PROTOCOL_VERSION);
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_inbound_tcp() {
    handshake_inbound::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_inbound_channels() {
    handshake_inbound::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_inbound_noise() {
    handshake_inbound::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn handshake_outbound<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let (peer_event_sender, mut peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
    let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
    let time_getter = mocked_time_getter_seconds(cur_time);

    let (mut socket1_reader, mut socket1_writer) =
        new_message_stream(socket1, Some(*p2p_config.protocol_config.max_message_size));
    let handshake_handler = HandshakeHandler::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into(),
        ConnectionInfo::Outbound {
            handshake_nonce: 1,
            local_services_override: None,
        },
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TEST_PROTOCOL_VERSION.into(),
        time_getter,
    );

    let handle = tokio_spawn_in_current_tracing_span(
        async move {
            handshake_handler
                .run_handshake(&peer_event_sender, &mut socket1_reader, &mut socket1_writer)
                .await
        },
        "",
    );

    let (mut socket2_reader, mut socket2_writer) =
        new_message_stream(socket2, Some(*p2p_config.protocol_config.max_message_size));
    socket2_reader.recv().await.unwrap();
    assert!(socket2_writer
        .send(Message::Handshake(HandshakeMessage::HelloAck {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            software_version: *chain_config.software_version(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            services: [Service::Blocks, Service::Transactions].as_slice().into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_int_seconds(123456),
        }))
        .await
        .is_ok());

    expect_peer_info_received_event(
        &mut peer_event_receiver,
        &peer_event::PeerInfo {
            protocol_version: TEST_PROTOCOL_VERSION,
            network: *chain_config.magic_bytes(),
            common_services: [Service::Blocks, Service::Transactions].as_slice().into(),
            user_agent: p2p_config.user_agent.clone(),
            software_version: *chain_config.software_version(),
            node_address_as_seen_by_peer: None,
            handshake_nonce: 1,
        },
    )
    .await;

    let common_protocol_version = handle.await.unwrap().unwrap();
    assert_eq!(common_protocol_version.0, TEST_PROTOCOL_VERSION);
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_outbound_tcp() {
    handshake_outbound::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_outbound_channels() {
    handshake_outbound::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_outbound_noise() {
    handshake_outbound::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn handshake_different_network<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let (peer_event_sender, mut peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
    let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
    let time_getter = mocked_time_getter_seconds(Arc::clone(&cur_time));

    let (mut socket1_reader, mut socket1_writer) =
        new_message_stream(socket1, Some(*p2p_config.protocol_config.max_message_size));
    let handshake_handler = HandshakeHandler::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into(),
        ConnectionInfo::Inbound,
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TEST_PROTOCOL_VERSION.into(),
        time_getter,
    );

    let handle = tokio_spawn_in_current_tracing_span(
        async move {
            handshake_handler
                .run_handshake(&peer_event_sender, &mut socket1_reader, &mut socket1_writer)
                .await
        },
        "",
    );
    let (mut socket2_reader, mut socket2_writer) =
        new_message_stream(socket2, Some(*p2p_config.protocol_config.max_message_size));
    assert!(socket2_reader.recv().now_or_never().is_none());
    assert!(socket2_writer
        .send(Message::Handshake(HandshakeMessage::Hello {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            software_version: *chain_config.software_version(),
            network: MagicBytes::new([1, 2, 3, 4]),
            user_agent: p2p_config.user_agent.clone(),
            services: [Service::Blocks, Service::Transactions].as_slice().into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_int_seconds(cur_time.load()),
            handshake_nonce: 123,
        }))
        .await
        .is_ok());

    expect_some_peer_info_received_event(&mut peer_event_receiver).await;
    expect_sync_event(&mut peer_event_receiver).await;

    let common_protocol_version = handle.await.unwrap().unwrap();
    assert_eq!(common_protocol_version.0, TEST_PROTOCOL_VERSION);
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_different_network_tcp() {
    handshake_different_network::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_different_network_channels() {
    handshake_different_network::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn handshake_different_network_noise() {
    handshake_different_network::<TestTransportNoise, NoiseTcpTransport>().await;
}

async fn invalid_handshake_message<A, T>()
where
    A: TestTransportMaker<Transport = T>,
    T: TransportSocket,
{
    let (socket1, socket2) = get_two_connected_sockets::<A, T>().await;
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let (peer_event_sender, _peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);
    let cur_time = Arc::new(SeqCstAtomicU64::new(123456));
    let time_getter = mocked_time_getter_seconds(cur_time);

    let (mut socket1_reader, mut socket1_writer) =
        new_message_stream(socket1, Some(*p2p_config.protocol_config.max_message_size));
    let handshake_handler = HandshakeHandler::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into(),
        ConnectionInfo::Inbound,
        chain_config,
        Arc::clone(&p2p_config),
        TEST_PROTOCOL_VERSION.into(),
        time_getter,
    );

    let handle = tokio_spawn_in_current_tracing_span(
        async move {
            handshake_handler
                .run_handshake(&peer_event_sender, &mut socket1_reader, &mut socket1_writer)
                .await
        },
        "",
    );

    let (mut socket2_reader, mut socket2_writer) =
        new_message_stream(socket2, Some(*p2p_config.protocol_config.max_message_size));
    assert!(socket2_reader.recv().now_or_never().is_none());
    socket2_writer
        .send(Message::HeaderListRequest(HeaderListRequest::new(
            Locator::new(vec![]),
        )))
        .await
        .unwrap();

    assert!(matches!(
        handle.await.unwrap(),
        Err(P2pError::ProtocolError(ProtocolError::HandshakeExpected))
    ),);
}

#[tracing::instrument]
#[tokio::test]
async fn invalid_handshake_message_tcp() {
    invalid_handshake_message::<TestTransportTcp, TcpTransportSocket>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn invalid_handshake_message_channels() {
    invalid_handshake_message::<TestTransportChannel, MpscChannelTransport>().await;
}

#[tracing::instrument]
#[tokio::test]
async fn invalid_handshake_message_noise() {
    invalid_handshake_message::<TestTransportNoise, NoiseTcpTransport>().await;
}

#[rstest::rstest]
#[case::all_in_sync(
        123456,
        123456,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
#[case::peer_ahead_within_tolerance(
        100000,
        100009,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
#[case::peer_ahead_within_tolerance_and_delay(
        100000,
        100011,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
#[case::peer_ahead_too_much(
        100000,
        100014,
        Duration::from_secs(2),
        |res| assert!(matches!(res, Err(P2pError::ConnectionValidationFailed(ConnectionValidationError::TimeDiff {
            remote_time: _,
            accepted_peer_time: _
        })))),
    )]
#[case::peer_behind_within_tolerance(
        100009,
        100000,
        Duration::from_secs(2),
        |res| assert_eq!(res, Ok(())),
    )]
#[case::peer_behind_too_much(
        100014,
        100000,
        Duration::from_secs(2),
        |res| assert!(matches!(res, Err(P2pError::ConnectionValidationFailed(ConnectionValidationError::TimeDiff {
            remote_time: _,
            accepted_peer_time: _
        })))),
    )]
#[case::peer_in_sync_but_times_out(
        100000,
        100000,
        Duration::from_secs(11),
        |res| assert_eq!(res, Err(P2pError::ProtocolError(ProtocolError::Unresponsive))),
    )]
#[tokio::test]
async fn handshake_timestamp_verification(
    #[case] local_init_time: u64,
    #[case] peer_init_time: u64,
    #[case] response_delay: Duration,
    #[case] result_check: impl FnOnce(crate::Result<()>),
) {
    tokio::time::pause();
    let local_time = Arc::new(SeqCstAtomicU64::new(1000 * local_init_time));
    let local_time_getter = mocked_time_getter_milliseconds(Arc::clone(&local_time));
    let peer_time = Arc::new(SeqCstAtomicU64::new(1000 * peer_init_time));
    let peer_time_getter = mocked_time_getter_milliseconds(Arc::clone(&peer_time));

    let (socket1, socket2) =
        get_two_connected_sockets::<TestTransportChannel, MpscChannelTransport>().await;
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = Arc::new(test_p2p_config());
    let (peer_event_sender, _peer_event_receiver) = mpsc::channel(TEST_CHAN_BUF_SIZE);

    let (mut socket1_reader, mut socket1_writer) =
        new_message_stream(socket1, Some(*p2p_config.protocol_config.max_message_size));
    let handshake_handler = HandshakeHandler::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into(),
        ConnectionInfo::Outbound {
            handshake_nonce: 1,
            local_services_override: None,
        },
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
        TEST_PROTOCOL_VERSION.into(),
        peer_time_getter,
    );

    let handle = tokio_spawn_in_current_tracing_span(
        async move {
            handshake_handler
                .run_handshake(&peer_event_sender, &mut socket1_reader, &mut socket1_writer)
                .await
        },
        "",
    );

    // Advance both peer clocks and tokio time by given delay in 200ms increments to simulate
    // the flow of time. Doing this in one step makes the test result sensitive to the runtime
    // scheduler behavior.
    let increment = 200;
    for _ in 0..(response_delay.as_millis() as u64 / increment) {
        local_time.fetch_add(increment);
        peer_time.fetch_add(increment);
        tokio::time::advance(Duration::from_millis(increment)).await;
    }

    let (mut socket2_reader, mut socket2_writer) =
        new_message_stream(socket2, Some(*p2p_config.protocol_config.max_message_size));
    socket2_reader.recv().await.unwrap();
    let _ = socket2_writer
        .send(Message::Handshake(HandshakeMessage::HelloAck {
            protocol_version: TEST_PROTOCOL_VERSION.into(),
            software_version: *chain_config.software_version(),
            network: *chain_config.magic_bytes(),
            user_agent: p2p_config.user_agent.clone(),
            services: [Service::Blocks, Service::Transactions].as_slice().into(),
            receiver_address: None,
            current_time: P2pTimestamp::from_time(local_time_getter.get_time()),
        }))
        .await;

    let result = handle.await.unwrap().map(|_| ());
    result_check(result);
}
