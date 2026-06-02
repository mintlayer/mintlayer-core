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

use std::sync::Arc;

use rstest::rstest;

use chainstate::ChainstateConfig;
use common::primitives::user_agent::mintlayer_core_user_agent;
use networking::{
    test_helpers::{
        TestTransportChannel, TestTransportMaker, TestTransportNoise, TestTransportTcp,
    },
    transport::{TransportSocket, new_message_stream},
};
use p2p_test_utils::{SHORT_TIMEOUT, run_with_timeout};
use randomness::RngExt as _;
use test_utils::{
    BasicTestTimeGetter, assert_matches,
    random::{Seed, make_seedable_rng},
};

use crate::{
    config::{BackendConfig, P2pConfig},
    net::default_backend::types::{HandshakeMessage, Message, P2pTimestamp},
    test_helpers::TEST_PROTOCOL_VERSION,
    tests::helpers::TestNode,
};

// Check that `BackendConfig::max_pending_inbound_connections` actually limits the number of pending
// incoming connections.
async fn pending_inbound_connections_limit<TTM>(seed: Seed)
where
    TTM: TestTransportMaker,
    TTM::Transport: TransportSocket,
{
    let mut rng = make_seedable_rng(seed);

    let max_pending_inbound_connections = 5;
    let good_peers_count = rng.random_range(1..=3);

    let time_getter = BasicTestTimeGetter::new();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());

    let p2p_config = Arc::new(P2pConfig {
        backend_config: BackendConfig {
            max_pending_inbound_connections: max_pending_inbound_connections.into(),

            outbound_connection_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            disconnection_timeout: Default::default(),
            socket_write_timeout: Default::default(),
        },

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        whitelisted_addresses: Default::default(),
        ban_config: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        user_agent: mintlayer_core_user_agent(),
        sync_stalling_timeout: Default::default(),
        peer_manager_config: Default::default(),
        protocol_config: Default::default(),
        custom_disconnection_reason_for_banning: Default::default(),
    });

    let mut test_node = TestNode::<TTM::Transport>::start(
        true,
        time_getter.clone(),
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        Arc::clone(&p2p_config),
        TTM::make_transport(),
        TTM::make_address().into(),
        TEST_PROTOCOL_VERSION.into(),
        None,
        make_seedable_rng(rng.random()),
    )
    .await;

    let transport = TTM::make_transport();

    let peer_time = P2pTimestamp::from_time(time_getter.get_time_getter().get_time());

    let mut pending_peers_readers_writers = Vec::new();

    // A `max_pending_inbound_connections` number of inbound peers connect, but don't initiate
    // the handshake. Each peer is registered as pending.
    for _ in 0..max_pending_inbound_connections {
        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let (msg_reader, msg_writer) = new_message_stream::<_, Message>(
            stream,
            Some(*p2p_config.protocol_config.max_message_size),
        );
        let peer_id = test_node.wait_for_next_pending_peer_creation_in_backend().await;

        pending_peers_readers_writers.push((peer_id, msg_reader, msg_writer));
    }

    test_node.assert_no_pending_peer_removal_in_backend().await;

    // A few more inbound peers attempt to connect. These are not registered as pending and are
    // dropped immediately because the limit for pending peers has been reached.
    for _ in 0..3 {
        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let (mut msg_reader, _) = new_message_stream::<_, Message>(
            stream,
            Some(*p2p_config.protocol_config.max_message_size),
        );

        test_node.assert_no_pending_peer_creation_in_backend().await;
        tokio::time::timeout(SHORT_TIMEOUT, msg_reader.recv())
            .await
            .unwrap()
            .unwrap_err();
    }

    let mut good_peers_readers_writers = Vec::new();

    // A few of the pending peers decide to initiate the handshake, after which they're no longer pending.
    for _ in 0..good_peers_count {
        let peer_idx = rng.random_range(0..pending_peers_readers_writers.len());

        let (peer_id, mut msg_reader, mut msg_writer) =
            pending_peers_readers_writers.remove(peer_idx);

        msg_writer
            .send(Message::Handshake(HandshakeMessage::Hello {
                protocol_version: TEST_PROTOCOL_VERSION.into(),
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

        let msg = msg_reader.recv().await.unwrap();
        assert_matches!(msg, Message::Handshake(HandshakeMessage::HelloAck { .. }));

        test_node.wait_for_next_pending_peer_removal_in_backend(peer_id).await;

        // Don't drop the readers/writers to make sure the peer continues to exist.
        good_peers_readers_writers.push((peer_id, msg_reader, msg_writer));
    }

    // Since `good_peers_count` peers are no longer pending, the node will accept this number
    // of new peers and they will be registered as pending.
    for _ in 0..good_peers_count {
        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let (msg_reader, msg_writer) = new_message_stream::<_, Message>(
            stream,
            Some(*p2p_config.protocol_config.max_message_size),
        );
        let peer_id = test_node.wait_for_next_pending_peer_creation_in_backend().await;

        pending_peers_readers_writers.push((peer_id, msg_reader, msg_writer));
    }

    // A few more inbound peers attempt to connect. These are not registered as pending and are
    // dropped immediately because the limit for pending peers has been reached again.
    for _ in 0..3 {
        let stream = transport.connect(test_node.local_address().socket_addr()).await.unwrap();
        let (mut msg_reader, _) = new_message_stream::<_, Message>(
            stream,
            Some(*p2p_config.protocol_config.max_message_size),
        );

        test_node.assert_no_pending_peer_creation_in_backend().await;
        tokio::time::timeout(SHORT_TIMEOUT, msg_reader.recv())
            .await
            .unwrap()
            .unwrap_err();
    }

    test_node.join().await;
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_inbound_connections_limit_tcp(#[case] seed: Seed) {
    run_with_timeout(pending_inbound_connections_limit::<TestTransportTcp>(seed)).await;
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_inbound_connections_limit_channels(#[case] seed: Seed) {
    run_with_timeout(pending_inbound_connections_limit::<TestTransportChannel>(
        seed,
    ))
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest]
#[case(Seed::from_entropy())]
#[trace]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_inbound_connections_limit_noise(#[case] seed: Seed) {
    run_with_timeout(pending_inbound_connections_limit::<TestTransportNoise>(
        seed,
    ))
    .await;
}
