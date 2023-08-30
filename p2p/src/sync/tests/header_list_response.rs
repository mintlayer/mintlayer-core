// Copyright (c) 2022 RBB S.r.l
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

use std::{iter, sync::Arc, time::Duration};

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{chain::config::create_unit_test_config, primitives::Idable};
use p2p_test_utils::create_n_blocks;
use test_utils::random::Seed;

use crate::{
    error::ProtocolError,
    message::{BlockListRequest, HeaderList, SyncMessage},
    sync::tests::helpers::TestNode,
    testing_utils::test_p2p_config,
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_count_limit_exceeded(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();

    let p2p_config = Arc::new(test_p2p_config());
    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let headers = iter::repeat(block.header().clone())
        .take(*p2p_config.msg_header_count_limit + 1)
        .collect();
    node.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers))).await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::HeadersLimitExceeded(0, 0)).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unordered_headers(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Skip the header in the middle.
    let headers = create_n_blocks(&mut tf, 3)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, b)| b.header().clone())
        .collect();

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers))).await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnected_headers(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let headers = create_n_blocks(&mut tf, 3)
        .into_iter()
        .skip(1)
        .map(|b| b.header().clone())
        .collect();

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers))).await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_headers(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let blocks = create_n_blocks(&mut tf, 3);

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    node.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers))).await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(
            blocks.into_iter().map(|b| b.get_id()).collect()
        ))
    );

    node.assert_no_error().await;

    node.join_subsystem_manager().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect() {
    let p2p_config = Arc::new(P2pConfig {
        sync_stalling_timeout: Duration::from_millis(100).into(),

        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        block_relay_peer_count: Default::default(),
    });
    let mut node = TestNode::builder().with_p2p_config(Arc::clone(&p2p_config)).build().await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    node.assert_disconnect_peer_event(peer).await;

    node.join_subsystem_manager().await;
}
