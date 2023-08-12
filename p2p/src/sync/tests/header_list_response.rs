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
    config::NodeType,
    error::ProtocolError,
    message::{BlockListRequest, HeaderList, SyncMessage},
    sync::tests::helpers::SyncManagerHandle,
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
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = iter::repeat(block.header().clone())
        .take(*p2p_config.msg_header_count_limit + 1)
        .collect();
    handle
        .send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers)))
        .await;

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::HeadersLimitExceeded(0, 0)).ban_score()
    );
    handle.assert_no_event().await;

    handle.join_subsystem_manager().await;
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

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle
        .send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers)))
        .await;

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
    );
    handle.assert_no_event().await;

    handle.join_subsystem_manager().await;
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

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle
        .send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers)))
        .await;

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
    );
    handle.assert_no_event().await;

    handle.join_subsystem_manager().await;
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

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    handle
        .send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers)))
        .await;

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(
            blocks.into_iter().map(|b| b.get_id()).collect()
        ))
    );

    handle.assert_no_error().await;

    handle.join_subsystem_manager().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect() {
    let p2p_config = Arc::new(P2pConfig {
        node_type: NodeType::Full.into(),
        user_agent: "test".try_into().unwrap(),
        sync_stalling_timeout: Duration::from_millis(100).into(),
        ..P2pConfig::default()
    });
    let mut handle = SyncManagerHandle::builder()
        .with_p2p_config(Arc::clone(&p2p_config))
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    handle.assert_disconnect_peer_event(peer).await;

    handle.join_subsystem_manager().await;
}
