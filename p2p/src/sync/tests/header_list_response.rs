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

use std::{iter, sync::Arc};

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{chain::config::create_unit_test_config, primitives::Idable};
use p2p_test_utils::{create_n_blocks, start_subsystems_with_chainstate};
use test_utils::random::Seed;

use crate::{
    error::ProtocolError,
    message::{BlockListRequest, HeaderListResponse, SyncMessage},
    sync::tests::helpers::SyncManagerHandle,
    testing_utils::test_p2p_config,
    types::peer_id::PeerId,
    P2pError,
};

#[tokio::test]
#[should_panic = "Received a message from unknown peer"]
async fn nonexistent_peer() {
    let mut handle = SyncManagerHandle::start().await;

    let peer = PeerId::new();

    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(Vec::new())),
    );

    handle.resume_panic().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn header_count_limit_exceeded(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(test_p2p_config());
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = iter::repeat(block.header().clone())
        .take(*p2p_config.msg_header_count_limit + 1)
        .collect();
    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::HeadersLimitExceeded(0, 0)).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
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
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
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
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn valid_headers(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let blocks = create_n_blocks(&mut tf, 3);
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    handle.send_message(
        peer,
        SyncMessage::HeaderListResponse(HeaderListResponse::new(headers)),
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(
            blocks.into_iter().map(|b| b.get_id()).collect()
        ))
    );

    handle.assert_no_error().await;
}
