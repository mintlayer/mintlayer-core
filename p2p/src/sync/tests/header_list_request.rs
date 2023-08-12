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

use chainstate::{ban_score::BanScore, Locator};
use chainstate_test_framework::TestFramework;
use common::{chain::config::create_unit_test_config, primitives::Idable};
use test_utils::random::Seed;

use crate::{
    error::ProtocolError,
    message::{HeaderListRequest, SyncMessage},
    sync::tests::helpers::TestNode,
    types::peer_id::PeerId,
    P2pError,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn max_locator_size_exceeded(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let headers = iter::repeat(block.get_id().into()).take(102).collect();
    node.send_message(
        peer,
        SyncMessage::HeaderListRequest(HeaderListRequest::new(Locator::new(headers))),
    )
    .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::LocatorSizeExceeded(0, 0)).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_request(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    let block_index = tf.make_block_builder().build_and_process().unwrap().unwrap();
    let locator = tf
        .chainstate
        .get_locator_from_height(block_index.block_height().prev_height().unwrap())
        .unwrap();

    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    node.send_message(
        peer,
        SyncMessage::HeaderListRequest(HeaderListRequest::new(locator)),
    )
    .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    let headers = match message {
        SyncMessage::HeaderList(l) => l.into_headers(),
        m => panic!("Unexpected message: {m:?}"),
    };
    assert_eq!(headers.len(), 1);
    assert_eq!(&headers[0], block_index.block_header());
    node.assert_no_error().await;

    node.join_subsystem_manager().await;
}
