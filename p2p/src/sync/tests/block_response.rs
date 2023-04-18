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

use std::{sync::Arc, time::Duration};

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{chain::config::create_unit_test_config, primitives::Idable};
use crypto::random::Rng;
use p2p_test_utils::{create_n_blocks, start_subsystems_with_chainstate};
use test_utils::random::Seed;

use crate::{
    config::NodeType,
    error::ProtocolError,
    message::{BlockListRequest, BlockResponse, HeaderList, SyncMessage},
    net::types::SyncingEvent,
    sync::tests::helpers::SyncManagerHandle,
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[should_panic = "Received a message from unknown peer"]
async fn nonexistent_peer(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config)).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();

    handle.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)));

    handle.resume_panic().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrequested_block(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config)).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle.send_message(peer, SyncMessage::BlockResponse(BlockResponse::new(block)));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned())).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_response(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let num_blocks = rng.gen_range(2..10);
    let blocks = create_n_blocks(&mut tf, num_blocks);
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config)).await;

    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let headers = blocks.iter().map(|b| b.header().clone()).collect();
    handle.send_message(peer, SyncMessage::HeaderList(HeaderList::new(headers)));

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    let ids = blocks.iter().map(|b| b.get_id()).collect();
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(ids))
    );

    for (i, block) in blocks.into_iter().enumerate() {
        handle.send_message(
            peer,
            SyncMessage::BlockResponse(BlockResponse::new(block.clone())),
        );

        // A peer would request headers after the last block.
        if i < num_blocks - 1 {
            assert_eq!(
                handle.message().await.1,
                SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()]))
            );
        } else {
            // The order of receiving the block announcement and header list request is nondeterministic.
            let header_list = match (handle.event().await, handle.event().await) {
                (
                    SyncingEvent::Message {
                        peer: _,
                        message: SyncMessage::HeaderListRequest(_),
                    },
                    SyncingEvent::Message {
                        peer: _,
                        message: SyncMessage::HeaderList(l),
                    },
                ) => l.into_headers(),
                (
                    SyncingEvent::Message {
                        peer: _,
                        message: SyncMessage::HeaderList(l),
                    },
                    SyncingEvent::Message {
                        peer: _,
                        message: SyncMessage::HeaderListRequest(_),
                    },
                ) => l.into_headers(),
                (e1, e2) => panic!("Unexpected events: {e1:?} {e2:?}"),
            };
            assert_eq!(header_list, vec![block.header().clone()]);
        }
    }

    handle.assert_no_error().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn disconnect(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    let block = tf.make_block_builder().build();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(P2pConfig {
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
        node_type: NodeType::Full.into(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_unconnected_headers: Default::default(),
        sync_stalling_timeout: Duration::from_millis(100).into(),
    });
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    handle.send_message(
        peer,
        SyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()])),
    );

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::BlockListRequest(BlockListRequest::new(vec![block.get_id()]))
    );

    tokio::time::sleep(Duration::from_millis(300)).await;
    handle.assert_disconnect_peer_event(peer).await;
}
