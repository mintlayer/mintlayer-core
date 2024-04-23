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

use std::sync::Arc;

use chainstate::BlockSource;
use chainstate_test_framework::TestFramework;
use common::chain::{block::timestamp::BlockTimestamp, config::create_unit_test_config};
use test_utils::{random::Seed, BasicTestTimeGetter};

use crate::{
    message::{BlockSyncMessage, HeaderList},
    sync::tests::helpers::TestNode,
    test_helpers::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
};

// Check that the header list request is sent to a newly connected peer.
#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_peer() {
    for_each_protocol_version(|protocol_version| async move {
        let mut node = TestNode::start(protocol_version).await;

        let peer = PeerId::new();
        let _ = node.connect_peer(peer, protocol_version).await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that the attempt to connect the peer twice results in an error.
#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[should_panic = "Registered duplicated peer"]
async fn connect_peer_twice() {
    for_each_protocol_version(|protocol_version| async move {
        let mut node = TestNode::start(protocol_version).await;

        let peer_id = PeerId::new();
        let _ = node.connect_peer(peer_id, protocol_version).await;

        let _ = node.try_connect_peer(peer_id, protocol_version);

        node.resume_panic().await;
    })
    .await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[should_panic = "Unregistering unknown peer:"]
async fn disconnect_nonexistent_peer() {
    for_each_protocol_version(|protocol_version| async move {
        let mut node = TestNode::start(protocol_version).await;

        let peer = PeerId::new();
        node.disconnect_peer(peer);

        node.resume_panic().await;
    })
    .await;
}

#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_peer() {
    for_each_protocol_version(|protocol_version| async move {
        let mut node = TestNode::start(protocol_version).await;

        let peer_id = PeerId::new();
        let _ = node.connect_peer(peer_id, protocol_version).await;
        node.disconnect_peer(peer_id);
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn do_not_disconnect_peer_after_receiving_known_header_list(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        // Original bug description:
        //
        // There are two connected and fully synchronized nodes: Node1 and Node2.
        // Node1 generates a new block and sends a header notification to the Node2.
        // Node2 sends a header list message to all connected peers.
        // Node1 receives the headers list messages but does nothing because the specific block is already known.
        // Node1 unexpectedly disconnects Node2.
        //
        // Test case based on a simplified scenario:
        //
        // t = 0                     | Node has block; connects to a peer; peer sends a header list with the same block
        // t = sync_stalling_timeout | Node checks for peer timeout; should not disconnect

        let mut rng = test_utils::random::make_seedable_rng(seed);
        let time = BasicTestTimeGetter::new();
        let chain_config = Arc::new(create_unit_test_config());
        let p2p_config = Arc::new(test_p2p_config());

        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .with_time_getter(time.get_time_getter())
            .build();
        let block = tf
            .make_block_builder()
            .with_timestamp(BlockTimestamp::from_time(time.get_time_getter().get_time()))
            .build(&mut rng);
        tf.process_block(block.clone(), BlockSource::Local).unwrap();

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_time_getter(time.get_time_getter())
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        // Connect peer and assume we requested a header list.
        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        // Peer sends us a header list but we already know the containing block.
        let msg = BlockSyncMessage::HeaderList(HeaderList::new(vec![block.header().clone()]));
        peer.send_block_sync_message(msg).await;

        // Advance time across the timeout boundary. This would trigger a disconnect in a scenario
        // where we expect additional data from the peer. However, in this case we don't expect
        // additional data and therefore no disconnection should take place.
        time.advance_time(*p2p_config.sync_stalling_timeout);

        // Ensure the peer does not get disconnected.
        node.assert_no_disconnect_peer_event(peer.get_id()).await;

        node.join_subsystem_manager().await;
    })
    .await;
}
