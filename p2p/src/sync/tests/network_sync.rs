// Copyright (c) 2023 RBB S.r.l
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

use common::chain::block::timestamp::BlockTimestamp;
use crypto::random::Rng;
use p2p_test_utils::P2pBasicTestTimeGetter;
use test_utils::random::Seed;

use crate::{config::P2pConfig, sync::tests::helpers::TestNode};

use super::helpers::{
    get_random_bytes, new_block, new_top_blocks, nodes_in_sync, sync_nodes, try_sync_nodes_once,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic(#[case] seed: Seed) {
    logging::init_logging::<&std::path::Path>(None);

    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let p2p_config = Arc::new(P2pConfig {
        msg_header_count_limit: 10.into(),
        max_request_blocks_count: 5.into(),
        ..P2pConfig::default()
    });

    let mut blocks = Vec::new();
    for _ in 0..13 {
        let block = new_block(
            &chain_config,
            blocks.last(),
            BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
            get_random_bytes(&mut rng),
        );
        blocks.push(block.clone());
    }

    // Start `node1` with some fresh blocks (timestamp less than 24 hours old) to make `is_initial_block_download` false there
    let mut node1 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(blocks)
        .build()
        .await;

    // A new node is joining the network
    let mut node2 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .build()
        .await;

    node1.try_connect_peer(node2.peer_id);
    node2.try_connect_peer(node1.peer_id);

    sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

    new_top_blocks(
        node1.chainstate(),
        BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
        get_random_bytes(&mut rng),
        0,
        1,
    )
    .await;
    sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

    for _ in 0..15 {
        for _ in 0..rng.gen_range(1..2) {
            new_top_blocks(
                node1.chainstate(),
                BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
                get_random_bytes(&mut rng),
                0,
                1,
            )
            .await;
        }
        sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;
    }

    node1.join_subsystem_manager().await;
    node2.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_download_unexpected_disconnect(#[case] seed: Seed) {
    logging::init_logging::<&std::path::Path>(None);

    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let p2p_config = Arc::new(P2pConfig::default());

    let mut blocks = Vec::new();
    for _ in 0..1000 {
        let block = new_block(
            &chain_config,
            blocks.last(),
            BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
            get_random_bytes(&mut rng),
        );
        time_getter.advance_time(Duration::from_secs(600));
        blocks.push(block.clone());
    }

    // Start `node1` with up-to-date blockchain
    let mut node1 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(blocks)
        .build()
        .await;

    // A new node is joining the network
    let mut node2 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .build()
        .await;

    node1.try_connect_peer(node2.peer_id);
    node2.try_connect_peer(node1.peer_id);

    // Simulate a normal block sync process.
    // There should be no unexpected disconnects.
    let mut nodes = vec![&mut node1, &mut node2];
    while !nodes_in_sync(&nodes).await {
        try_sync_nodes_once(&mut rng, &mut nodes, 50).await;
        time_getter.advance_time(Duration::from_millis(10));
    }

    node1.join_subsystem_manager().await;
    node2.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reorg(#[case] seed: Seed) {
    logging::init_logging::<&std::path::Path>(None);

    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let p2p_config = Arc::new(P2pConfig::default());

    let mut blocks = Vec::new();
    for _ in 0..10 {
        let block = new_block(
            &chain_config,
            blocks.last(),
            BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
            get_random_bytes(&mut rng),
        );
        time_getter.advance_time(Duration::from_secs(60));
        blocks.push(block.clone());
    }

    // Start `node1` with up-to-date blockchain
    let mut node1 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(blocks.clone())
        .build()
        .await;

    // Start `node2` with up-to-date blockchain
    let mut node2 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(blocks)
        .build()
        .await;

    node1.try_connect_peer(node2.peer_id);
    node2.try_connect_peer(node1.peer_id);

    sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

    // First blockchain reorg
    new_top_blocks(
        node1.chainstate(),
        BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
        get_random_bytes(&mut rng),
        1,
        2,
    )
    .await;

    sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

    // Second blockchain reorg
    new_top_blocks(
        node1.chainstate(),
        BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
        get_random_bytes(&mut rng),
        1,
        2,
    )
    .await;

    sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

    node1.join_subsystem_manager().await;
    node2.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_production(#[case] seed: Seed) {
    logging::init_logging::<&std::path::Path>(None);

    let mut rng = test_utils::random::make_seedable_rng(seed);
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let time_getter = P2pBasicTestTimeGetter::new();

    let p2p_config = Arc::new(P2pConfig {
        msg_header_count_limit: 10.into(),
        max_request_blocks_count: 5.into(),
        ..P2pConfig::default()
    });

    let mut blocks = Vec::new();
    for _ in 0..10 {
        let block = new_block(
            &chain_config,
            blocks.last(),
            BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
            get_random_bytes(&mut rng),
        );
        blocks.push(block.clone());
    }

    // Start `node1` with some fresh blocks (timestamp less than 24 hours old) to make `is_initial_block_download` false there
    let mut node1 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .with_blocks(blocks)
        .build()
        .await;

    // A new node is joining the network
    let mut node2 = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_time_getter(time_getter.get_time_getter())
        .build()
        .await;

    let chainstate1 = node1.chainstate().clone();

    node1.try_connect_peer(node2.peer_id);
    node2.try_connect_peer(node1.peer_id);

    let notification = Arc::new(tokio::sync::Notify::new());
    let notification_copy = Arc::clone(&notification);

    let sync_task = tokio::spawn(async move {
        sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

        notification.notified().await;

        sync_nodes(&mut rng, vec![&mut node1, &mut node2].as_mut_slice()).await;

        node1.join_subsystem_manager().await;
        node2.join_subsystem_manager().await;
    });

    let mut rng = test_utils::random::make_seedable_rng(seed);

    for _ in 0..20 {
        new_top_blocks(
            &chainstate1,
            BlockTimestamp::from_duration_since_epoch(time_getter.get_time_getter().get_time()),
            get_random_bytes(&mut rng),
            0,
            1,
        )
        .await;
    }

    notification_copy.notify_one();

    let () = tokio::time::timeout(Duration::from_secs(60), sync_task).await.unwrap().unwrap();
}
