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

//! Tests for the per-peer fork download budget (see `sync::peer::fork_download_budget`).
//!
//! The budget limits the total number of headers a peer can make us process per refill
//! interval. These tests verify that:
//! * exceeding the budget defers the processing of header lists without any punishment of
//!   the peer (no ban/discouragement events),
//! * peers cannot bypass the budget with announcements that are anchored at our tip,
//! * deferred data is fetched once the budget is refilled (liveness is preserved),
//! * the budget is not enforced during the initial block download.

use std::{sync::Arc, time::Duration};

use chainstate::ChainstateHandle;
use common::{
    chain::{
        GenBlock,
        block::{Block, signed_block_header::SignedBlockHeader},
        config::create_unit_test_config,
    },
    primitives::{Id, Idable},
};
use test_utils::{
    BasicTestTimeGetter,
    random::{Seed, make_seedable_rng},
};

use crate::{
    config::P2pConfig,
    message::{BlockSyncMessage, HeaderList},
    protocol::{ForkDownloadLimit, ForkDownloadRefillInterval, ProtocolConfig},
    sync::tests::helpers::{
        TestNode, make_new_block, make_new_top_blocks_return_headers,
        test_node_group::{BlockSyncMessageWithNodeIdx, TestNodeGroup},
    },
    test_helpers::{for_each_protocol_version, test_p2p_config_with_protocol_config},
};

/// A short refill interval makes the tests faster, since the retry timer is driven by the
/// real tokio clock while the budget refill itself is driven by the mocked time getter.
const REFILL_INTERVAL: Duration = Duration::from_secs(60);

fn make_p2p_config(max_fork_downloads_per_peer: usize) -> P2pConfig {
    test_p2p_config_with_protocol_config(ProtocolConfig {
        max_fork_downloads_per_peer: ForkDownloadLimit::new(max_fork_downloads_per_peer),
        fork_download_refill_interval: ForkDownloadRefillInterval::new(REFILL_INTERVAL),
        ..Default::default()
    })
}

async fn best_block_id(chainstate: &ChainstateHandle) -> Id<GenBlock> {
    chainstate
        .call(|c| -> Result<_, chainstate::ChainstateError> { c.get_best_block_id() })
        .await
        .unwrap()
        .unwrap()
}

async fn has_block(chainstate: &ChainstateHandle, block_id: Id<Block>) -> bool {
    chainstate
        .call(move |c| -> Result<_, chainstate::ChainstateError> {
            c.get_block(&block_id).map(|b| b.is_some())
        })
        .await
        .unwrap()
        .unwrap()
}

fn known_list_msg(headers: &[SignedBlockHeader]) -> BlockSyncMessageWithNodeIdx {
    BlockSyncMessageWithNodeIdx {
        message: BlockSyncMessage::HeaderList(HeaderList::new(headers.to_vec())),
        sender_node_idx: 1,
        receiver_node_idx: 0,
    }
}

/// Extend the chain with `count` new blocks and return only the newly created blocks.
fn make_chain(
    chain_config: &Arc<common::chain::ChainConfig>,
    prev_blocks: &[Block],
    count: usize,
    time_getter: &BasicTestTimeGetter,
    rng: &mut impl randomness::Rng,
) -> Vec<Block> {
    let mut last_block = prev_blocks.last();
    let mut new_blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let block = make_new_block(
            chain_config,
            last_block,
            &time_getter.get_time_getter(),
            rng,
        );
        time_getter.advance_time(Duration::from_secs(60));
        new_blocks.push(block);
        last_block = new_blocks.last();
    }
    new_blocks
}

/// Exhausting the fork download budget must defer the processing of header lists without
/// any punishment of the peer, and the deferred data must be fetched once the budget is
/// refilled.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fork_download_budget_exhaustion_defers_without_punishment_and_recovers_after_refill(
    #[case] seed: Seed,
) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let blocks = make_chain(&chain_config, &[], 10, &time_getter, &mut rng);
        let mainchain_tip_id = blocks.last().unwrap().get_id();
        let mainchain_headers = blocks.iter().map(|b| b.header().clone()).collect::<Vec<_>>();

        // `node1` is the node under test; it has a budget of 100 headers.
        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks.clone())
            .with_p2p_config(Arc::new(make_p2p_config(100)))
            .build()
            .await;
        let chainstate1 = node1.chainstate().clone();

        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks)
            .build()
            .await;
        let chainstate2 = node2.chainstate().clone();

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        nodes.sync_all(&mainchain_tip_id.into(), &mut rng).await;

        // Exhaust the budget of `node1` by sending it an already-known header list 12 times.
        // Each list charges 10 tokens and the capacity is 100, so the budget is guaranteed
        // to be exhausted regardless of what was charged during the bootstrap.
        for _ in 0..12 {
            nodes.send_sync_message(known_list_msg(&mainchain_headers)).await;
        }
        nodes.exchange_block_sync_messages(&mut rng).await;

        // The budget is exhausted, so a newly produced header list must be deferred: no
        // block download must happen and the peer must not be punished for the
        // announcement (any ban/discouragement event fails the test).
        let fork_headers = make_new_top_blocks_return_headers(
            &chainstate2,
            time_getter.get_time_getter(),
            &mut rng,
            0,
            1,
        )
        .await;
        let fork_tip_id = fork_headers.last().unwrap().block_id();
        nodes.exchange_block_sync_messages(&mut rng).await;

        assert_eq!(
            best_block_id(&chainstate1).await,
            Id::<GenBlock>::from(mainchain_tip_id)
        );
        assert!(!has_block(&chainstate1, fork_tip_id).await);

        // Once the budget is refilled, the deferred headers must be fetched and the nodes
        // must converge.
        time_getter.advance_time(REFILL_INTERVAL * 2);
        nodes.sync_all(&fork_tip_id.into(), &mut rng).await;

        assert_eq!(
            best_block_id(&chainstate1).await,
            Id::<GenBlock>::from(fork_tip_id)
        );
        assert!(has_block(&chainstate1, fork_tip_id).await);

        nodes.join_subsystem_managers().await;
    })
    .await;
}

/// The budget must also apply to announcements that are anchored at our tip. Otherwise an
/// adversary could produce an unlimited number of valid blocks that share the same parent
/// (each of them being a tip-anchored single-header announcement) and make us download and
/// process all of them for free.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tip_anchored_fork_variants_are_budget_limited(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        let blocks = make_chain(&chain_config, &[], 10, &time_getter, &mut rng);
        let mainchain_tip_id = blocks.last().unwrap().get_id();
        let mainchain_headers = blocks.iter().map(|b| b.header().clone()).collect::<Vec<_>>();

        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks.clone())
            .with_p2p_config(Arc::new(make_p2p_config(100)))
            .build()
            .await;
        let chainstate1 = node1.chainstate().clone();

        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks)
            .build()
            .await;
        let chainstate2 = node2.chainstate().clone();

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        nodes.sync_all(&mainchain_tip_id.into(), &mut rng).await;

        // Exhaust the budget of `node1`.
        for _ in 0..12 {
            nodes.send_sync_message(known_list_msg(&mainchain_headers)).await;
        }
        nodes.exchange_block_sync_messages(&mut rng).await;

        // Produce 5 valid forks that all start at the same parent (one block below the
        // common tip of the nodes). Each fork consists of 2 blocks: a sibling of the
        // current tip and its child, which outcompetes the current tip. Every such fork is
        // announced to `node1` as a tip-anchored header list. All of them must be deferred.
        let mut variant_ids = Vec::new();
        for _ in 0..5 {
            let headers = make_new_top_blocks_return_headers(
                &chainstate2,
                time_getter.get_time_getter(),
                &mut rng,
                1,
                2,
            )
            .await;
            variant_ids.extend(headers.iter().map(|h| h.block_id()));
        }
        let best_variant_id = *variant_ids.last().unwrap();
        nodes.exchange_block_sync_messages(&mut rng).await;

        assert_eq!(
            best_block_id(&chainstate1).await,
            Id::<GenBlock>::from(mainchain_tip_id)
        );
        for variant_id in &variant_ids {
            assert!(!has_block(&chainstate1, *variant_id).await);
        }

        // After the budget is refilled, the nodes must converge on the peer's best chain
        // without any punishment of the peer.
        time_getter.advance_time(REFILL_INTERVAL * 2);
        nodes.sync_all(&best_variant_id.into(), &mut rng).await;

        assert_eq!(
            best_block_id(&chainstate1).await,
            Id::<GenBlock>::from(best_variant_id)
        );
        assert!(has_block(&chainstate1, best_variant_id).await);

        nodes.join_subsystem_managers().await;
    })
    .await;
}

/// The fork download budget must not be enforced during the initial block download,
/// otherwise a node that is catching up with the network could be stalled by the budget.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fork_download_budget_is_not_enforced_during_initial_block_download(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());

        // Both nodes have a 10-block chain whose tip is 2 days old, which is older than the
        // default max tip age (24 hours), so `node2` considers itself to be in the initial
        // block download.
        let old_time_getter = BasicTestTimeGetter::with_secs_since_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(2 * 24 * 60 * 60),
        );

        let blocks = make_chain(&chain_config, &[], 10, &old_time_getter, &mut rng);

        // `node1` also has a 30-block fork that `node2` must download in a single
        // 30-header list, which exceeds the budget of 10 headers.
        let fork_blocks = make_chain(&chain_config, &blocks, 30, &old_time_getter, &mut rng);
        let fork_tip_id = fork_blocks.last().unwrap().get_id();

        // `node1` follows the fork, so its tip is "fresh" relative to its own (old) clock
        // and it is not in the initial block download.
        let mut node1_blocks = blocks.clone();
        node1_blocks.extend(fork_blocks);

        let node1 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(old_time_getter.get_time_getter())
            .with_blocks(node1_blocks)
            .build()
            .await;

        let node2 = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_time_getter(BasicTestTimeGetter::new().get_time_getter())
            .with_blocks(blocks)
            .with_p2p_config(Arc::new(make_p2p_config(10)))
            .build()
            .await;
        let chainstate2 = node2.chainstate().clone();

        let mut nodes = TestNodeGroup::new(vec![node1, node2]);
        nodes.set_assert_no_peer_manager_events(true);

        // The 30-header list sent in response to the header list request of `node2` must
        // not be deferred despite exceeding the budget.
        nodes.sync_all(&fork_tip_id.into(), &mut rng).await;

        assert_eq!(
            best_block_id(&chainstate2).await,
            Id::<GenBlock>::from(fork_tip_id)
        );

        nodes.join_subsystem_managers().await;
    })
    .await;
}
