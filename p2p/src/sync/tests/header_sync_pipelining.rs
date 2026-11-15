// Copyright (c) 2025 RBB S.r.l
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

use chainstate_test_framework::TestFramework;
use common::chain::{
    Block, block::signed_block_header::SignedBlockHeader, block::timestamp::BlockTimestamp,
    config::create_unit_test_config,
};
use common::primitives::{Id, Idable, time::Time};
use p2p_test_utils::create_n_blocks;
use test_utils::BasicTestTimeGetter;
use test_utils::random::{Seed, make_seedable_rng};

use crate::{
    P2pConfig,
    message::{BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest},
    protocol::{ForkDownloadLimit, ForkDownloadRefillInterval, ProtocolConfig},
    sync::tests::helpers::{TestNode, TestPeer, make_new_block},
    test_helpers::{for_each_protocol_version, test_p2p_config_with_protocol_config},
    types::peer_id::PeerId,
};

const HEADER_LIST_LIMIT: usize = 4;
const BLOCK_REQUEST_LIMIT: usize = 4;

/// Tracks the blocks the node has requested from the peer and not yet received.
/// On every outgoing block request it verifies the serving contract that peers
/// enforce: no request exceeds the limit, the total outstanding stays within
/// the limit, and no block is requested again while still outstanding.
struct OutstandingRequests {
    limit: usize,
    outstanding: Vec<Id<Block>>,
}

impl OutstandingRequests {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            outstanding: Vec::new(),
        }
    }

    fn on_block_request(&mut self, ids: &[Id<Block>]) {
        assert!(!ids.is_empty(), "empty block request must never be sent");
        assert!(
            ids.len() <= self.limit,
            "request of {} blocks exceeds the limit of {}",
            ids.len(),
            self.limit
        );
        for id in ids {
            assert!(
                !self.outstanding.contains(id),
                "block {id} requested again while still outstanding"
            );
        }
        self.outstanding.extend_from_slice(ids);
        assert!(
            self.outstanding.len() <= self.limit,
            "total outstanding {} exceeds the limit of {}",
            self.outstanding.len(),
            self.limit
        );
    }

    fn on_block_received(&mut self, id: &Id<Block>) {
        let pos = self
            .outstanding
            .iter()
            .position(|outstanding| outstanding == id)
            .unwrap_or_else(|| panic!("received a block that was not outstanding: {id}"));
        self.outstanding.remove(pos);
    }
}

fn pipelining_test_config() -> Arc<P2pConfig> {
    pipelining_config_with_limits(HEADER_LIST_LIMIT, BLOCK_REQUEST_LIMIT)
}

fn pipelining_config_with_limits(header_limit: usize, block_limit: usize) -> Arc<P2pConfig> {
    let config = crate::test_helpers::test_p2p_config();
    Arc::new(P2pConfig {
        protocol_config: ProtocolConfig {
            msg_header_count_limit: header_limit.into(),
            max_request_blocks_count: block_limit.into(),
            ..config.protocol_config
        },
        ..config
    })
}

fn headers_of(blocks: &[Block]) -> Vec<SignedBlockHeader> {
    blocks.iter().map(|block| block.header().clone()).collect()
}

fn ids_of(blocks: &[Block]) -> Vec<Id<Block>> {
    blocks.iter().map(|block| block.get_id()).collect()
}

async fn deliver_block(peer: &TestPeer, block: &Block) {
    peer.send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
        block.clone(),
    )))
    .await;
}

async fn expect_block_request(
    node: &mut TestNode,
    outstanding: &mut OutstandingRequests,
) -> Vec<Id<Block>> {
    let (_, message) = node.get_sent_block_sync_message().await;
    let BlockSyncMessage::BlockListRequest(request) = message else {
        panic!("expected a block request, got {message:?}")
    };
    let ids = request.into_block_ids();
    outstanding.on_block_request(&ids);
    ids
}

async fn expect_header_request(node: &mut TestNode) {
    let (_, message) = node.get_sent_block_sync_message().await;
    assert!(
        matches!(
            message,
            BlockSyncMessage::HeaderListRequest(HeaderListRequest { .. })
        ),
        "expected a header request, got {message:?}"
    );
}

/// While blocks are being downloaded, the node requests further headers to keep
/// a look-ahead window ahead of the download; header responses may repeat
/// headers that are still in the download pipeline (the request anchor is the
/// last processed block), and those must be skipped rather than requested
/// again. The next portion of the look-ahead is requested while the previous
/// block batch is still in flight, so the peer's send stream stays continuous.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipelined_requests_keep_stream_continuous(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        let blocks = create_n_blocks(&mut rng, &mut tf, 7);
        let headers = headers_of(&blocks);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .with_p2p_config(pipelining_test_config())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let mut outstanding = OutstandingRequests::new(BLOCK_REQUEST_LIMIT);
        let mut pipelined_requests = 0;

        // A full header list starts the download and also triggers a header
        // request, since the look-ahead window is not full yet.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers[..4].to_vec(),
        )))
        .await;

        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[..4].to_vec()
        );
        expect_header_request(&mut node).await;

        // Two blocks get processed; the header response repeats the in-flight
        // headers and adds new ones. The repeated headers are skipped, the new
        // ones are staged, and another header request follows because the
        // window is still not full.
        deliver_block(&peer, &blocks[0]).await;
        outstanding.on_block_received(&blocks[0].get_id());
        deliver_block(&peer, &blocks[1]).await;
        outstanding.on_block_received(&blocks[1].get_id());

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers[2..6].to_vec(),
        )))
        .await;
        expect_header_request(&mut node).await;

        // The next block drops the in-flight count below half the limit: the
        // staged headers must be requested now, while the last block of the
        // first batch is still in flight.
        deliver_block(&peer, &blocks[2]).await;
        outstanding.on_block_received(&blocks[2].get_id());

        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[4..6].to_vec()
        );
        assert!(outstanding.outstanding.contains(&blocks[3].get_id()));
        pipelined_requests += 1;

        // Another header response, again anchored at the last processed block:
        // only the genuinely new header is staged, and the window is still not
        // full, so a header request follows.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers[3..7].to_vec(),
        )))
        .await;
        expect_header_request(&mut node).await;

        deliver_block(&peer, &blocks[3]).await;
        outstanding.on_block_received(&blocks[3].get_id());
        deliver_block(&peer, &blocks[4]).await;
        outstanding.on_block_received(&blocks[4].get_id());

        // In-flight count is below half the limit again: the last staged
        // header is requested while block 5 is still in flight.
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[6..].to_vec()
        );
        assert!(outstanding.outstanding.contains(&blocks[5].get_id()));
        pipelined_requests += 1;

        deliver_block(&peer, &blocks[5]).await;
        outstanding.on_block_received(&blocks[5].get_id());
        deliver_block(&peer, &blocks[6]).await;
        outstanding.on_block_received(&blocks[6].get_id());

        // Nothing is staged or in flight anymore: the node asks for headers.
        expect_header_request(&mut node).await;

        assert_eq!(pipelined_requests, 2);
        assert!(outstanding.outstanding.is_empty());
        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

/// A full header list containing nothing but headers already held in the
/// download pipeline must not trigger further header requests: the request
/// anchor cannot advance until blocks are processed, so asking again would
/// only produce the same answer.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_full_header_list_does_not_spin_requests(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        let blocks = create_n_blocks(&mut rng, &mut tf, 4);
        let headers = headers_of(&blocks);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .with_p2p_config(pipelining_test_config())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers.clone(),
        )))
        .await;

        let (_, message) = node.get_sent_block_sync_message().await;
        assert!(matches!(
            message,
            BlockSyncMessage::BlockListRequest(BlockListRequest { .. })
        ));
        expect_header_request(&mut node).await;

        // Answer the header request with the very same full list: everything
        // in it is in flight already. No further request may be issued.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers.clone(),
        )))
        .await;

        node.assert_no_sync_message().await;

        // The download completes normally afterwards.
        for block in &blocks {
            deliver_block(&peer, block).await;
        }
        expect_header_request(&mut node).await;

        // Once the download is over, the repeated list is a fully known list: the peer
        // still gets its grace of a few header requests before we stop asking, and a
        // known list must never be answered with more than that.
        for _ in 0..3 {
            peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
                headers.clone(),
            )))
            .await;
            expect_header_request(&mut node).await;
        }
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers)))
            .await;
        node.assert_no_sync_message().await;

        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

/// A header list received during a download whose chain diverges from the
/// staged look-ahead replaces the staged headers: after the in-flight batch
/// completes, the node requests the replacement headers, not the stale ones.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn diverging_header_list_replaces_staged_lookahead(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        let blocks = create_n_blocks(&mut rng, &mut tf, 6);

        // Two blocks on a fork off the second mainchain block. The blocks must be
        // distinguishable from the corresponding mainchain blocks: otherwise the node
        // trims them as already-held headers instead of staging a diverging look-ahead.
        // The mainchain blocks are built with identical deterministic contents, so a
        // different timestamp is what sets the fork apart.
        let fork_base_time = blocks[1].header().timestamp().into_time();
        let fork_block_0 = tf
            .make_block_builder()
            .with_parent(blocks[1].get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                fork_base_time.as_secs_since_epoch() + 1,
            )))
            .build(&mut rng);
        let fork_block_1 = tf
            .make_block_builder()
            .with_parent(fork_block_0.get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                fork_base_time.as_secs_since_epoch() + 2,
            )))
            .build(&mut rng);
        let fork_blocks = [fork_block_0, fork_block_1];

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .with_p2p_config(pipelining_test_config())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let mut outstanding = OutstandingRequests::new(BLOCK_REQUEST_LIMIT);

        let headers = headers_of(&blocks);
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers[..4].to_vec(),
        )))
        .await;

        // First batch requested; a header request follows because the window
        // is not full.
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[..4].to_vec()
        );
        expect_header_request(&mut node).await;

        // Two blocks get processed, making the fork parent known to the
        // chainstate; the header response stages a look-ahead on the
        // mainchain (blocks 4 and 5).
        deliver_block(&peer, &blocks[0]).await;
        outstanding.on_block_received(&blocks[0].get_id());
        deliver_block(&peer, &blocks[1]).await;
        outstanding.on_block_received(&blocks[1].get_id());

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(
            headers[2..6].to_vec(),
        )))
        .await;
        expect_header_request(&mut node).await;

        // A diverging list arrives while the download is in flight. It does
        // not connect to the staged look-ahead, so it must replace it.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &fork_blocks,
        ))))
        .await;

        // The next processed block drops the in-flight count below half the
        // limit: the replacement headers must be requested now, while the
        // last mainchain block of the batch is still in flight.
        deliver_block(&peer, &blocks[2]).await;
        outstanding.on_block_received(&blocks[2].get_id());

        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&fork_blocks)
        );
        assert!(outstanding.outstanding.contains(&blocks[3].get_id()));

        // Complete the in-flight mainchain batch, then the fork blocks.
        deliver_block(&peer, &blocks[3]).await;
        outstanding.on_block_received(&blocks[3].get_id());
        for block in &fork_blocks {
            deliver_block(&peer, block).await;
            outstanding.on_block_received(&block.get_id());
        }
        expect_header_request(&mut node).await;

        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

/// A header list received during a download whose chain branches off a header staged
/// strictly inside the look-ahead window must keep the window a single connected chain:
/// the staged headers after the branch point are dropped, the new headers continue from
/// the branch point, and the resulting block requests stay connected (no block is ever
/// requested whose parent is neither processed nor part of the same request sequence).
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_window_branch_keeps_lookahead_connected(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        let blocks = create_n_blocks(&mut rng, &mut tf, 6);

        // Three blocks branching off the fifth mainchain block. The blocks must be
        // distinguishable from the corresponding mainchain blocks, which are built with
        // identical deterministic contents, so a different timestamp is what sets the
        // fork apart.
        let fork_base_time = blocks[4].header().timestamp().into_time();
        let fork_block_0 = tf
            .make_block_builder()
            .with_parent(blocks[4].get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                fork_base_time.as_secs_since_epoch() + 1,
            )))
            .build(&mut rng);
        let fork_block_1 = tf
            .make_block_builder()
            .with_parent(fork_block_0.get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                fork_base_time.as_secs_since_epoch() + 2,
            )))
            .build(&mut rng);
        let fork_block_2 = tf
            .make_block_builder()
            .with_parent(fork_block_1.get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                fork_base_time.as_secs_since_epoch() + 3,
            )))
            .build(&mut rng);
        let fork_blocks = [fork_block_0, fork_block_1, fork_block_2];

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .with_p2p_config(pipelining_config_with_limits(6, 2))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let mut outstanding = OutstandingRequests::new(2);

        // A full list of six headers starts the download: two blocks in flight, four
        // staged, and a header request for the look-ahead.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &blocks,
        ))))
        .await;
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[..2].to_vec()
        );
        expect_header_request(&mut node).await;

        deliver_block(&peer, &blocks[0]).await;
        outstanding.on_block_received(&blocks[0].get_id());
        deliver_block(&peer, &blocks[1]).await;
        outstanding.on_block_received(&blocks[1].get_id());

        // The first batch drained; the next two staged blocks are requested.
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[2..4].to_vec()
        );

        // The peer reorganized away from the staged continuation at blocks[4] (which is
        // still staged, not processed). The list repeats the in-flight and staged
        // headers up to the branch point and then continues on the fork. The staged
        // headers after the branch point must be dropped and the fork headers staged in
        // their place, keeping the window connected.
        let mut branch_list = headers_of(&blocks)[2..5].to_vec();
        branch_list.extend(headers_of(&fork_blocks));
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(branch_list)))
            .await;
        expect_header_request(&mut node).await;

        deliver_block(&peer, &blocks[2]).await;
        outstanding.on_block_received(&blocks[2].get_id());
        deliver_block(&peer, &blocks[3]).await;
        outstanding.on_block_received(&blocks[3].get_id());

        // The branch point itself is requested together with the first fork block: the
        // request stays connected, and the abandoned staged header (blocks[5]) is not
        // requested.
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            [blocks[4].get_id(), fork_blocks[0].get_id()].to_vec()
        );

        deliver_block(&peer, &blocks[4]).await;
        outstanding.on_block_received(&blocks[4].get_id());
        deliver_block(&peer, &fork_blocks[0]).await;
        outstanding.on_block_received(&fork_blocks[0].get_id());

        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&fork_blocks)[1..].to_vec()
        );

        deliver_block(&peer, &fork_blocks[1]).await;
        outstanding.on_block_received(&fork_blocks[1].get_id());
        deliver_block(&peer, &fork_blocks[2]).await;
        outstanding.on_block_received(&fork_blocks[2].get_id());

        expect_header_request(&mut node).await;

        assert!(outstanding.outstanding.is_empty());
        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

/// With very small block request limits (where the top-up watermark can never be
/// reached while a batch is in flight) the download proceeds in lockstep batches, and
/// the invariants hold throughout: the outstanding count never exceeds the limit, no
/// block is requested twice while outstanding, and a block request is only issued while
/// nothing else is outstanding.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy(), 1)]
#[case(Seed::from_entropy(), 2)]
#[case(Seed::from_entropy(), 3)]
#[case(Seed::from_entropy(), 4)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn small_block_request_limits_degrade_to_lockstep(
    #[case] seed: Seed,
    #[case] block_request_limit: usize,
) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        let blocks = create_n_blocks(&mut rng, &mut tf, 4);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .with_p2p_config(pipelining_config_with_limits(4, block_request_limit))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let mut outstanding = OutstandingRequests::new(block_request_limit);

        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &blocks,
        ))))
        .await;

        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[..block_request_limit].to_vec()
        );
        expect_header_request(&mut node).await;

        let mut requested_until = block_request_limit;
        let mut block_requests = 1;
        for (idx, block) in blocks.iter().enumerate() {
            deliver_block(&peer, block).await;
            outstanding.on_block_received(&block.get_id());

            if idx + 1 == requested_until {
                assert!(outstanding.outstanding.is_empty());
                if requested_until < blocks.len() {
                    let next_until = (requested_until + block_request_limit).min(blocks.len());
                    assert_eq!(
                        expect_block_request(&mut node, &mut outstanding).await,
                        ids_of(&blocks)[requested_until..next_until].to_vec()
                    );
                    requested_until = next_until;
                    block_requests += 1;
                } else {
                    expect_header_request(&mut node).await;
                }
            }
        }

        assert_eq!(
            block_requests,
            blocks.len().div_ceil(block_request_limit),
            "the download must proceed in lockstep batches of the configured size"
        );
        assert!(outstanding.outstanding.is_empty());
        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

const REFILL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// A chain of `count` blocks with advancing timestamps, matching the fork download
/// budget test setup (the budget applies outside of the initial block download, which
/// the advancing heights and times ensure).
fn make_timed_chain(
    chain_config: &Arc<common::chain::ChainConfig>,
    count: usize,
    time_getter: &BasicTestTimeGetter,
    rng: &mut impl randomness::Rng,
) -> Vec<Block> {
    let mut prev = None;
    let mut blocks = Vec::with_capacity(count);
    for _ in 0..count {
        let block = make_new_block(chain_config, prev, &time_getter.get_time_getter(), rng);
        time_getter.advance_time(std::time::Duration::from_secs(60));
        blocks.push(block);
        prev = blocks.last();
    }
    blocks
}

fn budgeted_pipelining_config() -> P2pConfig {
    test_p2p_config_with_protocol_config(ProtocolConfig {
        msg_header_count_limit: 4.into(),
        max_request_blocks_count: 2.into(),
        max_fork_downloads_per_peer: ForkDownloadLimit::new(1),
        fork_download_refill_interval: ForkDownloadRefillInterval::new(REFILL_INTERVAL),
        ..Default::default()
    })
}

/// An exhausted fork download budget defers header lists during an active download:
/// nothing is staged and no request is made in response. Once the budget has refilled,
/// the scheduled retry asks for headers while the download is still in flight, and the
/// pipelining logic continues to work on top of the retried list.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exhausted_budget_defers_lists_during_download(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();

        // The node is bootstrapped with the first ten blocks, so the fork download
        // budget applies (it is only enforced outside of the initial block download).
        let blocks = make_timed_chain(&chain_config, 15, &time_getter, &mut rng);

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_time_getter(time_getter.get_time_getter())
            .with_blocks(blocks[..10].to_vec())
            .with_p2p_config(Arc::new(budgeted_pipelining_config()))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let mut outstanding = OutstandingRequests::new(2);

        // The first list is processed (the budget starts with a single token) and
        // starts the download: two blocks in flight, two staged.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &blocks[10..14],
        ))))
        .await;
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[10..12].to_vec()
        );
        expect_header_request(&mut node).await;

        deliver_block(&peer, &blocks[10]).await;
        outstanding.on_block_received(&blocks[10].get_id());

        // The budget is exhausted, so the next list must be deferred: nothing is staged
        // and no message is sent in response.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &blocks[11..15],
        ))))
        .await;
        node.assert_no_sync_message().await;

        // Once the budget has refilled, the scheduled retry asks for headers again.
        time_getter.advance_time(REFILL_INTERVAL * 2);
        expect_header_request(&mut node).await;

        // The retried list is now payable: the repeated in-flight header is skipped and
        // the rest is staged on top of the running download.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &blocks[11..15],
        ))))
        .await;
        expect_header_request(&mut node).await;

        // The in-flight batch drains into the staged look-ahead, and the very small
        // block request limit keeps the rest of the download in lockstep.
        deliver_block(&peer, &blocks[11]).await;
        outstanding.on_block_received(&blocks[11].get_id());
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[12..14].to_vec()
        );

        deliver_block(&peer, &blocks[12]).await;
        outstanding.on_block_received(&blocks[12].get_id());
        deliver_block(&peer, &blocks[13]).await;
        outstanding.on_block_received(&blocks[13].get_id());
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)[14..15].to_vec()
        );

        deliver_block(&peer, &blocks[14]).await;
        outstanding.on_block_received(&blocks[14].get_id());

        expect_header_request(&mut node).await;

        assert!(outstanding.outstanding.is_empty());
        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}

/// A divergent full header list anchored at a block the node already has carries no
/// repeated headers, so staging is limited only by the remaining look-ahead window
/// capacity. Two such lists fill the window exactly to its target; a third must stage
/// nothing and send nothing. Delivering the in-flight blocks reopens capacity and the
/// download of the staged headers resumes normally.
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staging_capacity_caps_lookahead_window(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        let blocks = create_n_blocks(&mut rng, &mut tf, 2);

        // Two divergent two-header chains off the genesis tip. The blocks must be
        // distinguishable from the mainchain blocks, which are built with identical
        // deterministic contents, so different timestamps are what set them apart.
        let base_time = blocks[0].header().timestamp().into_time();
        let divergent_first_0 = tf
            .make_block_builder()
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                base_time.as_secs_since_epoch() + 1,
            )))
            .build(&mut rng);
        let divergent_first_1 = tf
            .make_block_builder()
            .with_parent(divergent_first_0.get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                base_time.as_secs_since_epoch() + 2,
            )))
            .build(&mut rng);
        let divergent_chain_1 = [divergent_first_0, divergent_first_1];
        let divergent_second_0 = tf
            .make_block_builder()
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                base_time.as_secs_since_epoch() + 3,
            )))
            .build(&mut rng);
        let divergent_second_1 = tf
            .make_block_builder()
            .with_parent(divergent_second_0.get_id().into())
            .with_timestamp(BlockTimestamp::from_time(Time::from_secs_since_epoch(
                base_time.as_secs_since_epoch() + 4,
            )))
            .build(&mut rng);
        let divergent_chain_2 = [divergent_second_0, divergent_second_1];

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_chainstate(tf.into_chainstate())
            .with_p2p_config(pipelining_config_with_limits(2, 2))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let mut outstanding = OutstandingRequests::new(2);

        // A full list starts the download: both blocks in flight, the window at half
        // the target.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &blocks,
        ))))
        .await;
        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&blocks)
        );
        expect_header_request(&mut node).await;

        // The first divergent list is staged wholesale and fills the window exactly to
        // the target, so no header request follows.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &divergent_chain_1,
        ))))
        .await;

        // The second divergent list finds the window full: nothing is staged and
        // nothing is sent.
        peer.send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(headers_of(
            &divergent_chain_2,
        ))))
        .await;
        node.assert_no_sync_message().await;

        // Delivering the in-flight blocks reopens the window: the staged headers are
        // requested and the download completes.
        deliver_block(&peer, &blocks[0]).await;
        outstanding.on_block_received(&blocks[0].get_id());
        deliver_block(&peer, &blocks[1]).await;
        outstanding.on_block_received(&blocks[1].get_id());

        assert_eq!(
            expect_block_request(&mut node, &mut outstanding).await,
            ids_of(&divergent_chain_1)
        );

        deliver_block(&peer, &divergent_chain_1[0]).await;
        outstanding.on_block_received(&divergent_chain_1[0].get_id());
        deliver_block(&peer, &divergent_chain_1[1]).await;
        outstanding.on_block_received(&divergent_chain_1[1].get_id());

        expect_header_request(&mut node).await;

        assert!(outstanding.outstanding.is_empty());
        node.assert_no_error().await;
        node.join_subsystem_manager().await;
    })
    .await;
}
