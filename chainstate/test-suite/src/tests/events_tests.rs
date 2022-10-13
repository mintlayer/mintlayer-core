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
use std::sync::Mutex;

use chainstate::BlockError;
use chainstate::BlockSource;
use chainstate::ChainstateError;
use chainstate::ChainstateEvent;
use chainstate::CheckBlockError;
use chainstate::OrphanCheckError;
use common::chain::block::timestamp::BlockTimestamp;
use common::primitives::id::Idable;
use common::primitives::BlockHeight;
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::make_seedable_rng;
use test_utils::random::Seed;

use crate::tests::EventList;
use chainstate_test_framework::OrphanErrorHandler;
use chainstate_test_framework::{TestChainstate, TestFramework};

type ErrorList = Arc<Mutex<Vec<BlockError>>>;

// Subscribe to events, process a block and check that the `NewTip` event is triggered.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simple_subscribe(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();
        let events = subscribe(&mut tf.chainstate, 1);

        // Produce and process a block.
        let first_block =
            tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
        assert!(!tf.chainstate.subscribers().is_empty());
        tf.process_block(first_block.clone(), BlockSource::Local).unwrap();
        tf.chainstate.wait_for_all_events();

        // Check the event.
        {
            let guard = events.lock().unwrap();
            assert_eq!(guard.len(), 1);
            let (id, height) = &guard[0];
            assert_eq!(id, &first_block.get_id());
            assert_eq!(height, &BlockHeight::new(1));
        }

        // Process one more block.
        let second_block =
            tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
        tf.process_block(second_block.clone(), BlockSource::Local).unwrap();
        tf.chainstate.wait_for_all_events();

        let guard = events.lock().unwrap();
        assert_eq!(guard.len(), 2);
        let (id, height) = &guard[0];
        assert_eq!(id, &first_block.get_id());
        assert_eq!(height, &BlockHeight::new(1));
        let (id, height) = &guard[1];
        assert_eq!(id, &second_block.get_id());
        assert_eq!(height, &BlockHeight::new(2));
    });
}

// Subscribe to events several times, then process a block.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn several_subscribers(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();

        let subscribers = rng.gen_range(8..256);
        let events = subscribe(&mut tf.chainstate, subscribers);

        let block = tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();

        assert!(!tf.chainstate.subscribers().is_empty());
        tf.process_block(block.clone(), BlockSource::Local).unwrap();
        tf.chainstate.wait_for_all_events();

        let guard = events.lock().unwrap();
        assert_eq!(guard.len(), subscribers);
        guard.iter().for_each(|(id, height)| {
            assert_eq!(id, &block.get_id());
            assert_eq!(height, &BlockHeight::new(1));
        })
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn several_subscribers_several_events(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::default();

        let subscribers = rng.gen_range(4..16);
        let blocks = rng.gen_range(8..128);

        let events = subscribe(&mut tf.chainstate, subscribers);
        assert!(!tf.chainstate.subscribers().is_empty());

        for _ in 0..blocks {
            let block =
                tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
            let index = tf.process_block(block.clone(), BlockSource::Local).ok().flatten().unwrap();
            tf.chainstate.wait_for_all_events();

            let guard = events.lock().unwrap();
            let (id, height) = guard.last().unwrap();
            assert_eq!(id, index.block_id());
            assert_eq!(height, &index.block_height());
        }
        assert_eq!(blocks * subscribers, events.lock().unwrap().len());
    });
}

// An orphan block is rejected during processing, so it shouldn't trigger the new tip event.
#[test]
fn orphan_block() {
    utils::concurrency::model(move || {
        let (orphan_error_hook, errors) = orphan_error_hook();
        let mut tf = TestFramework::builder().with_orphan_error_hook(orphan_error_hook).build();

        let events = subscribe(&mut tf.chainstate, 1);
        assert!(!tf.chainstate.subscribers().is_empty());

        let block = tf.make_block_builder().make_orphan().build();
        assert_eq!(
            tf.process_block(block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::OrphanCheckFailed(
                OrphanCheckError::LocalOrphan
            ))
        );
        tf.chainstate.wait_for_all_events();
        assert!(events.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty());
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn custom_orphan_error_hook(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (orphan_error_hook, errors) = orphan_error_hook();
        let mut tf = TestFramework::builder().with_orphan_error_hook(orphan_error_hook).build();

        let events = subscribe(&mut tf.chainstate, 1);
        assert!(!tf.chainstate.subscribers().is_empty());

        let first_block =
            tf.make_block_builder().add_test_transaction_from_best_block(&mut rng).build();
        // Produce a block with a bad timestamp.
        let timestamp = tf.genesis().timestamp().as_int_seconds()
            + tf.chainstate.get_chain_config().max_future_block_time_offset().as_secs();
        let second_block = tf
            .make_block_builder()
            .with_parent(first_block.get_id().into())
            .with_timestamp(BlockTimestamp::from_int_seconds(timestamp))
            .build();

        // The second block isn't processed because its parent isn't known.
        assert_eq!(
            tf.process_block(second_block, BlockSource::Local).unwrap_err(),
            ChainstateError::ProcessBlockError(BlockError::OrphanCheckFailed(
                OrphanCheckError::LocalOrphan
            ))
        );
        tf.chainstate.wait_for_all_events();
        assert!(events.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty());

        // Processing the first block should trigger the custom orphan error hook.
        tf.process_block(first_block, BlockSource::Local).unwrap();
        tf.chainstate.wait_for_all_events();
        assert_eq!(events.lock().unwrap().len(), 1);
        let guard = errors.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(
            guard[0],
            BlockError::CheckBlockFailed(CheckBlockError::BlockTimeOrderInvalid)
        );
    });
}

// Subscribes to events N times emulating different subscribers.
fn subscribe(chainstate: &mut TestChainstate, n: usize) -> EventList {
    let events = Arc::new(Mutex::new(Vec::new()));

    for _ in 0..n {
        let events_ = Arc::clone(&events);
        let handler = Arc::new(move |event: ChainstateEvent| match event {
            ChainstateEvent::NewTip(block_id, block_height) => {
                events_.lock().unwrap().push((block_id, block_height));
            }
        });
        chainstate.subscribe_to_events(handler);
    }

    events
}

fn orphan_error_hook() -> (Arc<OrphanErrorHandler>, ErrorList) {
    let errors = Arc::new(Mutex::new(Vec::new()));
    let errors_ = Arc::clone(&errors);
    let handler = Arc::new(move |error: &BlockError| {
        errors_.lock().unwrap().push(error.clone());
    });
    (handler, errors)
}
