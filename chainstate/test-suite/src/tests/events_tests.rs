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

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use rstest::rstest;

use chainstate::{
    BlockError, BlockSource, ChainstateError, ChainstateEvent, CheckBlockError, OrphanCheckError,
};
use chainstate_test_framework::{OrphanErrorHandler, TestChainstate, TestFramework};
use common::{
    chain::{block::timestamp::BlockTimestamp, GenBlock},
    primitives::{id::Idable, BlockHeight, Id},
};
use randomness::Rng;
use test_utils::{
    assert_matches,
    random::{make_seedable_rng, Seed},
};

// TODO use EventList from helpers instead.
type EventList = Arc<Mutex<Vec<(Id<GenBlock>, BlockHeight)>>>;

type ErrorList = Arc<Mutex<Vec<BlockError>>>;

// Subscribe to events, process a block and check that the `NewTip` event is triggered.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simple_subscribe(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();
        let events = subscribe(&mut tf.chainstate, 1);

        // Produce and process a block.
        let first_block = tf
            .make_block_builder()
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);
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
        let second_block = tf
            .make_block_builder()
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);
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
        let mut tf = TestFramework::builder(&mut rng).build();

        let subscribers = rng.gen_range(8..256);
        let events = subscribe(&mut tf.chainstate, subscribers);

        let block = tf
            .make_block_builder()
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);

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
        let mut tf = TestFramework::builder(&mut rng).build();

        let subscribers = rng.gen_range(4..16);
        let blocks = rng.gen_range(8..128);

        let events = subscribe(&mut tf.chainstate, subscribers);
        assert!(!tf.chainstate.subscribers().is_empty());

        for _ in 0..blocks {
            let block = tf
                .make_block_builder()
                .add_test_transaction_from_best_block(&mut rng)
                .build(&mut rng);
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
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn orphan_block(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let (orphan_error_hook, errors) = orphan_error_hook();
        let mut tf = TestFramework::builder(&mut rng)
            .with_orphan_error_hook(orphan_error_hook)
            .build();

        let events = subscribe(&mut tf.chainstate, 1);
        assert!(!tf.chainstate.subscribers().is_empty());

        let block = tf.make_block_builder().make_orphan(&mut rng).build(&mut rng);
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
        let mut tf = TestFramework::builder(&mut rng)
            .with_orphan_error_hook(orphan_error_hook)
            .build();

        let events = subscribe(&mut tf.chainstate, 1);
        assert!(!tf.chainstate.subscribers().is_empty());

        let first_block = tf
            .make_block_builder()
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);
        // Produce a block with a bad timestamp.
        let timestamp = tf.genesis().timestamp().as_int_seconds()
            + tf.chainstate
                .get_chain_config()
                .max_future_block_time_offset(BlockHeight::zero())
                .as_secs()
            + 1;
        let second_block = tf
            .make_block_builder()
            .with_parent(first_block.get_id().into())
            .with_timestamp(BlockTimestamp::from_int_seconds(timestamp))
            .build(&mut rng);
        let second_block_id = second_block.get_id();

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
        let errors_guard = errors.lock().unwrap();
        assert_eq!(errors_guard.len(), 1);
        assert_matches!(
            &errors_guard[0],
            BlockError::CheckBlockFailed(CheckBlockError::BlockFromTheFuture {
                block_id,
                block_timestamp: _,
                current_time: _
            })
            if block_id == &second_block_id
        );
    });
}

// Subscribes to events N times emulating different subscribers.
fn subscribe(chainstate: &mut TestChainstate, n: usize) -> EventList {
    let events = Arc::new(Mutex::new(Vec::new()));

    for _ in 0..n {
        let events_ = Arc::clone(&events);
        let handler = Arc::new(move |event: ChainstateEvent| match event {
            ChainstateEvent::NewTip {
                id: block_id,
                height: block_height,
                is_initial_block_download: _,
            } => {
                events_.lock().unwrap().push((block_id, block_height));
            }
        });
        chainstate.subscribe_to_subsystem_events(handler);
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

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn several_subscribers_several_events_broadcaster(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let initial_secs_since_genesis = 100;
    let max_tip_age_secs = 10;
    let mut tf = TestFramework::builder(&mut rng)
        .with_max_tip_age(Duration::from_secs(max_tip_age_secs).into())
        .with_initial_time_since_genesis(initial_secs_since_genesis)
        .build();
    let mock_time = Arc::clone(tf.time_value.as_ref().unwrap());

    let subscribers_count = rng.gen_range(4..16);
    let blocks_count = rng.gen_range(8..128);

    let mut receivers: Vec<_> = (0..subscribers_count)
        .map(|_| tf.chainstate.subscribe_to_rpc_events())
        .collect();

    let event_processor = tokio::spawn(async move {
        let mut events = vec![Vec::new(); receivers.len()];
        for _ in 0..blocks_count {
            for (idx, receiver) in receivers.iter_mut().enumerate() {
                events[idx].push(receiver.recv().await.unwrap());
            }
        }
        for receiver in receivers.iter_mut() {
            assert!(receiver.recv().await.is_none());
        }
        events
    });

    let first_fresh_block_idx = rng.gen_range(0..blocks_count);

    let mut expected_events = Vec::new();
    for idx in 0..blocks_count {
        let (time_advance, is_ibd) = match idx.cmp(&first_fresh_block_idx) {
            std::cmp::Ordering::Less => {
                // The block will not be considered fresh and the chainstate will remain in ibd.
                (rng.gen_range(max_tip_age_secs..max_tip_age_secs * 2), true)
            }
            std::cmp::Ordering::Equal => {
                // The block will be considered fresh and the chainstate will no longer be in ibd.
                (rng.gen_range(0..max_tip_age_secs), false)
            }
            std::cmp::Ordering::Greater => {
                // The chainstate can't return to ibd once it switched to non-ibd,
                // so block time can be arbitrary here.
                (rng.gen_range(0..max_tip_age_secs * 2), false)
            }
        };

        let timestamp = BlockTimestamp::from_int_seconds(mock_time.fetch_add(time_advance));
        let block = tf
            .make_block_builder()
            .with_timestamp(timestamp)
            .add_test_transaction_from_best_block(&mut rng)
            .build(&mut rng);
        let index = tf.process_block(block.clone(), BlockSource::Local).ok().flatten().unwrap();
        expected_events.push(ChainstateEvent::NewTip {
            id: (*index.block_id()).into(),
            height: index.block_height(),
            is_initial_block_download: is_ibd,
        });
    }

    std::mem::drop(tf);

    let event_traces = tokio::time::timeout(std::time::Duration::from_secs(5), event_processor)
        .await
        .expect("timeout")
        .expect("event processor panicked");

    for (subscriber_idx, actual_events) in event_traces.iter().enumerate() {
        assert_eq!(
            actual_events, &expected_events,
            "events mismatch for subscriber {subscriber_idx}"
        );
    }
}
