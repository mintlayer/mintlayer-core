// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Sinitsyn, S. Tkach

use std::sync::Arc;

use crate::detail::tests::*;
use chainstate_storage::Store;

type ErrorList = Arc<Mutex<Vec<BlockError>>>;

// Subscribe to events, process a block and check that the `NewTip` event is triggered.
#[test]
fn simple_subscribe() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        let events = subscribe(&mut chainstate, 1);

        // Produce and process a block.
        let first_block = produce_test_block(TestBlockInfo::from_genesis(
            chainstate.chain_config.genesis_block(),
        ));
        assert!(!chainstate.events_controller.subscribers().is_empty());
        chainstate.process_block(first_block.clone(), BlockSource::Local).unwrap();
        chainstate.wait_for_all_events();

        // Check the event.
        {
            let guard = events.lock().unwrap();
            assert_eq!(guard.len(), 1);
            let (id, height) = &guard[0];
            assert_eq!(id, &first_block.get_id());
            assert_eq!(height, &BlockHeight::new(1));
        }

        // Process one more block.
        let second_block = produce_test_block(TestBlockInfo::from_block(&first_block));
        chainstate.process_block(second_block.clone(), BlockSource::Local).unwrap();
        chainstate.wait_for_all_events();

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
#[test]
fn several_subscribers() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();
        let mut rng = make_seedable_rng(None);
        let subscribers = rng.gen_range(8..256);
        let events = subscribe(&mut chainstate, subscribers);

        let block = produce_test_block(TestBlockInfo::from_genesis(
            chainstate.chain_config.genesis_block(),
        ));

        assert!(!chainstate.events_controller.subscribers().is_empty());
        chainstate.process_block(block.clone(), BlockSource::Local).unwrap();
        chainstate.wait_for_all_events();

        let guard = events.lock().unwrap();
        assert_eq!(guard.len(), subscribers);
        guard.iter().for_each(|(id, height)| {
            assert_eq!(id, &block.get_id());
            assert_eq!(height, &BlockHeight::new(1));
        })
    });
}

#[test]
fn several_subscribers_several_events() {
    common::concurrency::model(|| {
        let mut chainstate = setup_chainstate();

        let mut rng = make_seedable_rng(None);
        let subscribers = rng.gen_range(4..16);
        let blocks = rng.gen_range(8..128);

        let events = subscribe(&mut chainstate, subscribers);
        assert!(!chainstate.events_controller.subscribers().is_empty());

        let mut block_info = TestBlockInfo::from_genesis(chainstate.chain_config.genesis_block());
        for _ in 0..blocks {
            let block = produce_test_block(block_info);
            block_info = TestBlockInfo::from_block(&block);
            let index = chainstate
                .process_block(block.clone(), BlockSource::Local)
                .ok()
                .flatten()
                .unwrap();
            chainstate.wait_for_all_events();

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
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let (orphan_error_hook, errors) = orphan_error_hook();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            Some(orphan_error_hook),
            Default::default(),
        )
        .unwrap();

        let events = subscribe(&mut chainstate, 1);
        assert!(!chainstate.events_controller.subscribers().is_empty());

        let block = produce_test_block(
            TestBlockInfo::from_genesis(chainstate.chain_config.genesis_block()).orphan(),
        );
        assert_eq!(
            chainstate.process_block(block, BlockSource::Local).unwrap_err(),
            BlockError::OrphanCheckFailed(OrphanCheckError::LocalOrphan)
        );
        chainstate.wait_for_all_events();
        assert!(events.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty());
    });
}

#[test]
fn custom_orphan_error_hook() {
    common::concurrency::model(|| {
        let chain_config = Arc::new(create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let storage = Store::new_empty().unwrap();
        let (orphan_error_hook, errors) = orphan_error_hook();
        let mut chainstate = Chainstate::new(
            chain_config,
            chainstate_config,
            storage,
            Some(orphan_error_hook),
            Default::default(),
        )
        .unwrap();

        let events = subscribe(&mut chainstate, 1);
        assert!(!chainstate.events_controller.subscribers().is_empty());

        let first_block = produce_test_block(TestBlockInfo::from_genesis(
            chainstate.chain_config.genesis_block(),
        ));
        // Produce a block with a bad timestamp.
        let timestamp = chainstate.chain_config.genesis_block().timestamp().as_int_seconds()
            + chainstate.chain_config.max_future_block_time_offset().as_secs();
        let second_block = Block::new(
            vec![],
            first_block.get_id().into(),
            BlockTimestamp::from_int_seconds(timestamp),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL);

        // The second block isn't processed because its parent isn't known.
        assert_eq!(
            chainstate.process_block(second_block, BlockSource::Local).unwrap_err(),
            BlockError::OrphanCheckFailed(OrphanCheckError::LocalOrphan)
        );
        chainstate.wait_for_all_events();
        assert!(events.lock().unwrap().is_empty());
        assert!(errors.lock().unwrap().is_empty());

        // Processing the first block should trigger the custom orphan error hook.
        chainstate.process_block(first_block, BlockSource::Local).unwrap();
        chainstate.wait_for_all_events();
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
fn subscribe(chainstate: &mut Chainstate, n: usize) -> EventList {
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
