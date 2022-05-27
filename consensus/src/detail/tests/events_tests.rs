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
// Author(s): A. Sinitsyn

use crate::detail::tests::*;
use blockchain_storage::Store;
use common::chain::block::Block;
use common::primitives::Id;
use std::collections::BTreeMap;

#[test]
fn test_events_simple_subscribe() {
    use std::sync::Arc;

    common::concurrency::model(|| {
        let mut consensus = setup_consensus();

        // We should connect a new block
        let block = produce_test_block(consensus.chain_config.genesis_block(), false);
        // The event "NewTip" should return block_id and height
        let expected_block_id = block.get_id();
        let expected_block_height = BlockHeight::new(1);

        // Event handler
        let events: EventList = Arc::new(Mutex::new(Vec::new()));
        let events_copy = Arc::clone(&events);
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    events_copy.lock().unwrap().push((block_id, block_height));
                }
            },
        );

        // Subscribe and then process a new block
        consensus.subscribe_to_events(subscribe_func);
        assert!(!consensus.event_subscribers.is_empty());
        assert!(consensus.process_block(block, BlockSource::Local).is_ok());
        wait_for_threadpool_to_finish(&mut consensus);
        assert!(events.lock().unwrap().len() == 1);
        events.lock().unwrap().iter().for_each(|(block_id, block_height)| {
            assert!(block_height == &expected_block_height);
            assert!(block_id == &expected_block_id);
        });
    });
}

#[test]
fn test_events_with_a_bunch_of_subscribers() {
    use std::sync::Arc;

    const COUNT_SUBSCRIBERS: usize = 100;

    common::concurrency::model(|| {
        let mut consensus = setup_consensus();

        // We should connect a new block
        let block = produce_test_block(consensus.chain_config.genesis_block(), false);

        // The event "NewTip" should return block_id and height
        let expected_block_id = block.get_id();
        let expected_block_height = BlockHeight::new(1);

        // Event handler
        let events: EventList = Arc::new(Mutex::new(Vec::new()));
        let events_copy = Arc::clone(&events);
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    events_copy.lock().unwrap().push((block_id, block_height));
                }
            },
        );

        // Subscribe and then process a new block
        for _ in 0..COUNT_SUBSCRIBERS {
            consensus.subscribe_to_events(subscribe_func.clone());
        }
        assert!(!consensus.event_subscribers.is_empty());
        assert!(consensus.process_block(block, BlockSource::Local).is_ok());
        wait_for_threadpool_to_finish(&mut consensus);
        assert!(events.lock().unwrap().len() == COUNT_SUBSCRIBERS);
        events.lock().unwrap().iter().for_each(|(block_id, block_height)| {
            assert!(block_height == &expected_block_height);
            assert!(block_id == &expected_block_id);
        });
    });
}

#[test]
fn test_events_a_bunch_of_events() {
    use common::chain::config::create_unit_test_config;
    use std::sync::Arc;

    const COUNT_SUBSCRIBERS: usize = 10;
    const COUNT_EVENTS: usize = 100;

    common::concurrency::model(|| {
        let config = Arc::new(create_unit_test_config());
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage, None).unwrap();

        let mut map_heights: BTreeMap<Id<Block>, BlockHeight> = BTreeMap::new();
        let mut blocks = Vec::new();
        let mut rand_block = consensus.chain_config.genesis_block().clone();
        for height in 0..COUNT_EVENTS {
            rand_block = produce_test_block(&rand_block, false);
            blocks.push(rand_block.clone());
            map_heights.insert(
                rand_block.get_id(),
                BlockHeight::new(height.try_into().unwrap()),
            );
        }

        // Event handler
        let events: EventList = Arc::new(Mutex::new(Vec::new()));
        let events_copy = Arc::clone(&events);
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    events_copy.lock().unwrap().push((block_id, block_height));
                }
            },
        );

        // Subscribe and then process a new block
        for _ in 0..COUNT_SUBSCRIBERS {
            consensus.subscribe_to_events(subscribe_func.clone());
        }
        assert!(!consensus.event_subscribers.is_empty());

        for block in blocks {
            // We should connect a new block
            let block_index = consensus
                .process_block(block.clone(), BlockSource::Local)
                .ok()
                .flatten()
                .unwrap();
            wait_for_threadpool_to_finish(&mut consensus);
            assert!(block_index.get_block_id() == &events.lock().unwrap().last().unwrap().0);
            assert!(block_index.get_block_height() == events.lock().unwrap().last().unwrap().1);
        }
    });
}

#[test]
fn test_events_orphan_block() {
    use common::chain::config::create_unit_test_config;
    use std::sync::Arc;

    common::concurrency::model(|| {
        let config = Arc::new(create_unit_test_config());
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage, None).unwrap();

        // Let's create an orphan block
        let block = produce_test_block(consensus.chain_config.genesis_block(), true);

        // Event handler
        let events: EventList = Arc::new(Mutex::new(Vec::new()));
        let events_copy = Arc::clone(&events);
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    events_copy.lock().unwrap().push((block_id, block_height));
                }
            },
        );
        // Subscribe and then process a new block
        consensus.subscribe_to_events(subscribe_func);
        assert!(!consensus.event_subscribers.is_empty());
        assert!(consensus.process_block(block, BlockSource::Local).is_err());
        wait_for_threadpool_to_finish(&mut consensus);
        assert!(events.lock().unwrap().is_empty());
    });
}
