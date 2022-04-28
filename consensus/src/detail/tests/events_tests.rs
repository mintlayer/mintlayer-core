// Copyright (c) 2021 RBB S.r.l
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
use common::chain::config::create_mainnet;
use common::primitives::Id;
use std::collections::BTreeMap;

#[test]
fn test_events_simple_subscribe() {
    use std::sync::Arc;

    common::concurrency::model(|| {
        let mut consensus = setup_consensus();

        // We should connect a new block
        let block = produce_test_block(
            &consensus.chain_config,
            consensus.chain_config.genesis_block(),
            false,
        );
        // The event "NewTip" should return block_id and height
        let expected_block_id = block.get_id();
        let expected_block_height = BlockHeight::new(1);

        // Event handler
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    assert!(block_height == expected_block_height);
                    assert!(block_id == expected_block_id);
                }
            },
        );

        // Subscribe and then process a new block
        consensus.subscribe_to_events(subscribe_func);
        assert!(!consensus.event_subscribers.is_empty());
        assert!(consensus.process_block(block, BlockSource::Local).is_ok());
    });
}

#[test]
fn test_events_with_a_bunch_of_subscribers() {
    use std::sync::Arc;

    const COUNT_SUBSCRIBERS: usize = 100;

    common::concurrency::model(|| {
        let mut consensus = setup_consensus();

        // We should connect a new block
        let block = produce_test_block(
            &consensus.chain_config,
            consensus.chain_config.genesis_block(),
            false,
        );

        // The event "NewTip" should return block_id and height
        let expected_block_id = block.get_id();
        let expected_block_height = BlockHeight::new(1);

        // Event handler
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    assert!(block_height == expected_block_height);
                    assert!(block_id == expected_block_id);
                }
            },
        );

        // Subscribe and then process a new block
        for _ in 1..=COUNT_SUBSCRIBERS {
            consensus.subscribe_to_events(subscribe_func.clone());
        }
        assert!(!consensus.event_subscribers.is_empty());
        assert!(consensus.process_block(block, BlockSource::Local).is_ok());
    });
}

#[test]
fn test_events_a_bunch_of_events() {
    use std::sync::Arc;

    const COUNT_SUBSCRIBERS: usize = 10;
    const COUNT_EVENTS: usize = 100;

    common::concurrency::model(|| {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage).unwrap();

        let mut map_heights: BTreeMap<Id<Block>, BlockHeight> = BTreeMap::new();
        let mut blocks = Vec::new();
        let mut rand_block = consensus.chain_config.genesis_block().clone();
        for height in 1..=COUNT_EVENTS {
            rand_block = produce_test_block(&consensus.chain_config, &rand_block, false);
            blocks.push(rand_block.clone());
            map_heights.insert(
                rand_block.get_id(),
                BlockHeight::new(height.try_into().unwrap()),
            );
        }

        // Event handler
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(block_id, block_height) => {
                    assert!(map_heights.contains_key(&block_id));
                    assert!(&block_height == map_heights.get(&block_id).unwrap());
                }
            },
        );

        // Subscribe and then process a new block
        for _ in 1..=COUNT_SUBSCRIBERS {
            consensus.subscribe_to_events(subscribe_func.clone());
        }
        assert!(!consensus.event_subscribers.is_empty());

        for block in blocks {
            // We should connect a new block
            assert!(consensus.process_block(block.clone(), BlockSource::Local).is_ok());
        }
    });
}

#[test]
fn test_events_orphan_block() {
    use std::sync::Arc;

    common::concurrency::model(|| {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config, storage).unwrap();

        // Let's create an orphan block
        let block = produce_test_block(
            &consensus.chain_config,
            consensus.chain_config.genesis_block(),
            true,
        );

        // Event handler
        let subscribe_func = Arc::new(
            move |consensus_event: ConsensusEvent| match consensus_event {
                ConsensusEvent::NewTip(_, _) => {
                    panic!("Never should happen")
                }
            },
        );

        // Subscribe and then process a new block
        consensus.subscribe_to_events(subscribe_func);
        assert!(!consensus.event_subscribers.is_empty());
        assert!(consensus.process_block(block, BlockSource::Local).is_err());
    });
}
