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

use chainstate_types::BlockIndexHandle;
use itertools::Itertools;

use common::{
    chain::{block::timestamp::BlockTimestamp, GenBlock},
    primitives::Id,
};

use crate::detail::block_index_history_iter::BlockIndexHistoryIterator;

const MEDIAN_TIME_SPAN: usize = 11;

#[must_use]
pub fn calculate_median_time_past<H: BlockIndexHandle>(
    block_index_handle: &H,
    starting_block: &Id<GenBlock>,
) -> BlockTimestamp {
    let iter = BlockIndexHistoryIterator::new(*starting_block, block_index_handle);
    let time_values = iter
        .take(MEDIAN_TIME_SPAN)
        .map(|bi| bi.block_timestamp())
        .sorted()
        .collect::<Vec<_>>();

    time_values[time_values.len() / 2]
}

#[cfg(test)]
mod test {
    use crate::{
        detail::tx_verification_strategy::DefaultTransactionVerificationStrategy, BlockSource,
        Chainstate, ChainstateConfig,
    };
    use common::primitives::time;
    use test_utils::mock_time_getter::mocked_time_getter_seconds;

    use super::*;
    use chainstate_storage::inmemory::Store;
    use common::{
        chain::{
            block::{
                timestamp::{BlockTimestamp, BlockTimestampInternalType},
                Block, BlockReward, ConsensusData,
            },
            config::create_unit_test_config,
        },
        primitives::Idable,
    };
    use std::sync::{atomic::Ordering, Arc};

    fn make_block(prev_block: Id<GenBlock>, time: BlockTimestampInternalType) -> Block {
        Block::new(
            vec![],
            prev_block,
            BlockTimestamp::from_int_seconds(time),
            ConsensusData::None,
            BlockReward::new(Vec::new()),
        )
        .expect("Block creation failed")
    }

    fn chain_blocks(
        count: usize,
        initial_prev: Id<GenBlock>,
        initial_time: BlockTimestampInternalType,
    ) -> Vec<Block> {
        let mut res = vec![];
        let mut prev = initial_prev;
        let mut time = initial_time;
        for _ in 0..count {
            let block = make_block(prev, time);
            prev = block.get_id().into();
            time = block.timestamp().as_int_seconds() + 1;
            res.push(block);
        }
        assert_eq!(res.len(), count);
        res
    }

    #[test]
    fn blocks_median_time() {
        utils::concurrency::model(|| {
            let chain_config = Arc::new(create_unit_test_config());
            let chainstate_config = ChainstateConfig::new();
            let storage = Store::new_empty().unwrap();
            let mut chainstate = Chainstate::new(
                chain_config,
                chainstate_config,
                storage,
                DefaultTransactionVerificationStrategy::new(),
                None,
                Default::default(),
            )
            .unwrap();

            let block_count = 500;

            let blocks = chain_blocks(
                block_count,
                chainstate.chain_config.genesis_block_id(),
                time::get_system_time().as_secs(),
            );

            for block in &blocks {
                chainstate.process_block(block.clone().into(), BlockSource::Local).unwrap();
            }

            {
                let current_height: u64 = chainstate
                    .query()
                    .unwrap()
                    .get_best_block_index()
                    .unwrap()
                    .unwrap()
                    .block_height()
                    .into();
                assert_eq!(current_height, block_count as u64);
            }

            {
                // median time for genesis block
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(
                    &chainstate_ref,
                    &chainstate.chain_config.genesis_block_id(),
                );
                assert_eq!(median, chainstate.chain_config.genesis_block().timestamp());
            }

            for n in 0..MEDIAN_TIME_SPAN {
                // median time for block of height n
                // up to the median span
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median =
                    calculate_median_time_past(&chainstate_ref, &blocks[n].get_id().into());
                assert_eq!(median, blocks[n / 2].timestamp());
            }

            for n in MEDIAN_TIME_SPAN..block_count {
                // median time for block of height n
                // starting from the median span
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median =
                    calculate_median_time_past(&chainstate_ref, &blocks[n].get_id().into());
                assert_eq!(median, blocks[n - MEDIAN_TIME_SPAN / 2].timestamp());
            }
        });
    }

    #[test]
    fn blocks_median_time_unordered_blocks_in_time() {
        utils::concurrency::model(|| {
            let chain_config = Arc::new(create_unit_test_config());

            let current_time = Arc::new(std::sync::atomic::AtomicU64::new(
                chain_config.genesis_block().timestamp().as_int_seconds(),
            ));

            let time_getter = mocked_time_getter_seconds(Arc::clone(&current_time));

            let storage = Store::new_empty().unwrap();
            let chainstate_config = ChainstateConfig::new();
            let mut chainstate = Chainstate::new(
                chain_config,
                chainstate_config,
                storage,
                DefaultTransactionVerificationStrategy::new(),
                None,
                time_getter,
            )
            .unwrap();

            // we use unordered block times, and ensure that the median will be in the right spot
            let block1_time = current_time.load(Ordering::SeqCst) + 1;
            let block2_time = current_time.load(Ordering::SeqCst) + 20;
            let block3_time = current_time.load(Ordering::SeqCst) + 10;
            let block4_time = current_time.load(Ordering::SeqCst) + 18;
            let block5_time = current_time.load(Ordering::SeqCst) + 17;

            let block1 = make_block(chainstate.chain_config.genesis_block_id(), block1_time);
            let block2 = make_block(block1.get_id().into(), block2_time);
            let block3 = make_block(block2.get_id().into(), block3_time);
            let block4 = make_block(block3.get_id().into(), block4_time);
            let block5 = make_block(block4.get_id().into(), block5_time);

            chainstate.process_block(block1.clone().into(), BlockSource::Local).unwrap();
            chainstate.process_block(block2.clone().into(), BlockSource::Local).unwrap();
            chainstate.process_block(block3.clone().into(), BlockSource::Local).unwrap();
            chainstate.process_block(block4.clone().into(), BlockSource::Local).unwrap();
            chainstate.process_block(block5.clone().into(), BlockSource::Local).unwrap();

            {
                let current_height: u64 = chainstate
                    .query()
                    .unwrap()
                    .get_best_block_index()
                    .unwrap()
                    .unwrap()
                    .block_height()
                    .into();
                assert_eq!(current_height, 5);
            }

            {
                // median time for genesis block
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(
                    &chainstate_ref,
                    &chainstate.chain_config.genesis_block_id(),
                );
                assert_eq!(median, chainstate.chain_config.genesis_block().timestamp());
            }

            {
                // median time for block of height 1
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(&chainstate_ref, &block1.get_id().into());
                assert_eq!(median, BlockTimestamp::from_int_seconds(block1_time));
            }

            {
                // median time for block of height 2
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(&chainstate_ref, &block2.get_id().into());
                assert_eq!(median, BlockTimestamp::from_int_seconds(block1_time));
            }

            {
                // median time for block of height 3
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(&chainstate_ref, &block3.get_id().into());
                assert_eq!(median, BlockTimestamp::from_int_seconds(block3_time));
            }

            {
                // median time for block of height 4
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(&chainstate_ref, &block4.get_id().into());
                assert_eq!(median, BlockTimestamp::from_int_seconds(block3_time));
            }

            {
                // median time for block of height 5
                let chainstate_ref = chainstate.make_db_tx_ro().unwrap();
                let median = calculate_median_time_past(&chainstate_ref, &block5.get_id().into());
                assert_eq!(median, BlockTimestamp::from_int_seconds(block5_time));
            }
        });
    }
}
