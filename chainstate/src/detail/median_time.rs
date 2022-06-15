use common::{chain::block::Block, primitives::Id};
use itertools::Itertools;

use crate::detail::block_index_history_iter::BlockIndexHistoryIterator;

use super::consensus_validator::BlockIndexHandle;

const MEDIAN_TIME_SPAN: usize = 11;

#[must_use]
pub fn calculate_median_time_past<H: BlockIndexHandle>(
    block_index_handle: &H,
    starting_block: &Id<Block>,
) -> u32 {
    let iter = BlockIndexHistoryIterator::new(starting_block.clone(), block_index_handle);
    let time_values = iter
        .take(MEDIAN_TIME_SPAN)
        .map(|bi| bi.get_block_time())
        .sorted()
        .collect::<Vec<_>>();

    time_values[time_values.len() / 2]
}

#[cfg(test)]
mod test {
    use crate::{BlockSource, Chainstate};

    use super::*;
    use blockchain_storage::Store;
    use common::{
        chain::{block::ConsensusData, config::create_unit_test_config},
        primitives::{time, Idable},
    };
    use std::sync::Arc;

    fn make_block(prev_block: Id<Block>, time: u32) -> Block {
        Block::new(vec![], Some(prev_block), time, ConsensusData::None)
            .expect("Block creation failed")
    }

    fn chain_blocks(count: usize, initial_prev: Id<Block>, initial_time: u32) -> Vec<Block> {
        let mut res = vec![];
        let mut prev = initial_prev;
        let mut time = initial_time;
        for _ in 0..count {
            let block = make_block(prev, time);
            prev = block.get_id().clone();
            time = block.block_time() + 1;
            res.push(block);
        }
        assert_eq!(res.len(), count);
        res
    }

    #[test]
    fn blocks_median_time() {
        common::concurrency::model(|| {
            let chain_config = Arc::new(create_unit_test_config());
            let storage = Store::new_empty().unwrap();
            let mut chainstate = Chainstate::new(chain_config, storage, None, None).unwrap();

            let block_count = 500;

            let blocks = chain_blocks(
                block_count,
                chainstate.chain_config.genesis_block_id(),
                time::get() as u32,
            );

            for block in &blocks {
                chainstate.process_block(block.clone(), BlockSource::Local).unwrap();
            }

            {
                let current_height: u64 =
                    chainstate.get_best_block_index().unwrap().unwrap().get_block_height().into();
                assert_eq!(current_height, block_count as u64);
            }

            {
                // median time for genesis block
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(
                    &chainstate_ref,
                    &chainstate.chain_config.genesis_block_id(),
                );
                assert_eq!(median, chainstate.chain_config.genesis_block().block_time());
            }

            for n in 0..MEDIAN_TIME_SPAN {
                // median time for block of height n
                // up to the median span
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &blocks[n].get_id());
                assert_eq!(median, blocks[n / 2].block_time());
            }

            for n in MEDIAN_TIME_SPAN..block_count {
                // median time for block of height n
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &blocks[n].get_id());
                assert_eq!(median, blocks[n - MEDIAN_TIME_SPAN / 2].block_time());
            }
        });
    }
}
