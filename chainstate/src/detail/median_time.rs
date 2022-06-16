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
    use crate::{detail::time_getter::TimeGetter, BlockSource, Chainstate};

    use super::*;
    use blockchain_storage::Store;
    use common::{
        chain::{block::ConsensusData, config::create_unit_test_config},
        primitives::{time, Idable},
    };
    use std::sync::{atomic::Ordering, Arc};

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
            let mut chainstate =
                Chainstate::new(chain_config, storage, None, Default::default()).unwrap();

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
                // starting from the median span
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &blocks[n].get_id());
                assert_eq!(median, blocks[n - MEDIAN_TIME_SPAN / 2].block_time());
            }
        });
    }

    #[test]
    fn blocks_median_time_unordered_blocks_in_time() {
        common::concurrency::model(|| {
            let chain_config = Arc::new(create_unit_test_config());

            let current_time = Arc::new(std::sync::atomic::AtomicI64::new(
                chain_config.genesis_block().block_time() as i64,
            ));

            let chainstate_current_time = Arc::clone(&current_time);
            let time_getter = TimeGetter::new(Arc::new(move || {
                chainstate_current_time.load(Ordering::SeqCst)
            }));

            let storage = Store::new_empty().unwrap();
            let mut chainstate = Chainstate::new(chain_config, storage, None, time_getter).unwrap();

            // we use unordered block times, and ensure that the median will be in the right spot
            let block1_time = current_time.load(Ordering::SeqCst) as u32 + 1;
            let block2_time = current_time.load(Ordering::SeqCst) as u32 + 20;
            let block3_time = current_time.load(Ordering::SeqCst) as u32 + 10;
            let block4_time = current_time.load(Ordering::SeqCst) as u32 + 18;
            let block5_time = current_time.load(Ordering::SeqCst) as u32 + 17;

            let block1 = make_block(chainstate.chain_config.genesis_block_id(), block1_time);
            let block2 = make_block(block1.get_id(), block2_time);
            let block3 = make_block(block2.get_id(), block3_time);
            let block4 = make_block(block3.get_id(), block4_time);
            let block5 = make_block(block4.get_id(), block5_time);

            chainstate.process_block(block1.clone(), BlockSource::Local).unwrap();
            chainstate.process_block(block2.clone(), BlockSource::Local).unwrap();
            chainstate.process_block(block3.clone(), BlockSource::Local).unwrap();
            chainstate.process_block(block4.clone(), BlockSource::Local).unwrap();
            chainstate.process_block(block5.clone(), BlockSource::Local).unwrap();

            {
                let current_height: u64 =
                    chainstate.get_best_block_index().unwrap().unwrap().get_block_height().into();
                assert_eq!(current_height, 5);
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

            {
                // median time for block of height 1
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &block1.get_id());
                assert_eq!(median, block1_time);
            }

            {
                // median time for block of height 2
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &block2.get_id());
                assert_eq!(median, block1_time);
            }

            {
                // median time for block of height 3
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &block3.get_id());
                assert_eq!(median, block3_time);
            }

            {
                // median time for block of height 4
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &block4.get_id());
                assert_eq!(median, block3_time);
            }

            {
                // median time for block of height 5
                let chainstate_ref = chainstate.make_db_tx_ro();
                let median = calculate_median_time_past(&chainstate_ref, &block5.get_id());
                assert_eq!(median, block5_time);
            }
        });
    }
}
