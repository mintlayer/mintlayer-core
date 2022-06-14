use common::{
    chain::block::{Block, BlockIndex},
    primitives::Id,
};
use logging::log;

use super::consensus_validator::BlockIndexHandle;

pub struct BlockIndexHistoryIterator<'a, H> {
    next_id: Id<Block>,
    block_index_handle: &'a H,
}

impl<'a, H: BlockIndexHandle> BlockIndexHistoryIterator<'a, H> {
    #[must_use]
    pub fn new(starting_id: Id<Block>, block_index_handle: &'a H) -> Self {
        Self {
            next_id: starting_id,
            block_index_handle,
        }
    }
}

impl<'a, H: BlockIndexHandle> Iterator for BlockIndexHistoryIterator<'a, H> {
    type Item = BlockIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let result =
            self.block_index_handle.get_block_index(&self.next_id).expect("Database error");

        let bi = match result {
            Some(bi) => bi,
            None => {
                log::error!("CRITICAL: Invariant error; attempted to read id of a non-existent block index in iterator with id {}", self.next_id);
                return None;
            }
        };

        match bi.get_prev_block_id() {
            Some(next_id) => self.next_id = next_id.clone(),
            None => (),
        }

        Some(bi)
    }
}
