// Temporary placeholders. Should be deleted once an actual representation/implementation is ready.

use crate::pow::data::Data;
use common::chain::block::Block;
use common::primitives::{BlockHeight, Id};

pub struct BlockIndex {
    pub height: BlockHeight,
    pub data: Data,
}

impl BlockIndex {
    pub fn get_block_time(&self) -> u32 {
        todo!()
    }

    pub fn get_ancestor(&self, height: BlockHeight) -> BlockIndex {
        todo!()
    }

    pub fn get_prev(&self) -> Option<Id<Block>> {
        todo!()
    }
}

impl From<Block> for BlockIndex {
    fn from(_: Block) -> Self {
        todo!()
    }
}
