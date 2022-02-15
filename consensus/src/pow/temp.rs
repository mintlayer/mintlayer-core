#![allow(dead_code, unused_variables)]
// Temporary placeholders. Should be deleted once an actual representation/implementation is ready.

use common::chain::block::consensus_data::PoWData;
use common::chain::block::Block;
use common::primitives::{BlockHeight, Id};

pub struct BlockIndex {
    pub height: BlockHeight,
    pub data: PoWData,
}

impl BlockIndex {
    pub fn get_block_time(&self) -> u32 {
        todo!()
    }

    pub fn get_ancestor(&self, height: BlockHeight) -> BlockIndex {
        todo!()
    }

    pub fn prev(&self) -> Option<Id<Block>> {
        todo!()
    }
}

impl From<Block> for BlockIndex {
    fn from(_: Block) -> Self {
        todo!()
    }
}
