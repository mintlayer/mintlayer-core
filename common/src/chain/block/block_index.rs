use crate::chain::block::Block;
use crate::chain::ChainConfig;
use crate::primitives::{BlockHeight, Id, Idable};
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    pub block_id: Id<Block>,
    pub prev_block_id: Option<Id<Block>>,
    pub next_block_id: Option<Id<Block>>,
    pub chain_trust: u64,
    pub height: BlockHeight,
    pub time: u32,
    pub time_max: u32,
}

impl BlockIndex {
    pub fn new(block: &Block, chain_trust: u64, height: BlockHeight, time_max: u32) -> Self {
        // We have to use the whole block because we are not able to take block_hash from the header
        Self {
            block_id: block.get_id(),
            prev_block_id: block.get_prev_block_id().map(|block_id| block_id.into()),
            next_block_id: None,
            chain_trust,
            height,
            time: block.get_block_time(),
            time_max,
        }
    }

    pub fn get_block_id<'a: 'b, 'b>(&'a self) -> &'b Id<Block> {
        &self.block_id
    }

    pub fn get_prev_block_id<'a: 'b, 'b>(&'a self) -> &'b Option<Id<Block>> {
        &self.prev_block_id
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.prev_block_id == None && chain_config.genesis_block().get_id() == self.block_id
    }

    pub fn get_block_time(&self) -> u32 {
        self.time
    }
}
