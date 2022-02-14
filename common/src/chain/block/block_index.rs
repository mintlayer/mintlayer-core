use crate::chain::block::Block;
use crate::chain::ChainConfig;
use crate::primitives::{BlockHeight, Id, Idable, H256};
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    pub hash_block: H256,
    pub prev_block_hash: Option<H256>,
    pub next_block_hash: Option<H256>,
    pub chain_trust: u64,
    pub height: BlockHeight,
    pub time: u32,
}

impl BlockIndex {
    pub fn new(block: &Block) -> Self {
        // We have to use the whole block because we are not able to take hash_block from the header
        Self {
            hash_block: block.get_id().get(),
            prev_block_hash: Some(block.get_prev_block_id().get()),
            next_block_hash: None,
            chain_trust: 0,
            height: BlockHeight::new(0),
            time: block.get_block_time(),
        }
    }

    pub fn get_id(&self) -> Id<Block> {
        Id::new(&self.hash_block)
    }

    pub fn get_prev_block_id(&self) -> Option<Id<Block>> {
        self.prev_block_hash.map(|x| Id::new(&x))
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.prev_block_hash == None
            && chain_config.genesis_block().get_id().get() == self.hash_block
    }

    pub fn get_block_time(&self) -> u32 {
        self.time
    }
}
