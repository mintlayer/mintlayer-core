use crate::chain::block::Block;
use crate::chain::ChainConfig;
use crate::primitives::{BlockHeight, Id, Idable};
// use crate::Uint256;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    block_id: Id<Block>,
    prev_block_id: Option<Id<Block>>,
    next_block_id: Option<Id<Block>>,
    // TODO: When Carla finish her code, we should use Uint256 at the moment it's unable to store to DB
    //  pub chain_trust: Uint256,
    chain_trust: u128,
    height: BlockHeight,
    time: u32,
    // TODO: Discuss with Sam
    time_max: u32, 
}

impl BlockIndex {
    pub fn new(block: &Block, chain_trust: u128, height: BlockHeight, time_max: u32) -> Self {
        // We have to use the whole block because we are not able to take block_hash from the header
        Self {
            block_id: block.get_id(),
            prev_block_id: block.prev_block_id(),
            next_block_id: None,
            chain_trust,
            height,
            time: block.block_time(),
            time_max,
        }
    }

    pub fn get_block_id<'a: 'b, 'b>(&'a self) -> &'b Id<Block> {
        &self.block_id
    }

    pub fn get_prev_block_id<'a: 'b, 'b>(&'a self) -> &'b Option<Id<Block>> {
        &self.prev_block_id
    }

    pub fn get_next_block_id<'a: 'b, 'b>(&'a self) -> &'b Option<Id<Block>> {
        &self.next_block_id
    }

    pub fn set_next_block_id(&mut self, id_block: Id<Block>) {
        self.next_block_id = Some(id_block);
    }

    pub fn unset_next_block_id(&mut self) {
        self.next_block_id = None;
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.prev_block_id == None && chain_config.genesis_block().get_id() == self.block_id
    }

    pub fn get_block_time(&self) -> u32 {
        self.time
    }

    pub fn get_block_time_max(&self) -> u32 {
        self.time_max
    }

    pub fn get_block_height(&self) -> BlockHeight {
        self.height
    }

    pub fn get_chain_trust(&self) -> u128 {
        self.chain_trust
    }
}
