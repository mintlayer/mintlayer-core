use crate::chain::block::block_v1::BlockHeader;
use crate::chain::block::Block;
use crate::chain::ChainConfig;
use crate::primitives::{BlockHeight, Id, Idable};
// use crate::Uint256;
use serialization::{Decode, Encode};

#[derive(Debug, Clone, Encode, Decode)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    block_id: Id<Block>,
    block_header: BlockHeader,
    // TODO: When Carla finish her code, we should use Uint256 at the moment it's unable to store to DB
    //  pub chain_trust: Uint256,
    chain_trust: u128,
    height: BlockHeight,
    // TODO: Make a type for block time. ISSUE: https://github.com/mintlayer/mintlayer-core/issues/127
    // TODO: Discuss with Sam
    time_max: u32,
}

impl BlockIndex {
    pub fn new(block: &Block, chain_trust: u128, height: BlockHeight, time_max: u32) -> Self {
        // We have to use the whole block because we are not able to take block_hash from the header
        Self {
            block_header: block.header().clone(),
            block_id: block.get_id(),
            chain_trust,
            height,
            time_max,
        }
    }

    pub fn get_block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn get_prev_block_id(&self) -> &Option<Id<Block>> {
        &self.block_header.prev_block_hash
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.block_header.is_genesis(chain_config)
    }

    // TODO: Make a type for block time. ISSUE: https://github.com/mintlayer/mintlayer-core/issues/127
    pub fn get_block_time(&self) -> u32 {
        self.block_header.time
    }

    // TODO: Make a type for block time. ISSUE: https://github.com/mintlayer/mintlayer-core/issues/127
    pub fn get_block_time_max(&self) -> u32 {
        self.time_max
    }

    pub fn get_block_height(&self) -> BlockHeight {
        self.height
    }

    pub fn get_chain_trust(&self) -> u128 {
        self.chain_trust
    }

    pub fn get_block_header(&self) -> &BlockHeader {
        &self.block_header
    }

    pub fn into_block_header(self) -> BlockHeader {
        self.block_header
    }
}
