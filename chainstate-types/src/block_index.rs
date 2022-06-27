use common::chain::block::block_header::BlockHeader;
use common::chain::block::Block;
use common::chain::ChainConfig;
use common::primitives::{BlockHeight, Id, Idable};
use common::Uint256;
use serialization::{Decode, Encode};

use common::chain::block::timestamp::BlockTimestamp;

#[derive(Debug, Clone, Encode, Decode)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    block_id: Id<Block>,
    block_header: BlockHeader,
    skip: Option<Id<Block>>,
    chain_trust: Uint256,
    height: BlockHeight,
    time_max: BlockTimestamp,
}

impl BlockIndex {
    pub fn new(
        block: &Block,
        chain_trust: Uint256,
        some_ancestor: Option<Id<Block>>,
        height: BlockHeight,
        time_max: BlockTimestamp,
    ) -> Self {
        // We have to use the whole block because we are not able to take block_hash from the header
        Self {
            block_header: block.header().clone(),
            block_id: block.get_id(),
            skip: some_ancestor,
            chain_trust,
            height,
            time_max,
        }
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn prev_block_id(&self) -> &Option<Id<Block>> {
        self.block_header.prev_block_id()
    }

    pub fn is_genesis(&self, chain_config: &ChainConfig) -> bool {
        self.block_header.is_genesis(chain_config)
    }

    pub fn block_timestamp(&self) -> BlockTimestamp {
        self.block_header.timestamp()
    }

    pub fn chain_timestamps_max(&self) -> BlockTimestamp {
        self.time_max
    }

    pub fn block_height(&self) -> BlockHeight {
        self.height
    }

    pub fn chain_trust(&self) -> &Uint256 {
        &self.chain_trust
    }

    pub fn block_header(&self) -> &BlockHeader {
        &self.block_header
    }

    pub fn some_ancestor(&self) -> Option<&Id<Block>> {
        self.skip.as_ref()
    }

    pub fn into_block_header(self) -> BlockHeader {
        self.block_header
    }
}
