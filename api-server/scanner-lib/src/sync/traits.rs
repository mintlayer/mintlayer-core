use chainstate::ChainInfo;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

pub trait LocalNode {
    type Error: std::error::Error;

    /// Returns the current best known block (may be genesis)
    fn best_block(&self) -> (Id<GenBlock>, BlockHeight);

    /// Scan new blocks:
    /// 1. Reset local blocks to the common block height
    /// (it will be lower than the current block height in case of reorg).
    /// 2. Append new blocks.
    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> Result<(), Self::Error>;
}

#[async_trait::async_trait]
pub trait RemoteNode {
    type Error: std::error::Error;

    async fn chainstate(&self) -> Result<ChainInfo, Self::Error>;
    async fn last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error>;
    async fn mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error>;
}
