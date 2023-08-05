use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

/// An abstraction that represents the state of the API server locally.
/// This state is updated by the sync process, which uses a RemoteNode to fetch new blocks.
pub trait LocalBlockchainState {
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
