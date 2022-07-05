#[cfg(any(test, feature = "mock"))]
pub mod mock;

use std::sync::Arc;

use common::{
    chain::block::{Block, BlockHeader},
    primitives::{BlockHeight, Id},
};

use crate::{detail::BlockSource, ChainstateError, ChainstateEvent};

pub trait ChainstateInterface: Send {
    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>);
    fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ChainstateError>;
    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError>;
    fn get_best_block_id(&self) -> Result<Id<Block>, ChainstateError>;
    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError>;
    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, ChainstateError>;
    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError>;
    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, ChainstateError>;
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError>;

    /// Returns a list of block headers whose heights distances increase exponentially starting
    /// from the current tip.
    ///
    /// This returns a relatively short sequence even for a long chain. Such sequence can be used
    /// to quickly find a common ancestor between different chains.
    fn get_locator(&self) -> Result<Vec<BlockHeader>, ChainstateError>;

    /// Returns a list of block headers starting from the last locator's block that is in the main
    /// chain.
    ///
    /// The number of returned headers is limited by the `HEADER_LIMIT` constant. The genesis block
    /// header is returned in case there is no common ancestor with a better block height.
    fn get_headers(&self, locator: Vec<BlockHeader>) -> Result<Vec<BlockHeader>, ChainstateError>;

    /// Removes all headers that are already known to the chain from the given vector.
    fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, ChainstateError>;
}
