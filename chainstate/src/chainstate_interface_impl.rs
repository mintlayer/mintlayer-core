use common::{
    chain::block::{Block, BlockHeader},
    primitives::{BlockHeight, Id},
};
use utils::eventhandler::EventHandler;

use crate::{
    detail::{self, BlockSource},
    ChainstateError, ChainstateEvent, ChainstateInterface,
};

pub struct ChainstateInterfaceImpl {
    chainstate: detail::Chainstate,
}

impl ChainstateInterfaceImpl {
    pub fn new(chainstate: detail::Chainstate) -> Self {
        Self { chainstate }
    }
}

impl ChainstateInterface for ChainstateInterfaceImpl {
    fn subscribe_to_events(&mut self, handler: EventHandler<ChainstateEvent>) {
        self.chainstate.subscribe_to_events(handler)
    }

    fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ChainstateError> {
        self.chainstate
            .process_block(block, source)
            .map_err(ChainstateError::ProcessBlockError)?;
        Ok(())
    }

    fn preliminary_block_check(&self, block: Block) -> Result<(), ChainstateError> {
        self.chainstate
            .preliminary_block_check(block)
            .map_err(ChainstateError::ProcessBlockError)
    }

    fn get_best_block_id(&self) -> Result<Id<Block>, ChainstateError> {
        Ok(self
            .chainstate
            .get_best_block_id()
            .map_err(ChainstateError::FailedToReadProperty)?
            .expect("There always must be a best block"))
    }

    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError> {
        Ok(self
            .chainstate
            .get_block_height_in_main_chain(block_id)
            .map_err(ChainstateError::FailedToReadProperty)?
            .is_some())
    }

    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, ChainstateError> {
        self.chainstate
            .get_block_height_in_main_chain(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, ChainstateError> {
        self.chainstate
            .get_block_id_from_height(height)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError> {
        self.chainstate
            .get_block(block_id)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_locator(&self) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.chainstate.get_locator().map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_headers(&self, locator: Vec<BlockHeader>) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.chainstate
            .get_headers(locator)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, ChainstateError> {
        self.chainstate
            .filter_already_existing_blocks(headers)
            .map_err(ChainstateError::FailedToReadProperty)
    }

    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError> {
        let best_block_index = self
            .chainstate
            .get_best_block_index()
            .map_err(ChainstateError::FailedToReadProperty)?
            .expect("Best block index could not be found");
        Ok(best_block_index.get_block_height())
    }
}
