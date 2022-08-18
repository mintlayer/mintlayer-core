use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use chainstate_types::Locator;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};

use crate::{
    chainstate_interface::ChainstateInterface, BlockSource, ChainstateError, ChainstateEvent,
};

impl<
        T: Deref<Target = dyn ChainstateInterface> + DerefMut<Target = dyn ChainstateInterface> + Send,
    > ChainstateInterface for T
{
    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ChainstateEvent) + Send + Sync>) {
        self.deref_mut().subscribe_to_events(handler)
    }

    fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ChainstateError> {
        self.deref_mut().process_block(block, source)
    }

    fn preliminary_block_check(&self, block: Block) -> Result<Block, ChainstateError> {
        self.deref().preliminary_block_check(block)
    }

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, ChainstateError> {
        self.deref().get_best_block_id()
    }

    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ChainstateError> {
        self.deref().is_block_in_main_chain(block_id)
    }

    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, ChainstateError> {
        self.deref().get_block_height_in_main_chain(block_id)
    }

    fn get_best_block_height(&self) -> Result<BlockHeight, ChainstateError> {
        self.deref().get_best_block_height()
    }

    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, ChainstateError> {
        self.deref().get_block_id_from_height(height)
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ChainstateError> {
        self.deref().get_block(block_id)
    }

    fn get_locator(&self) -> Result<Locator, ChainstateError> {
        self.deref().get_locator()
    }

    fn get_headers(
        &self,
        locator: Locator,
    ) -> Result<Vec<common::chain::block::BlockHeader>, ChainstateError> {
        self.deref().get_headers(locator)
    }

    fn filter_already_existing_blocks(
        &self,
        headers: Vec<common::chain::block::BlockHeader>,
    ) -> Result<Vec<common::chain::block::BlockHeader>, ChainstateError> {
        self.deref().filter_already_existing_blocks(headers)
    }
}
