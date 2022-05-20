use std::sync::Arc;

use common::{
    chain::block::{Block, BlockHeader},
    primitives::{BlockHeight, Id},
};

use crate::{
    detail::{self, BlockSource},
    ConsensusError, ConsensusEvent, ConsensusInterface,
};

pub struct ConsensusInterfaceImpl {
    consensus: detail::Consensus,
}

impl ConsensusInterfaceImpl {
    pub fn new(consensus: detail::Consensus) -> Self {
        Self { consensus }
    }
}

impl ConsensusInterface for ConsensusInterfaceImpl {
    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(ConsensusEvent) + Send + Sync>) {
        self.consensus.subscribe_to_events(handler)
    }

    fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), ConsensusError> {
        self.consensus
            .process_block(block, source)
            .map_err(ConsensusError::ProcessBlockError)?;
        Ok(())
    }

    fn get_best_block_id(&self) -> Result<Id<Block>, ConsensusError> {
        Ok(self
            .consensus
            .get_best_block_id()
            .map_err(ConsensusError::FailedToReadProperty)?
            .expect("There always must be a best block"))
    }

    fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ConsensusError> {
        Ok(self
            .consensus
            .get_block_height_in_main_chain(block_id)
            .map_err(ConsensusError::FailedToReadProperty)?
            .is_some())
    }

    fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, ConsensusError> {
        self.consensus
            .get_block_height_in_main_chain(block_id)
            .map_err(ConsensusError::FailedToReadProperty)
    }

    fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, ConsensusError> {
        self.consensus
            .get_block_id_from_height(height)
            .map_err(ConsensusError::FailedToReadProperty)
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ConsensusError> {
        self.consensus.get_block(block_id).map_err(ConsensusError::FailedToReadProperty)
    }

    fn get_locator(&self) -> Result<Vec<BlockHeader>, ConsensusError> {
        self.consensus.get_locator().map_err(ConsensusError::FailedToReadProperty)
    }

    fn get_headers(&self, locator: Vec<BlockHeader>) -> Result<Vec<BlockHeader>, ConsensusError> {
        self.consensus
            .get_headers(locator)
            .map_err(ConsensusError::FailedToReadProperty)
    }
}
