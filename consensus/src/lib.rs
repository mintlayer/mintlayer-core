mod detail;

use common::{
    chain::{block::Block, ChainConfig},
    primitives::{BlockHeight, Id},
};
pub use detail::BlockError;
use detail::{BlockSource, Consensus};

pub struct ConsensusInterface {
    consensus: detail::Consensus,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ConsensusError {
    #[error("Initialization error")]
    FailedToInitializeConsensus(String),
    #[error("Block processing failed: `{0}`")]
    ProcessBlockError(BlockError),
    #[error("Property read error: `{0}`")]
    FailedToReadProperty(BlockError),
}

impl ConsensusInterface {
    pub fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<(), ConsensusError> {
        self.consensus
            .process_block(block, source)
            .map_err(ConsensusError::ProcessBlockError)?;
        Ok(())
    }

    pub fn get_best_block_id(&self) -> Result<Id<Block>, ConsensusError> {
        Ok(self
            .consensus
            .get_best_block_id()
            .map_err(ConsensusError::FailedToReadProperty)?
            .expect("There always must be a best block"))
    }

    pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> Result<bool, ConsensusError> {
        Ok(self
            .consensus
            .get_block_height_in_main_chain(block_id)
            .map_err(ConsensusError::FailedToReadProperty)?
            .is_some())
    }

    pub fn get_block_height_in_main_chain(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, ConsensusError> {
        self.consensus
            .get_block_height_in_main_chain(block_id)
            .map_err(ConsensusError::FailedToReadProperty)
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, ConsensusError> {
        self.consensus
            .get_block_id_from_height(height)
            .map_err(ConsensusError::FailedToReadProperty)
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ConsensusError> {
        self.consensus.get_block(block_id).map_err(ConsensusError::FailedToReadProperty)
    }
}

pub fn make_consensus(
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store,
) -> Result<ConsensusInterface, ConsensusError> {
    let cons = Consensus::new(chain_config, blockchain_storage)?;
    let cons_interface = ConsensusInterface { consensus: cons };
    Ok(cons_interface)
}

#[cfg(test)]
mod test;
