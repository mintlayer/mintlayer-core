mod detail;

use common::{
    chain::{block::Block, ChainConfig},
    primitives::Id,
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
    #[error("Property read error")]
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
            .map_err(|e| ConsensusError::FailedToReadProperty(e))?
            .expect("There always must be a best block"))
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
