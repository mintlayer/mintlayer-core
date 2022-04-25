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

impl ConsensusInterface {
    pub fn process_block(&mut self, block: Block, source: BlockSource) -> Result<(), BlockError> {
        self.consensus.process_block(block, source)?;
        Ok(())
    }

    pub fn get_best_block_id(&self) -> Result<Id<Block>, BlockError> {
        self.consensus.get_best_block_id()
    }
}

pub fn make_consensus(
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store,
) -> Result<ConsensusInterface, Box<dyn std::error::Error>> {
    let cons = Consensus::new(chain_config, blockchain_storage);
    let cons_interface = ConsensusInterface { consensus: cons };
    Ok(cons_interface)
}
