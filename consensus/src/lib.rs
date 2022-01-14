use blockchain_storage::{BlockchainStorage, BlockchainStorageError};
use common::chain::block::Block;
use common::chain::config::ChainConfig;

mod chain_state;
mod orphan_blocks;
use orphan_blocks::OrphanBlocksPool;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockStatus {
    Valid,
    Failed,
    // To be expanded
}

struct Consensus<S: BlockchainStorage> {
    chain_config: ChainConfig,
    blockchain_storage: S,
    orphan_blocks: OrphanBlocksPool,
}

impl<S: BlockchainStorage> Consensus<S> {
    pub fn new(chain_config: ChainConfig, blockchain_storage: S) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
        }
    }

    pub fn process_block(&self, block: &Block) -> BlockStatus {
        match self.check_block(block) {
            BlockStatus::Valid => {
                match <S as BlockchainStorage>::set_block(&self.blockchain_storage, block).is_ok() {
                    true => BlockStatus::Valid,
                    false => BlockStatus::Failed,
                }
            }
            BlockStatus::Failed => BlockStatus::Failed,
        }
    }

    fn check_block(&self, _block: &Block) -> BlockStatus {
        // Will have added some checks
        BlockStatus::Valid
    }
}

#[cfg(test)]
mod tests {
    use crate::Consensus;
    use common::chain::config::create_mainnet;

    #[test]
    #[allow(clippy::eq_op)]
    fn test_genesis() {
        let config = create_mainnet();
        // let storage = MocStorage::new();
        // let consensus = Consensus::new(config, storage);
    }
}
