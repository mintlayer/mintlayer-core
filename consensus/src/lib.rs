use blockchain_storage::BlockchainStorage;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::primitives::merkle::MerkleTreeFormError;
use common::primitives::{Id, H256};

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

    pub fn process_block(&mut self, block: &Block) -> BlockStatus {
        match self.check_block(block) {
            BlockStatus::Valid => {
                // TODO: Add checks for DB status, if we have recoverable error then we have to retry to perform operation
                match <S as BlockchainStorage>::add_block(&mut self.blockchain_storage, block)
                    .is_ok()
                {
                    true => BlockStatus::Valid,
                    false => BlockStatus::Failed,
                }
            }
            BlockStatus::Failed => BlockStatus::Failed,
        }
    }

    fn check_block_header(&mut self, block: &Block) -> blockchain_storage::Result<BlockStatus> {
        // Hash of the previous block
        let prev_block_id = block.get_prev_block_id();

        // If it is the genesis block, then we skip this check
        if prev_block_id != (Id::<Block>::new(&H256::zero())) {
            //  Is the previous block not found?
            if self.blockchain_storage.get_block(prev_block_id)?.is_none() {
                return Ok(BlockStatus::Failed);
            }
        }

        // MerkleTree root
        let merkle_tree_root = block.get_merkle_root();
        match calculate_tx_merkle_root(block.get_transactions()) {
            Ok(merkle_tree) => {
                if merkle_tree_root != merkle_tree {
                    return Ok(BlockStatus::Failed);
                }
            }
            Err(_merkle_error) => {
                // TODO: Should we return additional error information?
                return Ok(BlockStatus::Failed);
            }
        }

        // Witness merkle root
        let witness_merkle_root = block.get_witness_merkle_root();
        match calculate_witness_merkle_root(block.get_transactions()) {
            Ok(witness_merkle) => {
                if witness_merkle_root != witness_merkle {
                    return Ok(BlockStatus::Failed);
                }
            }
            Err(_merkle_error) => {
                // TODO: Should we return additional error information?
                return Ok(BlockStatus::Failed);
            }
        }
        //   - Time
        let block_time = block.get_block_time();

        //   - Consensus data
        Ok(BlockStatus::Valid)
    }

    fn check_block(&mut self, block: &Block) -> BlockStatus {
        // Checks:
        if self.check_block_header(block) != Ok(BlockStatus::Valid) {
            return BlockStatus::Failed;
        }

        // Will have added some checks
        BlockStatus::Valid
    }
}

#[cfg(test)]
mod tests {
    use crate::{BlockStatus, Consensus};
    use blockchain_storage::Store;
    use common::chain::config::create_mainnet;

    #[test]
    #[allow(clippy::eq_op)]
    fn test_block_accept_genesis() {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), storage);
        assert_eq!(
            consensus.process_block(config.genesis_block()),
            BlockStatus::Valid
        );
    }
}
