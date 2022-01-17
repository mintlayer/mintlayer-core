use blockchain_storage::{BlockchainStorage, Error};
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::primitives::{time, Id, H256};

mod chain_state;
use chain_state::BlockStatus;

mod orphan_blocks;
use crate::chain_state::BlockError;
use crate::chain_state::BlockIndex;
use orphan_blocks::OrphanBlocksPool;

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

    pub fn process_block(&mut self, block: &Block) -> Result<BlockStatus, BlockError> {
        if self.check_block(block) == BlockStatus::Failed {
            return Ok(BlockStatus::Failed);
        }

        if self.accept_block(block) == BlockStatus::Failed {
            return Ok(BlockStatus::Failed);
        }

        Ok(self.activate_best_chain(block)?)
    }

    fn activate_best_chain(&mut self, block: &Block) -> Result<BlockStatus, BlockError> {
        // let starting_tip = self
        //     .blockchain_storage
        //     .get_best_block_id()
        //     .map_err(|_| BlockError::Unknown)?
        //     .unwrap_or(BlockIndex::new());

        let new_tip = BlockIndex::new();

        Ok(BlockStatus::Valid)
    }

    fn accept_block(&mut self, block: &Block) -> BlockStatus {
        let blk_index = BlockIndex::new();

        if !self.check_block_index(&blk_index) {
            return BlockStatus::Failed;
        }

        match <S as BlockchainStorage>::add_block(&mut self.blockchain_storage, block) {
            Ok(_) => BlockStatus::Valid,
            Err(err) => {
                match err {
                    // TODO: Add checks for DB status, if we have recoverable error then we have to retry to perform operation
                    Error::RecoverableError(_) | Error::UnrecoverableError(_) => {
                        BlockStatus::Failed
                    }
                }
            }
        }
    }

    fn check_block_index(&mut self, blk_index: &BlockIndex) -> bool {
        // TODO: Will be expanded
        true
    }

    fn check_block_header(&mut self, block: &Block) -> blockchain_storage::Result<BlockStatus> {
        // Hash of the previous block
        let prev_block_id = block.get_prev_block_id();

        // If it is the genesis block, then we skip this check
        let previous_block = self.blockchain_storage.get_block(prev_block_id.clone())?;
        if prev_block_id != (Id::<Block>::new(&H256::zero())) {
            //  Is the previous block not found?
            if previous_block.is_none() {
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
        // Time
        let block_time = block.get_block_time();
        if let Some(previous_block) = previous_block {
            if previous_block.get_block_time() > block_time {
                return Ok(BlockStatus::Failed);
            }
        }
        if i64::from(block_time) > time::get() {
            return Ok(BlockStatus::Failed);
        }
        Ok(BlockStatus::Valid)
    }

    fn check_pos(&self, block: &Block) -> bool {
        // TODO: We have to decide how to check it
        true
    }
    fn check_transactions(&self, block: &Block) -> bool {
        //TODO: Must check for duplicate inputs (see CVE-2018-17144)
        //TODO: Size limits
        //TODO: Check signatures
        true
    }

    fn check_block(&mut self, block: &Block) -> BlockStatus {
        if self.check_block_header(block) != Ok(BlockStatus::Valid) {
            return BlockStatus::Failed;
        }
        if !self.check_pos(block) {
            return BlockStatus::Failed;
        }
        if !self.check_transactions(block) {
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
