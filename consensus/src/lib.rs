use blockchain_storage::{BlockchainStorage, Error};
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::primitives::{time, BlockHeight, Id, Idable};
use std::collections::HashSet;
use std::rc::Rc;

mod chain_state;
use chain_state::*;
mod orphan_blocks;
use crate::orphan_blocks::OrphanAddError;
use orphan_blocks::OrphanBlocksPool;

#[allow(dead_code)]
struct Consensus<S: BlockchainStorage> {
    chain_config: ChainConfig,
    blockchain_storage: S,
    orphan_blocks: OrphanBlocksPool,
    // TODO: We have to add these fields in a proper way.
    current_block_height: BlockHeight,
    failed_blocks: HashSet<BlockIndex>,
}

impl<S: BlockchainStorage> Consensus<S> {
    #[allow(dead_code)]
    pub fn new(chain_config: ChainConfig, blockchain_storage: S) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
            current_block_height: BlockHeight::new(0),
            failed_blocks: HashSet::new(),
        }
    }

    #[allow(dead_code)]
    pub fn process_block(&mut self, block: Block) -> Result<Option<Tip>, BlockError> {
        const RC_FAIL: &str = "RefCounter failure";
        self.check_block(&block)?;
        let mut rc_block = Rc::new(block);
        let block_index =
            self.accept_block(Rc::get_mut(&mut rc_block).expect(RC_FAIL)).map_err(|err| {
                dbg!(&err);
                match err {
                    BlockError::Orphan => self
                        .new_orphan_block(Rc::get_mut(&mut rc_block).expect(RC_FAIL))
                        .expect("Storage failure"),
                    _ => (),
                }
                err
            })?;
        Ok(self.activate_best_chain(block_index)?)
    }

    /// Mark new block as an orphan
    /// Ok(()) - Added
    /// Err(BlockError) - StorageFailure  
    fn new_orphan_block(&mut self, block: &Block) -> Result<(), BlockError> {
        // If we have not the previous block we have to move it to OrphanBlocksPool, except if it genesis block
        if block.get_id() != self.chain_config.genesis_block().get_id() {
            if self.get_block(block.get_prev_block_id())?.is_none() {
                self.orphan_blocks.add_block(block.clone()).map_err(|err| {
                    return match err {
                        OrphanAddError::BlockAlreadyInOrphanList(_) => BlockError::Orphan,
                    };
                })?;
            }
        }
        Ok(())
    }

    fn process_storage_failure(&self, err: blockchain_storage::Error) -> BlockError {
        match err {
            // TODO: Add checks for DB status, if we have recoverable error then we have to retry to perform operation
            Error::RecoverableError(_) | Error::UnrecoverableError(_) => {
                BlockError::StorageFailure(err)
            }
        }
    }

    fn get_ancestor(&mut self, block_id: Id<Block>) -> Result<BlockIndex, BlockError> {
        let block = self.get_block(block_id)?;
        dbg!(&block);
        match block {
            Some(block) => {
                let prev_block = block.get_prev_block_id();
                Ok(BlockIndex::new(
                    &self.get_block(prev_block)?.ok_or(BlockError::NotFound)?,
                ))
            }
            None => Err(BlockError::NotFound),
        }
    }

    fn exist_block(&mut self, block_id: Id<Block>) -> Result<bool, BlockError> {
        Ok(self.get_block(block_id)?.is_some())
    }

    fn get_block(&mut self, id: Id<Block>) -> Result<Option<Block>, BlockError> {
        Ok(self
            .blockchain_storage
            .get_block(id)
            .map_err(|err| self.process_storage_failure(err))?)
    }

    fn set_best_block_id(&mut self, id: &Id<Block>) -> Result<(), BlockError> {
        Ok(
            <S as BlockchainStorage>::set_best_block_id(&mut self.blockchain_storage, id)
                .map_err(|err| self.process_storage_failure(err))?,
        )
    }

    fn get_best_block_id(&mut self) -> Result<Option<Id<Block>>, BlockError> {
        Ok(
            <S as BlockchainStorage>::get_best_block_id(&mut self.blockchain_storage)
                .map_err(|err| self.process_storage_failure(err))?,
        )
    }

    // Disconnect active blocks which are no longer in the best chain.
    fn disconnect_blocks(&mut self, _ancestor: BlockIndex) {
        // TODO: Under construction
    }

    // Build list of new blocks to connect (in descending height order).
    fn make_new_chain(&self) -> Vec<BlockIndex> {
        // TODO: Under construction
        vec![]
    }

    // Connect mew blocks
    fn connect_blocks(&mut self, _blocks: Vec<BlockIndex>) {
        // TODO: Under construction
    }

    fn genesis_block_index(&self) -> BlockIndex {
        BlockIndex::new(self.chain_config.genesis_block())
    }

    fn get_common_ancestor(
        &mut self,
        tip: BlockIndex,
        new_block: BlockIndex,
    ) -> Result<BlockIndex, BlockError> {
        let mut prev_block_on_tip_chain = self.get_ancestor(tip.get_id())?;
        let mut prev_block_on_new_chain = self.get_ancestor(new_block.get_id())?;

        loop {
            if prev_block_on_tip_chain == prev_block_on_new_chain {
                return Ok(prev_block_on_tip_chain);
            }
            prev_block_on_tip_chain = self.get_ancestor(prev_block_on_tip_chain.get_id())?;
            prev_block_on_new_chain = self.get_ancestor(prev_block_on_new_chain.get_id())?;
        }
    }

    fn index_from_opt_id(&mut self, id_block: Id<Block>) -> Result<BlockIndex, BlockError> {
        let block = self
            .blockchain_storage
            .get_block(id_block)
            .map_err(|err| self.process_storage_failure(err))?;
        match block {
            Some(blk) => Ok(BlockIndex::new(&blk)),
            None => Err(BlockError::Unknown),
        }
    }

    #[allow(dead_code)]
    fn activate_best_chain(
        &mut self,
        mut block_index: BlockIndex,
    ) -> Result<Option<Tip>, BlockError> {
        println!("ENTER activate_best_chain");

        // TODO: We have to decide how we can generate `chain_trust`, at the moment it is wrong
        block_index.chain_trust = self.current_block_height.into();
        let best_block = self.get_best_block_id()?;
        println!("BEST BLOCK: {:?}", &best_block);
        if let Some(best_block) = best_block {
            let starting_tip = self.index_from_opt_id(best_block)?;
            println!("sadasdasdasdasd");

            if self.genesis_block_index() == starting_tip {
                self.connect_blocks(vec![block_index]);
            } else {
                let ancestor = self.get_common_ancestor(starting_tip, block_index)?;
                println!("sadasdasdasdasd");
                self.disconnect_blocks(ancestor);
                println!("sadasdasdasdasd");
                self.connect_blocks(self.make_new_chain());
                println!("sadasdasdasdasd");
            }
        }
        self.set_best_block_id(&block_index.get_id())?;

        // Chain trust most be higher
        self.current_block_height.increment();
        println!("LEAVE activate_best_chain");
        Ok(None)
    }

    #[allow(dead_code)]
    fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let blk_index = self.check_block_index(&BlockIndex::new(block))?;

        <S as BlockchainStorage>::add_block(&mut self.blockchain_storage, block)
            .map_err(|err| self.process_storage_failure(err))?;

        Ok(blk_index)
    }

    fn check_block_index(&mut self, blk_index: &BlockIndex) -> Result<BlockIndex, BlockError> {
        // BlockIndex is already known
        if self.exist_block(blk_index.get_id())? {
            println!("exist_block");
            return Err(BlockError::Unknown);
        }
        // Get prev block index
        if !blk_index.is_genesis(&self.chain_config) {
            let _prev_blk_index = self
                .get_ancestor(blk_index.get_prev_block_id())
                .map_err(|_| BlockError::Orphan)?;

            // TODO: Recheck this part
            // match prev_blk_index.status {
            //     BlockStatus::Valid => {
            //         for failed_block in ref mut self.failed_blocks {
            //             if &self.get_ancestor(prev_blk_index.get_id())? == failed_block {
            //                 let mut invalid_walk = prev_blk_index.clone();
            //                 while &invalid_walk != failed_block {
            //                     invalid_walk.status = BlockStatus::NoLongerOnMainChain;
            //                 }
            //             }
            //         }
            //     }
            //     _ => return Err(BlockError::PrevBlockInvalid),
            // }
        }

        // TODO: Will be expanded
        Ok(BlockIndex {
            status: BlockStatus::Valid,
            ..*blk_index
        })
    }

    #[allow(dead_code)]
    fn check_block_header(&mut self, block: &Block) -> Result<(), BlockError> {
        let previous_block = self.get_block(block.get_prev_block_id())?;

        // MerkleTree root
        let merkle_tree_root = block.get_merkle_root();
        match calculate_tx_merkle_root(block.get_transactions()) {
            Ok(merkle_tree) => {
                if merkle_tree_root != merkle_tree {
                    return Err(BlockError::Unknown);
                }
            }
            Err(_merkle_error) => {
                // TODO: Should we return additional error information?
                return Err(BlockError::Unknown);
            }
        }

        // Witness merkle root
        let witness_merkle_root = block.get_witness_merkle_root();
        match calculate_witness_merkle_root(block.get_transactions()) {
            Ok(witness_merkle) => {
                if witness_merkle_root != witness_merkle {
                    return Err(BlockError::Unknown);
                }
            }
            Err(_merkle_error) => {
                // TODO: Should we return additional error information?
                return Err(BlockError::Unknown);
            }
        }
        // Time
        let block_time = block.get_block_time();
        if let Some(previous_block) = previous_block {
            if previous_block.get_block_time() > block_time {
                return Err(BlockError::Unknown);
            }
        }
        if i64::from(block_time) > time::get() {
            return Err(BlockError::Unknown);
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn check_pos(&self, _block: &Block) -> Result<(), BlockError> {
        // TODO: We have to decide how to check it
        Ok(())
    }

    #[allow(dead_code)]
    fn check_transactions(&self, _block: &Block) -> Result<(), BlockError> {
        //TODO: Must check for duplicate inputs (see CVE-2018-17144)
        //TODO: Size limits
        //TODO: Check signatures
        Ok(())
    }

    #[allow(dead_code)]
    fn check_block(&mut self, block: &Block) -> Result<(), BlockError> {
        self.check_block_header(block)?;
        self.check_pos(block)?;
        self.check_transactions(block)?;
        // Will have added some checks
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blockchain_storage::Store;
    use common::address::Address;
    use common::chain::block::Block;
    use common::chain::config::create_mainnet;
    use common::chain::{Destination, Transaction, TxInput, TxOutput};
    use common::primitives::{Amount, Id, H256};

    fn produce_block(config: &ChainConfig, id_prev_block: Id<Block>) -> Block {
        use rand::prelude::*;

        let mut rng = rand::thread_rng();
        let mut witness: Vec<u8> = (1..100).collect();
        witness.shuffle(&mut rng);
        let mut address: Vec<u8> = (1..22).collect();
        address.shuffle(&mut rng);

        let receiver = Address::new(config, address).expect("Failed to create address");
        let input = TxInput::new(Id::new(&H256::zero()), 0, witness);
        let output = TxOutput::new(Amount::new(100000000000000), Destination::Address(receiver));
        let tx = Transaction::new(0, vec![input], vec![output], 0)
            .expect("Failed to create coinbase transaction");

        Block::new(vec![tx], id_prev_block, time::get() as u32, Vec::new())
            .expect("Error creating block")
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_block_accept() {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), storage);

        // process the genesis block
        let result = dbg!(consensus.process_block(config.genesis_block().clone()));
        assert!(result.is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            Some(config.genesis_block().get_id())
        );

        // Process the second block
        let new_block = produce_block(&config, config.genesis_block().get_id());
        dbg!(new_block.get_id());
        let new_id = Some(new_block.get_id());
        assert!(dbg!(consensus.process_block(new_block)).is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            new_id
        );

        // Process the orphan block
        let new_block = produce_block(&config, Id::<Block>::new(&H256::zero()));
        dbg!(new_block.get_id());
        assert_eq!(consensus.process_block(new_block), Err(BlockError::Orphan));

        // Process the parallel block and choose the better one
        let new_block = produce_block(&config, config.genesis_block().get_id());
        let new_id = Some(new_block.get_id());
        assert!(consensus.process_block(new_block).is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            new_id
        );
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_connect_chains() {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), storage);

        // process the genesis block

        let result = dbg!(consensus.process_block(config.genesis_block().clone()));
        assert!(result.is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            Some(config.genesis_block().get_id())
        );

        // Process the second block
        let new_block = produce_block(&config, config.genesis_block().get_id());
        dbg!(new_block.get_id());
        let new_id = Some(new_block.get_id());
        assert!(dbg!(consensus.process_block(new_block)).is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            new_id
        );
    }
}
