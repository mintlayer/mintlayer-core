use blockchain_storage::BlockchainStorage;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::primitives::{time, BlockHeight, Id, Idable};
use std::collections::BTreeSet;
mod chain_state;
use chain_state::*;
mod orphan_blocks;
use crate::orphan_blocks::OrphanAddError;
use common::chain::block::block_index::BlockIndex;
use orphan_blocks::OrphanBlocksPool;

#[allow(dead_code)]
struct Consensus<'a, S: BlockchainStorage> {
    chain_config: ChainConfig,
    blockchain_storage: &'a mut S,
    orphan_blocks: OrphanBlocksPool,
    current_block_height: BlockHeight,
    // TODO: We have to add these fields in a proper way.
    // failed_blocks: HashSet<BlockIndex>,
}

impl<'a, S: BlockchainStorage> Consensus<'a, S> {
    #[allow(dead_code)]
    pub fn new(chain_config: ChainConfig, blockchain_storage: &'a mut S) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
            current_block_height: BlockHeight::new(0),
        }
    }

    #[allow(dead_code)]
    pub fn process_block(&mut self, block: Block) -> Result<Option<BlockIndex>, BlockError> {
        self.check_block(&block)?;
        let block_index = self.accept_block(&block);
        if block_index == Err(BlockError::Orphan) {
            self.new_orphan_block(block)?;
        }
        self.activate_best_chain(block_index?)
    }

    /// Mark new block as an orphan
    /// Ok(()) - Added
    /// Err(BlockError) - StorageFailure  
    fn new_orphan_block(&mut self, block: Block) -> Result<(), BlockError> {
        // If we have not the previous block we have to move it to OrphanBlocksPool, except if it genesis block
        if block.get_id() != self.chain_config.genesis_block().get_id()
            && self
                .blockchain_storage
                .get_block_index(&block.get_prev_block_id())
                .map_err(|e| BlockError::from(e))?
                .is_none()
        {
            self.orphan_blocks.add_block(block).map_err(|err| match err {
                OrphanAddError::BlockAlreadyInOrphanList(_) => BlockError::Orphan,
            })?;
        }
        Ok(())
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_ancestor(&self, block_id: &Id<Block>) -> Result<BlockIndex, BlockError> {
        let block_index = self
            .blockchain_storage
            .get_block_index(block_id)
            .map_err(|e| BlockError::from(e))?;
        match block_index {
            Some(block_index) => {
                let prev_block = block_index.get_prev_block_id().ok_or(BlockError::NotFound)?;
                Ok(self
                    .blockchain_storage
                    .get_block_index(&prev_block)?
                    .ok_or(BlockError::NotFound)?)
            }
            None => Err(BlockError::NotFound),
        }
    }

    // Disconnect active blocks which are no longer in the best chain.
    fn disconnect_blocks(
        &mut self,
        tip: &BlockIndex,
        common_ancestor: &BlockIndex,
    ) -> Result<(), BlockError> {
        if tip.hash_block == common_ancestor.hash_block {
            // Nothing to do here
            return Ok(());
        }
        // Initialize disconnected chain
        let mut current_ancestor = *tip;
        // current_ancestor.status = BlockStatus::NoLongerOnMainChain;
        self.blockchain_storage.set_block_index(tip)?;
        // Collect blocks that should be disconnected

        while current_ancestor.hash_block == common_ancestor.hash_block {
            current_ancestor = self.get_ancestor(&current_ancestor.get_id())?;
            // current_ancestor.status = BlockStatus::NoLongerOnMainChain;
            self.blockchain_storage.set_block_index(tip)?;
        }
        Ok(())
    }

    // Build list of new blocks to connect (in descending height order).
    fn make_new_chain(
        &mut self,
        block_index: &BlockIndex,
        common_ancestor: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, BlockError> {
        if block_index.hash_block == common_ancestor.hash_block {
            // Nothing to do here
            return Ok(vec![*block_index]);
        }
        // Initialize disconnected chain
        let mut result = Vec::new();
        let mut current_ancestor = *block_index;
        // current_ancestor.status = BlockStatus::Valid;
        result.push(current_ancestor);
        // Connect blocks
        while current_ancestor.hash_block == common_ancestor.hash_block {
            current_ancestor = self.get_ancestor(&current_ancestor.get_id())?;
            // current_ancestor.status = BlockStatus::Valid;
            result.push(current_ancestor);
        }
        Ok(result)
    }

    // Connect mew blocks
    fn connect_blocks(&mut self, _blocks: &[BlockIndex]) -> Result<(), BlockError> {
        // for block_index in blocks {
        //     self.update_block_index(&BlockIndex {
        //         status: BlockStatus::Valid,
        //         ..*block_index
        //     })?;
        // }
        Ok(())
    }

    fn genesis_block_index(&self) -> BlockIndex {
        BlockIndex::new(self.chain_config.genesis_block())
    }

    fn get_common_ancestor(
        &self,
        tip: &BlockIndex,
        new_block: &BlockIndex,
    ) -> Result<BlockIndex, BlockError> {
        // Initialize two BtreeSet, one for the main chain and another for the new chain
        let mut mainchain = BTreeSet::new();
        let mut mainchain_ancestor = tip.hash_block;
        mainchain.insert(mainchain_ancestor);

        let mut newchain = BTreeSet::new();
        let mut newchain_ancestor = new_block.hash_block;
        newchain.insert(newchain_ancestor);

        // In every loop, we are checking if there are intersection hashes, if not, then load the previous blocks in chains
        loop {
            let intersection: Vec<_> = mainchain.intersection(&newchain).cloned().collect();
            if !intersection.is_empty() {
                // The common ancestor found
                return Ok(self
                    .blockchain_storage
                    .get_block_index(&Id::new(intersection.get(0).ok_or(BlockError::NotFound)?))?
                    .ok_or(BlockError::NotFound)?);
            }
            // Load next blocks from chains
            mainchain_ancestor = self.get_ancestor(&Id::new(&mainchain_ancestor))?.hash_block;
            mainchain.insert(mainchain_ancestor);

            newchain_ancestor = self.get_ancestor(&Id::new(&newchain_ancestor))?.hash_block;
            newchain.insert(newchain_ancestor);
        }
    }

    #[allow(dead_code)]
    fn activate_best_chain(
        &mut self,
        mut block_index: BlockIndex,
    ) -> Result<Option<BlockIndex>, BlockError> {
        // TODO: We have to decide how we can generate `chain_trust`, at the moment it is wrong
        block_index.chain_trust = self.current_block_height.into();
        let best_block = self.blockchain_storage.get_best_block_id()?;
        if let Some(best_block) = best_block {
            let starting_tip = self
                .blockchain_storage
                .get_block_index(&best_block)?
                .ok_or(BlockError::NotFound)?;
            if self.genesis_block_index() == starting_tip {
                self.connect_blocks(&[block_index])?;
            } else {
                let common_ancestor = self.get_common_ancestor(&starting_tip, &block_index)?;
                self.disconnect_blocks(&starting_tip, &common_ancestor)?;
                let new_chain = &mut self.make_new_chain(&block_index, &common_ancestor)?;
                self.connect_blocks(new_chain)?;
            }
        }
        self.blockchain_storage
            .set_best_block_id(&block_index.get_id())
            .map_err(|e| BlockError::from(e))?;
        // Chain trust most be higher
        self.current_block_height.increment();
        Ok(None)
    }

    #[allow(dead_code)]
    fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        // TODO: Look at BTC, write block index,
        let block_index = BlockIndex::new(block);
        self.check_block_index(&block_index)?;
        self.blockchain_storage
            .set_block_index(&block_index)
            .map_err(|e| BlockError::from(e))?;
        self.blockchain_storage.add_block(block).map_err(|e| BlockError::from(e))?;
        Ok(block_index)
    }

    fn exist_block(&self, id: &Id<Block>) -> Result<bool, BlockError> {
        Ok(self.blockchain_storage.get_block_index(id)?.is_some())
    }

    fn check_block_index(&self, blk_index: &BlockIndex) -> Result<BlockIndex, BlockError> {
        // BlockIndex is already known
        if self.exist_block(&blk_index.get_id())? {
            println!("exist_block");
            return Err(BlockError::Unknown);
        }
        // Get prev block index
        if !blk_index.is_genesis(&self.chain_config) {
            let prev_block_id = blk_index.get_prev_block_id().ok_or(BlockError::Orphan)?;
            let _prev_blk_index = self
                .blockchain_storage
                .get_block_index(&prev_block_id)?
                .ok_or(BlockError::Orphan)?;
        }

        // TODO: Will be expanded
        // Ok(BlockIndex {
        //     status: BlockStatus::Valid,
        //     ..*blk_index
        // })
        Ok(*blk_index)
    }

    #[allow(dead_code)]
    fn check_block_detail(&self, block: &Block) -> Result<(), BlockError> {
        let previous_block = self
            .blockchain_storage
            .get_block_index(&block.get_prev_block_id())?
            .ok_or(BlockError::NotFound)?; // TODO: Change to BlockIndex, and add the header (not the full header) of the block to block index

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
        if previous_block.get_block_time() > block_time {
            return Err(BlockError::Unknown);
        }
        if i64::from(block_time) > time::get() {
            return Err(BlockError::Unknown);
        }
        self.check_transactions(block)?; // Move to check_block_detail
                                         // Will have added some checks
        Ok(())
    }

    #[allow(dead_code)]
    fn check_consensus(&self, block: &Block) -> Result<(), BlockError> {
        let _consensus_data = block.get_consensus_data();
        // TODO: PoW is not in master at the moment =(
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
    fn check_block(&self, block: &Block) -> Result<(), BlockError> {
        self.check_consensus(block)?;
        self.check_block_detail(block)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // TODO: Add proptest here
    use super::*;
    use blockchain_storage::Store;
    use common::address::Address;
    use common::chain::block::Block;
    use common::chain::config::create_mainnet;
    use common::chain::{Destination, Transaction, TxInput, TxOutput};
    use common::primitives::consensus_data::ConsensusData;
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

        Block::new(
            vec![tx],
            id_prev_block,
            time::get() as u32,
            ConsensusData::None,
        )
        .expect("Error creating block")
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_parallel_chains() {
        let config = create_mainnet();
        let mut storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), &mut storage);

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
    fn test_orphans_chains() -> Result<(), BlockError> {
        let config = create_mainnet();
        let mut storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), &mut storage);

        // process the genesis block
        let result = dbg!(consensus.process_block(config.genesis_block().clone()));
        assert!(result.is_ok());
        assert_eq!(
            consensus.get_best_block_id()?,
            Some(config.genesis_block().get_id())
        );

        // Process the second block
        let new_block = produce_block(&config, config.genesis_block().get_id());
        dbg!(new_block.get_id());
        let new_id = Some(new_block.get_id());
        assert!(dbg!(consensus.process_block(new_block)).is_ok());
        assert_eq!(consensus.get_best_block_id()?, new_id);

        // Process the orphan block
        for _ in 0..255 {
            let new_block = produce_block(&config, Id::<Block>::new(&H256::zero()));
            dbg!(new_block.get_id());
            assert_eq!(consensus.process_block(new_block), Err(BlockError::Orphan));
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_connect_straight_chains() -> Result<(), BlockError> {
        let config = create_mainnet();
        let mut storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), &mut storage);

        // process the genesis block
        println!(
            "\nPROCESSING BLOCK 0: {:?}",
            &config.genesis_block().get_id().get()
        );
        let result = consensus.process_block(config.genesis_block().clone());
        assert!(result.is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            Some(config.genesis_block().get_id())
        );

        // Process the second block
        let new_block = produce_block(&config, config.genesis_block().get_id());
        println!("\nPROCESSING BLOCK 1: {:?}", &new_block.get_id().get());
        let new_id = Some(new_block.get_id());
        assert!(consensus.process_block(new_block).is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            new_id
        );

        for i in 2..255 {
            // Process another block
            let previous_block_id = new_id.clone().unwrap();
            let new_block = produce_block(&config, previous_block_id.clone());
            println!("\nPROCESSING BLOCK {}: {:?}", i, &new_block.get_id().get());
            let new_id = Some(new_block.get_id());
            assert!(consensus.process_block(new_block).is_ok());
            assert_eq!(consensus.get_best_block_id()?, new_id);
            let block_id = consensus.get_best_block_id()?.unwrap();
            assert_eq!(
                consensus.get_block(block_id)?.unwrap().get_prev_block_id(),
                previous_block_id
            )
        }
        Ok(())
    }

    // TODO: Not ready tests for this PR related to:
    //  Fail block processing
    //  More cases for reorg
    //  Tests with chain trust
}
