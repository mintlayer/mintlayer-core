use blockchain_storage::BlockchainStorage;
use blockchain_storage::StoreTxRw;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::primitives::{time, BlockHeight, Id, Idable};
mod chain_state;
use chain_state::*;
mod orphan_blocks;
use crate::orphan_blocks::{OrphanAddError, OrphanBlocksPool};
use common::chain::block::block_index::BlockIndex;
use common::chain::Transaction;

#[allow(dead_code)]
// TODO: We will generalize it when Lukas will be ready for that. At the moment, he recommended use
//  types directly.
// struct Consensus<'a, S: Transactional<'a> + BlockchainStorage> {
struct Consensus<'a> {
    chain_config: ChainConfig,
    blockchain_storage: &'a mut blockchain_storage::Store, //&'a mut S,
    orphan_blocks: OrphanBlocksPool,
}

impl<'a> Consensus<'a> {
    #[allow(dead_code)]
    pub fn new(
        chain_config: ChainConfig,
        blockchain_storage: &'a mut blockchain_storage::Store,
    ) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
        }
    }

    #[allow(dead_code)]
    pub fn process_block(&mut self, block: Block) -> Result<Option<BlockIndex>, BlockError> {
        self.check_block(&block)?;
        let mut tx = self.blockchain_storage.start_transaction_rw();
        let block_index = self.accept_block(&mut tx, &block);
        if block_index == Err(BlockError::Orphan) {
            self.new_orphan_block(block)?;
        }
        let block_index = block_index?;
        let result = self.activate_best_chain(&tx, block_index);
        tx.commit().expect("Committing of the transaction to DB failed");
        result
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

    fn apply_tx_in_undo(&mut self, _tx: &Transaction) {
        //TODO: not implemented yet
    }

    fn disconnect_block(&mut self, block_index: &BlockIndex) -> Result<(), BlockError> {
        let block = self
            .blockchain_storage
            .get_block(block_index.get_block_id())?
            .ok_or(BlockError::Unknown)?;
        for tx in block.get_transactions().iter().rev() {
            // TODO: Check that all outputs are available and match the outputs in the block itself
            //  exactly.
            for _output in tx.get_outputs() {
                // if output.is_spendable() {
                // TODO: We have to check that coin was spent, and that match outputs, height, coinbase
                // }
            }
            // Restore inputs
            if !tx.is_coinbase() {
                self.apply_tx_in_undo(tx);
                //TODO: Check undo status and
            }
        }
        // Not sure what we should return here, might be a new status instead of BlockError?
        self.blockchain_storage
            .set_best_block_id(&block_index.get_prev_block_id().ok_or(BlockError::Unknown)?)?;
        Ok(())
    }

    // Disconnect active blocks which are no longer in the best chain.
    fn disconnect_blocks(
        &mut self,
        tip: &BlockIndex,
        common_ancestor: &BlockIndex,
    ) -> Result<(), BlockError> {
        if tip.get_block_id() == common_ancestor.get_block_id() {
            // Nothing to do here
            return Ok(());
        }
        // Initialize disconnected chain
        let mut current_ancestor = *tip;
        current_ancestor.next_block_hash = None;
        self.blockchain_storage.set_block_index(tip)?;
        // Collect blocks that should be disconnected

        while current_ancestor.get_block_id() == common_ancestor.get_block_id() {
            current_ancestor = self.get_ancestor(&current_ancestor.get_block_id())?;
            current_ancestor.next_block_hash = None;
            self.disconnect_block(&current_ancestor)?;
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
        if block_index.get_block_id() == common_ancestor.get_block_id() {
            // Nothing to do here
            return Ok(vec![*block_index]);
        }
        // Initialize disconnected chain
        let mut result = Vec::new();
        let mut current_ancestor = *block_index;
        // current_ancestor.status = BlockStatus::Valid;
        result.push(current_ancestor);
        // Connect blocks
        while current_ancestor.get_block_id() == common_ancestor.get_block_id() {
            current_ancestor = self.get_ancestor(&current_ancestor.get_block_id())?;
            // current_ancestor.status = BlockStatus::Valid;
            result.push(current_ancestor);
        }
        Ok(result)
    }

    // Connect mew blocks
    fn connect_blocks(&mut self, blocks: &[BlockIndex]) -> Result<(), BlockError> {
        for block_index in blocks {
            // let chain_index = TxMainChainIndex::new();
        }
        Ok(())
    }

    // TODO: rename this to make_genesis_block_index
    fn genesis_block_index(&self) -> BlockIndex {
        BlockIndex::new(self.chain_config.genesis_block())
    }

    fn get_common_ancestor(
        &self,
        storage_tx: &StoreTxRw,
        tip: &BlockIndex,
        new_block: &BlockIndex,
    ) -> Result<BlockIndex, BlockError> {
        let mut ancestor = new_block;
        while !self.is_block_in_main_chain(ancestor, storage_tx) {
            ancestor = &self.get_ancestor(&ancestor.get_block_id())?;
        }
        Ok(*ancestor)
    }

    #[allow(dead_code)]
    fn activate_best_chain(
        &mut self,
        storage_tx: &StoreTxRw,
        block_index: BlockIndex,
    ) -> Result<Option<BlockIndex>, BlockError> {
        /*
        // TODO: When we activate the genesis block, we should:
        //  1. Set it's as a best block
        //  2. Connect it to the main chain

        // If we know that the genesis block has already processed then best_block must be already set
        //   If we don't in this case the best_block then DB has corrupted

        if block_index.get_block_id() == self.config.get_genesis_block().get_id() {
            self.blockchain_storage
                .get_best_block_id()
                .expect_err("Best block set even though genesis being submitted for connection");
            self.connect_blocks(new_chain)?;
            return;
        }

        // connect block to the chain
        let common_ancestor = self.get_common_ancestor(&starting_tip, &block_index)?;
        self.disconnect_blocks(&starting_tip, &common_ancestor)?;
        let new_chain = &mut self.make_new_chain(&block_index, &common_ancestor)?;
        self.connect_blocks(new_chain)?;

        self.blockchain_storage
            .set_best_block_id(&block_index.get_id())
            .map_err(|e| BlockError::from(e))?;
        // Chain trust most be higher
        self.current_block_height.increment();

         */
        Ok(None)
    }

    fn get_block_proof(&self, _block_index: &BlockIndex) -> u64 {
        //TODO: We have to make correct one
        10
    }

    fn add_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        // TODO: Check for duplicate block index
        let block_index = BlockIndex::new(block); // Move all variables into new as params
        let prev_block_index = self
            .blockchain_storage
            .get_block_index(&block_index.get_prev_block_id().ok_or(BlockError::Unknown)?)
            .map_err(|e| BlockError::from(e))?;
        // Set the block height
        block_index.height = if let Some(prev_block_index) = prev_block_index {
            // change to match
            prev_block_index.height + 1
        } else {
            BlockHeight::zero()
        };
        // Set Time Max
        block_index.time_max = if let Some(prev_block_index) = prev_block_index {
            std::cmp::max(prev_block_index.time_max, block_index.get_block_time())
        } else {
            block_index.get_block_time()
        };
        // Set Chain Trust
        block_index.chain_trust = if let Some(prev_block_index) = prev_block_index {
            prev_block_index.chain_trust
        } else {
            0
        } + self.get_block_proof(&block_index);

        self.blockchain_storage
            .set_block_index(&block_index)
            .map_err(|e| BlockError::from(e))?;

        Ok(block_index)
    }

    #[allow(dead_code)]
    fn accept_block(
        &self,
        storage_tx: &mut StoreTxRw,
        block: &Block,
    ) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_block_index(block)?;
        storage_tx.add_block(block).map_err(|e| BlockError::from(e))?;
        self.check_block_index(&block_index)?;
        Ok(block_index)
    }

    fn exist_block(&self, id: &Id<Block>) -> Result<bool, BlockError> {
        Ok(self.blockchain_storage.get_block_index(id)?.is_some())
    }

    fn check_block_index(&self, blk_index: &BlockIndex) -> Result<BlockIndex, BlockError> {
        // BlockIndex is already known
        if self.exist_block(&blk_index.get_block_id())? {
            println!("exist_block");
            return Err(BlockError::Unknown);
        }

        // TODO: Iterate over the entire block tree, using depth-first search. \
        //  Along the way, remember whether there are blocks on the path from genesis \
        //  block being explored which are the first to have certain properties.

        // TODO: Add genesis block checks.
        // TODO: Add consistency checks.
        // TODO: Check that for every block except the genesis block, the chainwork must be larger than the parent's.
        // TODO: The prev_block_id must point back for all blocks.
        // TODO: TREE valid implies all parents are TREE valid. CHAIN valid implies all parents are CHAIN valid. \
        //  SCRIPTS valid implies all parents are SCRIPTS valid
        // TODO: Process the unlinked blocks.

        // Get prev block index
        if !blk_index.is_genesis(&self.chain_config) {
            let prev_block_id = blk_index.get_prev_block_id().ok_or(BlockError::Orphan)?;
            let _prev_blk_index = self
                .blockchain_storage
                .get_block_index(&prev_block_id)?
                .ok_or(BlockError::Orphan)?;
        }

        // TODO: Will be expanded
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

    fn is_block_in_main_chain(&self, block_index: &BlockIndex, storage_tx: &StoreTxRw) -> bool {
        block_index.next_block_hash.is_some()
            || match storage_tx.get_best_block_id().ok().flatten() {
                Some(block_id) => block_index.get_block_id() == block_id,
                None => false,
            }
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
