use blockchain_storage::{BlockchainStorage, Error};
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::primitives::{time, BlockHeight, Id, Idable, H256};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;
mod chain_state;
use chain_state::*;
mod orphan_blocks;
use crate::orphan_blocks::OrphanAddError;
use orphan_blocks::OrphanBlocksPool;

#[allow(dead_code)]
struct Consensus<S: BlockchainStorage> {
    chain_config: ChainConfig,
    blockchain_storage: Rc<RefCell<S>>,
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
            blockchain_storage: Rc::new(RefCell::new(blockchain_storage)),
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
        let mut_block = Rc::get_mut(&mut rc_block).expect(RC_FAIL);
        let block_index = self.accept_block(mut_block).map_err(|err| {
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

    fn process_storage<T, F>(&self, mut func: F) -> Result<T, BlockError>
    where
        F: FnMut() -> Result<T, Error>,
    {
        use blockchain_storage::Recoverable;

        let result = func();
        match result {
            Ok(result) => Ok(result),
            // TODO: Most likely, this part should be on storage side. Consensus have to process \
            //  EntityNotFound, StorageFailure, and probably some other errors. At the moment, \
            //  this part is not done!
            Err(Error::Storage(Recoverable::TransactionFailed))
            | Err(Error::Storage(Recoverable::TemporarilyUnavailable))
            | Err(Error::Storage(Recoverable::Unknown)) => {
                let second_attempt = func();
                if second_attempt.is_err() {
                    return Err(BlockError::StorageFailure(Error::Storage(
                        Recoverable::TransactionFailed,
                    )));
                }
                Ok(second_attempt.map_err(|_| BlockError::Unknown)?)
            }
        }
    }

    /// Allow to read from storeage the previous block and return itself BlockIndex
    fn get_ancestor(&mut self, block_id: &Id<Block>) -> Result<BlockIndex, BlockError> {
        let block = self.get_block(block_id.clone())?;
        match block {
            Some(block) => {
                let prev_block = block.get_prev_block_id();
                let result = self.get_block(prev_block);
                Ok(BlockIndex::new(&result?.ok_or(BlockError::NotFound)?))
            }
            None => Err(BlockError::NotFound),
        }
    }

    fn update_block_index(&self, _block_index: &BlockIndex) -> Result<(), BlockError> {
        // TODO: We should update storage layer
        Ok(())
    }

    fn exist_block(&mut self, block_id: Id<Block>) -> Result<bool, BlockError> {
        Ok(self.get_block(block_id)?.is_some())
    }

    fn get_block(&mut self, id: Id<Block>) -> Result<Option<Block>, BlockError> {
        let storage = self.blockchain_storage.borrow_mut();
        self.process_storage(|| storage.get_block(id.clone()))
    }

    fn set_best_block_id(&mut self, id: &Id<Block>) -> Result<(), BlockError> {
        let mut storage = self.blockchain_storage.borrow_mut();
        self.process_storage(|| storage.set_best_block_id(&id.clone()))
        // TODO: Also we should update index \
        //  self.process_storage(|| storage.set_best_block_index(&id.clone()))
    }

    fn get_best_block_id(&mut self) -> Result<Option<Id<Block>>, BlockError> {
        let storage = self.blockchain_storage.borrow_mut();
        self.process_storage(|| storage.get_best_block_id())
    }

    fn index_from_opt_id(&mut self, id_block: Id<Block>) -> Result<BlockIndex, BlockError> {
        let storage = self.blockchain_storage.borrow_mut();
        match self.process_storage(|| storage.get_block(id_block.clone()))? {
            Some(blk) => Ok(BlockIndex::new(&blk)),
            None => Err(BlockError::Unknown),
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
        let mut current_ancestor = tip.clone();
        current_ancestor.status = BlockStatus::NoLongerOnMainChain;
        self.update_block_index(&tip)?;
        // Collect blocks that should be disconnected

        while current_ancestor.hash_block == common_ancestor.hash_block {
            current_ancestor = self.get_ancestor(&current_ancestor.get_id())?;
            current_ancestor.status = BlockStatus::NoLongerOnMainChain;
            self.update_block_index(&tip)?;
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
            return Ok(vec![block_index.clone()]);
        }
        // Initialize disconnected chain
        let mut result = Vec::new();
        let mut current_ancestor = block_index.clone();
        current_ancestor.status = BlockStatus::Valid;
        result.push(current_ancestor);
        // Connect blocks
        while current_ancestor.hash_block == common_ancestor.hash_block {
            current_ancestor = self.get_ancestor(&current_ancestor.get_id())?;
            current_ancestor.status = BlockStatus::Valid;
            result.push(current_ancestor);
        }
        Ok(result)
    }

    // Connect mew blocks
    fn connect_blocks(&mut self, blocks: &Vec<BlockIndex>) -> Result<(), BlockError> {
        for block_index in blocks {
            self.update_block_index(&BlockIndex {
                status: BlockStatus::Valid,
                ..*block_index
            })?;
        }
        Ok(())
    }

    fn genesis_block_index(&self) -> BlockIndex {
        BlockIndex::new(self.chain_config.genesis_block())
    }

    fn get_common_ancestor(
        &mut self,
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
                return Ok(BlockIndex::new(
                    &self
                        .get_block(Id::new(intersection.get(0).ok_or(BlockError::NotFound)?))?
                        .ok_or(BlockError::NotFound)?,
                ));
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
    ) -> Result<Option<Tip>, BlockError> {
        // TODO: We have to decide how we can generate `chain_trust`, at the moment it is wrong
        block_index.chain_trust = self.current_block_height.into();
        let best_block = self.get_best_block_id()?;
        println!("BEST BLOCK: {:?}", &best_block);
        if let Some(best_block) = best_block {
            let starting_tip = self.index_from_opt_id(best_block)?;
            if self.genesis_block_index() == starting_tip {
                println!("CONNECT THE FIRST BLOCK");
                self.connect_blocks(&mut vec![block_index])?;
            } else {
                let common_ancestor = self.get_common_ancestor(&starting_tip, &block_index)?;
                println!("COMMON ANCESTOR: {:?}", &common_ancestor.hash_block);
                self.disconnect_blocks(&starting_tip, &common_ancestor)?;
                let new_chain = &mut self.make_new_chain(&block_index, &common_ancestor)?;
                self.connect_blocks(new_chain)?;
                println!("SET UP THE NEW CHAIN HAS BEEN FINISHED");
            }
        }
        self.set_best_block_id(&block_index.get_id())?;

        // Chain trust most be higher
        self.current_block_height.increment();
        Ok(None)
    }

    #[allow(dead_code)]
    fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let blk_index = self.check_block_index(&BlockIndex::new(block))?;
        let mut storage = self.blockchain_storage.borrow_mut();
        self.process_storage(|| storage.add_block(block))?;
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
            let _prev_blk_index =
                self.get_block(blk_index.get_prev_block_id())?.ok_or(BlockError::Orphan)?;
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
    fn check_block(&mut self, block: &Block) -> Result<(), BlockError> {
        self.check_block_header(block)?;
        self.check_consensus(block)?;
        self.check_transactions(block)?;
        // Will have added some checks
        Ok(())
    }
}

// To make tests more transparent
fn internal_get_common_ancestor<FUNC, HASH256>(
    tip: H256,
    new_block: H256,
    get_ancestor: FUNC,
) -> Result<H256, BlockError>
where
    FUNC: Fn(&Id<HASH256>) -> Result<BlockIndex, BlockError>,
{
    // Initialize two BtreeSet, one for the main chain and another for the new chain
    let mut mainchain = BTreeSet::new();
    let mut mainchain_ancestor = tip;
    mainchain.insert(mainchain_ancestor);

    let mut newchain = BTreeSet::new();
    let mut newchain_ancestor = new_block;
    newchain.insert(newchain_ancestor);

    // In every loop, we are checking if there are intersection hashes, if not, then load the previous blocks in chains
    loop {
        let intersection: Vec<_> = mainchain.intersection(&newchain).cloned().collect();
        if !intersection.is_empty() {
            // The common ancestor found
            return Ok(*intersection.get(0).ok_or(BlockError::NotFound)?);
        }
        // Load next blocks from chains
        mainchain_ancestor = get_ancestor(&Id::new(&mainchain_ancestor))?.hash_block;
        mainchain.insert(mainchain_ancestor);

        newchain_ancestor = get_ancestor(&Id::new(&newchain_ancestor))?.hash_block;
        newchain.insert(newchain_ancestor);
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
    use common::primitives::consensus_data::ConsensusData;
    use common::primitives::{Amount, Id, H256};

    #[test]
    fn test_storage() {
        let config = create_mainnet();
        let storage = Store::new_empty().unwrap();
        let mut consensus = Consensus::new(config.clone(), storage);
        let result = consensus.process_block(config.genesis_block().clone());
        println!("hash: {:?}", config.genesis_block().get_id());
        assert!(result.is_ok());
        let result = consensus.get_block(config.genesis_block().get_id());
        assert!(result.unwrap().is_some());
    }

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

        // Process another block
        let new_block = produce_block(&config, new_id.unwrap());
        println!("\nPROCESSING BLOCK 2: {:?}", &new_block.get_id().get());
        let new_id = Some(new_block.get_id());
        assert!(consensus.process_block(new_block).is_ok());
        assert_eq!(
            consensus.get_best_block_id().expect("Best block didn't found"),
            new_id
        );
    }
}
