use crate::orphan_blocks::{OrphanAddError, OrphanBlocksPool};
use blockchain_storage::BlockchainStorage;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::chain::{
    OutPoint, OutPointSourceId, SpendablePosition, Spender, Transaction, TxMainChainIndex,
};
use common::primitives::{time, Amount, BlockHeight, Id, Idable};
mod chain_state;
use chain_state::*;
mod orphan_blocks;
use std::collections::BTreeMap;

#[allow(dead_code)]
// TODO: We will generalize it when Lukas will be ready for that. At the moment, he recommended use
//  types directly.
// struct Consensus<'a, S: Transactional<'a> + BlockchainStorage> {
struct Consensus {
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store, //&'a mut S,
    orphan_blocks: OrphanBlocksPool,
}

type CachedInputs = BTreeMap<Id<Transaction>, TxMainChainIndex>;
type PeerId = u32;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum BlockSource {
    Peer(PeerId),
    Local,
}

impl Consensus {
    fn make_tx(&mut self) -> ConsensusRef {
        let db_tx = self.blockchain_storage.start_transaction_rw();
        ConsensusRef {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &mut self.orphan_blocks,
        }
    }

    #[allow(dead_code)]
    pub fn new(chain_config: ChainConfig, blockchain_storage: blockchain_storage::Store) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
        }
    }

    #[allow(dead_code)]
    pub fn process_block(
        &mut self,
        block: Block,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut consensus_ref = self.make_tx();
        consensus_ref.check_block(&block)?; // TODO: this seems to require block index, which doesn't seem to be the case in bitcoin, as otherwise orphans can't be checked
        let block_index = consensus_ref.accept_block(&block);
        if BlockSource::Local == block_source && block_index == Err(BlockError::Orphan) {
            consensus_ref.new_orphan_block(block)?;
        }
        let result = consensus_ref.activate_best_chain(block_index?)?;
        consensus_ref.commit().expect("Committing transactions to DB failed");
        Ok(result)
    }
}

struct ConsensusRef<'a> {
    chain_config: &'a ChainConfig,
    // TODO: make this generic over Rw and Ro
    db_tx: <blockchain_storage::Store as Transactional<'a>>::TransactionRw,
    orphan_blocks: &'a mut OrphanBlocksPool,
}

impl<'a> ConsensusRef<'a> {
    fn commit(self) -> blockchain_storage::Result<()> {
        self.db_tx.commit()
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_ancestor(&self, block_id: &Id<Block>) -> Result<BlockIndex, BlockError> {
        let block_index = self.db_tx.get_block_index(block_id).map_err(BlockError::from)?;
        match block_index {
            Some(block_index) => {
                let prev_block =
                    block_index.get_prev_block_id().as_ref().ok_or(BlockError::NotFound)?;
                Ok(self.db_tx.get_block_index(prev_block)?.ok_or(BlockError::NotFound)?)
            }
            None => Err(BlockError::NotFound),
        }
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(block_index.get_block_id().clone())?)
    }

    fn reorganize(
        &mut self,
        cached_inputs: &mut CachedInputs,
        best_block_id: Option<Id<Block>>,
        top_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        // Disconnect the current chain
        // TODO: Reasonably minimize amount of calls to storage, use function params
        if let Some(best_block_id) = best_block_id {
            let mut ancestor = self
                .db_tx
                .get_block_index(&best_block_id)?
                .expect("Can't get block index. Inconsistent DB");
            while !self.is_block_in_main_chain(&ancestor) {
                self.disconnect_tip(cached_inputs, &mut ancestor)?;
                ancestor = self.get_ancestor(ancestor.get_block_id())?;
            }
        }

        // Connect the new chain
        let mut ancestor = top_block_index.clone();
        while !self.is_block_in_main_chain(&ancestor) {
            self.connect_tip(cached_inputs, &ancestor)?;
            ancestor = self.get_ancestor(ancestor.get_block_id())?;
        }
        Ok(())
    }

    fn store_cached_inputs(&mut self, cached_inputs: &mut CachedInputs) -> Result<(), BlockError> {
        for (tx_id, tx_index) in cached_inputs.iter() {
            self.db_tx.set_mainchain_tx_index(tx_id, tx_index)?;
        }
        Ok(())
    }

    fn connect_transactions(
        &mut self,
        cached_inputs: &mut CachedInputs,
        transactions: &Vec<Transaction>,
    ) -> Result<(), BlockError> {
        for tx in transactions.iter() {
            let inputs = tx.get_inputs();

            for input in inputs {
                let input_index = input.get_outpoint().get_output_index();

                let mut tx_index = match cached_inputs.get(&tx.get_id()) {
                    Some(tx_index) => tx_index.clone(),
                    None => {
                        Self::find_mainchain_index_by_outpoint(&self.db_tx, input.get_outpoint())?
                    }
                };

                if input_index >= tx_index.get_output_count() {
                    return Err(BlockError::Unknown);
                }

                // Add checks
                tx_index
                    .spend(input_index, Spender::from(tx.get_id()))
                    .map_err(BlockError::from)?;

                // TODO: Check that all outputs are available and match the outputs in the block itself
                //  exactly.

                cached_inputs.insert(tx.get_id(), tx_index.clone());
            }
        }
        self.store_cached_inputs(cached_inputs)?;
        Ok(())
    }

    fn disconnect_transactions(
        &mut self,
        cached_inputs: &mut CachedInputs,
        transactions: &Vec<Transaction>,
    ) -> Result<(), BlockError> {
        for tx in transactions.iter().rev() {
            let inputs = tx.get_inputs();
            for input in inputs {
                let input_index = input.get_outpoint().get_output_index();

                let mut tx_index = match cached_inputs.get(&tx.get_id()) {
                    Some(tx_index) => tx_index.clone(),
                    None => self
                        .db_tx
                        .get_mainchain_tx_index(&tx.get_id())?
                        .ok_or(BlockError::Unknown)?,
                };

                if input_index >= tx_index.get_output_count() {
                    return Err(BlockError::Unknown);
                }

                // Add checks
                tx_index.unspend(input_index).map_err(BlockError::from)?;

                // TODO: Check that all outputs are available and match the outputs in the block itself
                //  exactly.

                cached_inputs.insert(tx.get_id(), tx_index.clone());
            }
            // Restore inputs
            self.db_tx.del_mainchain_tx_index(&tx.get_id())?;
        }
        Ok(())
    }

    fn find_mainchain_index_by_outpoint(
        tx_db: &<blockchain_storage::Store as Transactional<'a>>::TransactionRw,
        outpoint: &OutPoint,
    ) -> Result<TxMainChainIndex, BlockError> {
        let tx_id = match outpoint.get_tx_id() {
            OutPointSourceId::Transaction(tx_id) => tx_id,
            OutPointSourceId::BlockReward(_) => {
                unimplemented!()
            }
        };
        Ok(tx_db.get_mainchain_tx_index(&tx_id)?.ok_or(BlockError::Unknown)?)
    }

    fn find_by_outpoint(
        tx_db: &<blockchain_storage::Store as Transactional<'a>>::TransactionRw,
        outpoint: &OutPoint,
    ) -> Result<Transaction, BlockError> {
        let tx_id = match outpoint.get_tx_id() {
            OutPointSourceId::Transaction(tx_id) => tx_id,
            OutPointSourceId::BlockReward(_) => {
                unimplemented!()
            }
        };
        let tx_index = tx_db.get_mainchain_tx_index(&tx_id)?.ok_or(BlockError::Unknown)?;
        match tx_index.get_tx_position() {
            SpendablePosition::Transaction(position) => {
                tx_db.get_mainchain_tx_by_position(position)?.ok_or(BlockError::Unknown)
            }
            SpendablePosition::BlockReward(_) => unimplemented!(),
        }
    }

    fn get_input_value(
        tx_db: &<blockchain_storage::Store as Transactional<'a>>::TransactionRw,
        input: &common::chain::TxInput,
    ) -> Result<Amount, BlockError> {
        // Read the transaction from DB
        let tx = Self::find_by_outpoint(tx_db, input.get_outpoint())?;
        let output_index = input.get_outpoint().get_output_index();
        Ok(tx.get_outputs()[output_index as usize].get_value())
    }

    fn check_block_fee(&self, transactions: &Vec<Transaction>) -> Result<(), BlockError> {
        let input_mlt = transactions
            .iter()
            .map(|x| {
                x.get_inputs()
                    .iter()
                    .map(|input| {
                        Self::get_input_value(&self.db_tx, input).expect("Couldn't get input")
                    })
                    .sum::<Amount>()
            })
            .sum();
        let output_mlt: Amount = transactions
            .iter()
            .map(|x| x.get_outputs().iter().map(|output| output.get_value()).sum::<Amount>())
            .sum();

        // Check that fee is not negative
        if output_mlt > input_mlt {
            return Err(BlockError::Unknown);
        }
        Ok(())
    }

    fn check_script(&self, _transactions: &Vec<Transaction>) -> Result<(), BlockError> {
        //TODO: Check script
        Ok(())
    }

    fn check_tx_inputs(&self, _transactions: &Vec<Transaction>) -> Result<(), BlockError> {
        Ok(())
    }

    fn check_tx_outputs(&self, _transactions: &Vec<Transaction>) -> Result<(), BlockError> {
        // TODO: Check tx outputs to prevent the overwriting of the transaction
        Ok(())
    }

    // Connect new block
    fn connect_tip(
        &mut self,
        cached_inputs: &mut CachedInputs,
        block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        assert_eq!(
            &self.db_tx.get_best_block_id().expect("Only fails at genesis"),
            block_index.get_prev_block_id()
        );

        match &block_index.get_prev_block_id() {
            Some(prev_block_id) => {
                let block = self.get_block_from_index(block_index)?.expect("Inconsistent DB");
                let transactions = block.get_transactions();

                self.check_block_fee(transactions)?;
                self.check_script(transactions)?;
                self.check_tx_inputs(transactions)?;
                self.check_tx_outputs(transactions)?;

                self.connect_transactions(cached_inputs, transactions)?;

                // CONNECT: Set-up the next_block_id
                let mut prev_block = self
                    .db_tx
                    .get_block_index(prev_block_id)?
                    .expect("Can't get block index. Inconsistent DB");
                prev_block.next_block_id = Some(block.get_id());
                self.db_tx
                    .set_block_index(&prev_block)
                    .expect("Can't set block index. Inconsistent DB");
                self.db_tx.set_block_index(block_index)?;
                Ok(())
            }
            None => panic!("Failed to read block"),
        }
    }

    fn disconnect_tip(
        &mut self,
        cached_inputs: &mut CachedInputs,
        block_index: &mut BlockIndex,
    ) -> Result<(), BlockError> {
        assert_eq!(
            &self.db_tx.get_best_block_id().expect("Only fails at genesis"),
            block_index.get_prev_block_id()
        );

        let block = self.get_block_from_index(block_index)?.expect("Inconsistent DB");
        self.disconnect_transactions(cached_inputs, block.get_transactions())?;
        self.db_tx.set_best_block_id(
            block_index.get_prev_block_id().as_ref().ok_or(BlockError::Unknown)?,
        )?;
        // Update connection
        block_index.next_block_id = None;
        self.db_tx.set_block_index(block_index)?;
        Ok(())
    }

    fn get_best_block_index(&self, best_block_id: &Id<Block>) -> Result<BlockIndex, BlockError> {
        Ok(self
            .db_tx
            .get_block_index(best_block_id)
            .map_err(BlockError::from)?
            .expect("Inconsistent DB"))
    }

    fn activate_best_chain(
        &mut self,
        new_block_index: BlockIndex,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut cached_inputs = CachedInputs::new();

        let best_block_id = self.db_tx.get_best_block_id()?;
        if *new_block_index.get_block_id() == self.chain_config.genesis_block().get_id() {
            if best_block_id.is_some() {
                panic!("Inconsistent DB: There is exist the best block, but at the same time was tried processing genesis block")
            }
            self.connect_tip(&mut cached_inputs, &new_block_index)?;
            self.db_tx
                .set_best_block_id(new_block_index.get_block_id())
                .map_err(BlockError::from)?;
            return Ok(Some(new_block_index));
        }

        if let Some(best_block_id) = best_block_id {
            // Chain trust is higher than the best block
            let current_best_block_index = self.get_best_block_index(&best_block_id)?;
            if new_block_index.chain_trust > current_best_block_index.chain_trust {
                self.reorganize(&mut cached_inputs, Some(best_block_id), &new_block_index)?;
                self.db_tx
                    .set_best_block_id(new_block_index.get_block_id())
                    .map_err(BlockError::from)?;
                return Ok(Some(new_block_index));
            } else {
                // TODO: we don't store block indexes for blocks we don't accept, because this is PoS
                // Equal chain trust or less
                self.db_tx.set_block_index(&new_block_index)?;
            }
        }
        Ok(None)
    }

    fn get_block_proof(&self, _block: &Block) -> u128 {
        //TODO: We have to make correct one
        10
    }

    fn add_to_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        // TODO: Check for duplicate block index
        let prev_block_index = self
            .db_tx
            .get_block_index(&block.get_prev_block_id().ok_or(BlockError::Unknown)?.into())
            .map_err(BlockError::from)?;
        // Set the block height
        let height = match &prev_block_index {
            Some(prev_block_index) => prev_block_index.height.next_height(),
            None => BlockHeight::zero(),
        };
        // Set Time Max
        let time_max = match &prev_block_index {
            Some(prev_block_index) => {
                std::cmp::max(prev_block_index.time_max, block.get_block_time())
            }
            None => block.get_block_time(),
        };
        // Set Chain Trust
        let chain_trust = match &prev_block_index {
            Some(prev_block_index) => prev_block_index.chain_trust,
            None => 0,
        } + self.get_block_proof(block);
        let block_index = BlockIndex::new(block, chain_trust, height, time_max);
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        Ok(block_index)
    }

    #[allow(dead_code)]
    fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_to_block_index(block)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        self.check_block_index(&block_index)?;
        Ok(block_index)
    }

    fn exist_block(&self, id: &Id<Block>) -> Result<bool, BlockError> {
        Ok(self.db_tx.get_block_index(id)?.is_some())
    }

    fn check_block_index(&self, blk_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known
        if self.exist_block(blk_index.get_block_id())? {
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
        // if !blk_index.is_genesis(&self.chain_config) {
        //     let prev_block_id = blk_index.get_prev_block_id().ok_or(BlockError::Orphan)?;
        //     let _prev_blk_index = self
        //         .blockchain_storage
        //         .get_block_index(&prev_block_id)?
        //         .ok_or(BlockError::Orphan)?;
        // }

        // TODO: Will be expanded
        Ok(())
    }

    #[allow(dead_code)]
    fn check_block_detail(&self, block: &Block) -> Result<(), BlockError> {
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

        // TODO: Check it
        match &block.get_prev_block_id() {
            Some(block_id) => {
                let previous_block = self
                    .db_tx
                    .get_block_index(&Id::<Block>::from(block_id))?
                    .ok_or(BlockError::NotFound)?; // TODO: Fix it
                                                   // Time
                let block_time = block.get_block_time();
                if previous_block.get_block_time() > block_time {
                    return Err(BlockError::Unknown);
                }
                if i64::from(block_time) > time::get() {
                    return Err(BlockError::Unknown);
                }
            }
            None => (), // TODO: This is only for genesis, AND should never come from a peer
        }

        self.check_transactions(block)?;
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

    fn is_block_in_main_chain(&self, block_index: &BlockIndex) -> bool {
        block_index.next_block_id.is_some()
            || match self.db_tx.get_best_block_id().ok().flatten() {
                Some(ref block_id) => block_index.get_block_id() == block_id,
                None => false,
            }
    }

    /// Mark new block as an orphan
    /// Ok(()) - Added
    /// Err(BlockError) - StorageFailure  
    fn new_orphan_block(&mut self, block: Block) -> Result<(), BlockError> {
        // If we have not the previous block we have to move it to OrphanBlocksPool, except if it genesis block
        match (
            block.get_prev_block_id(),
            block.get_id() != self.chain_config.genesis_block().get_id(),
        ) {
            (Some(_), _) => (), // Not a genesis block and have the ancestor
            (None, true) => {
                // Not a genesis and have no the ancestor
                self.orphan_blocks.add_block(block).map_err(|err| match err {
                    OrphanAddError::BlockAlreadyInOrphanList(_) => BlockError::Orphan,
                })?;
            }
            (None, false) => (), // genesis
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // TODO: Add proptest here
    use super::*;
    use common::address::Address;
    use common::chain::block::Block;
    use common::chain::{Destination, Transaction, TxInput, TxOutput};
    use common::primitives::consensus_data::ConsensusData;
    use common::primitives::{Amount, Id, H256};

    #[allow(dead_code)]
    fn produce_block(config: &ChainConfig, id_prev_block: Id<Block>) -> Block {
        use rand::prelude::*;

        let mut rng = rand::thread_rng();
        let mut witness: Vec<u8> = (1..100).collect();
        witness.shuffle(&mut rng);
        let mut address: Vec<u8> = (1..22).collect();
        address.shuffle(&mut rng);

        let receiver = Address::new(config, address).expect("Failed to create address");
        let input = TxInput::new(
            common::chain::OutPointSourceId::Transaction(Id::new(&H256::zero())),
            0,
            witness,
        );
        let output = TxOutput::new(Amount::new(100000000000000), Destination::Address(receiver));
        let tx = Transaction::new(0, vec![input], vec![output], 0)
            .expect("Failed to create coinbase transaction");

        Block::new(
            vec![tx],
            Some(Id::from(id_prev_block)),
            time::get() as u32,
            ConsensusData::None,
        )
        .expect("Error creating block")
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_parallel_chains() {
        // let config = create_mainnet();
        // let mut storage = Store::new_empty().unwrap();
        // let mut consensus = Consensus::new(config.clone(), storage);
        //
        // // process the genesis block
        // let result = dbg!(consensus.process_block(config.genesis_block().clone()));
        // assert!(result.is_ok());
        // assert_eq!(
        //     consensus.get_best_block_id().expect("Best block didn't found"),
        //     Some(config.genesis_block().get_id())
        // );
        //
        // // Process the second block
        // let new_block = produce_block(&config, config.genesis_block().get_id());
        // dbg!(new_block.get_id());
        // let new_id = Some(new_block.get_id());
        // assert!(dbg!(consensus.process_block(new_block)).is_ok());
        // assert_eq!(
        //     consensus.get_best_block_id().expect("Best block didn't found"),
        //     new_id
        // );
        //
        // // Process the parallel block and choose the better one
        // let new_block = produce_block(&config, config.genesis_block().get_id());
        // let new_id = Some(new_block.get_id());
        // assert!(consensus.process_block(new_block).is_ok());
        // assert_eq!(
        //     consensus.get_best_block_id().expect("Best block didn't found"),
        //     new_id
        // );
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_orphans_chains() -> Result<(), BlockError> {
        // let config = create_mainnet();
        // let mut storage = Store::new_empty().unwrap();
        // let mut consensus = Consensus::new(config.clone(), &mut storage);
        //
        // // process the genesis block
        // let result = dbg!(consensus.process_block(config.genesis_block().clone()));
        // assert!(result.is_ok());
        // assert_eq!(
        //     consensus.get_best_block_id()?,
        //     Some(config.genesis_block().get_id())
        // );
        //
        // // Process the second block
        // let new_block = produce_block(&config, config.genesis_block().get_id());
        // dbg!(new_block.get_id());
        // let new_id = Some(new_block.get_id());
        // assert!(dbg!(consensus.process_block(new_block)).is_ok());
        // assert_eq!(consensus.get_best_block_id()?, new_id);
        //
        // // Process the orphan block
        // for _ in 0..255 {
        //     let new_block = produce_block(&config, Id::<Block>::new(&H256::zero()));
        //     dbg!(new_block.get_id());
        //     assert_eq!(consensus.process_block(new_block), Err(BlockError::Orphan));
        // }
        Ok(())
    }

    #[test]
    #[allow(clippy::eq_op)]
    fn test_connect_straight_chains() -> Result<(), BlockError> {
        // let config = create_mainnet();
        // let mut storage = Store::new_empty().unwrap();
        // let mut consensus = Consensus::new(config.clone(), &mut storage);
        //
        // // process the genesis block
        // println!(
        //     "\nPROCESSING BLOCK 0: {:?}",
        //     &config.genesis_block().get_id().get()
        // );
        // let result = consensus.process_block(config.genesis_block().clone());
        // assert!(result.is_ok());
        // assert_eq!(
        //     consensus.get_best_block_id().expect("Best block didn't found"),
        //     Some(config.genesis_block().get_id())
        // );
        //
        // // Process the second block
        // let new_block = produce_block(&config, config.genesis_block().get_id());
        // println!("\nPROCESSING BLOCK 1: {:?}", &new_block.get_id().get());
        // let new_id = Some(new_block.get_id());
        // assert!(consensus.process_block(new_block).is_ok());
        // assert_eq!(
        //     consensus.get_best_block_id().expect("Best block didn't found"),
        //     new_id
        // );
        //
        // for i in 2..255 {
        //     // Process another block
        //     let previous_block_id = new_id.clone().unwrap();
        //     let new_block = produce_block(&config, previous_block_id.clone());
        //     println!("\nPROCESSING BLOCK {}: {:?}", i, &new_block.get_id().get());
        //     let new_id = Some(new_block.get_id());
        //     assert!(consensus.process_block(new_block).is_ok());
        //     assert_eq!(consensus.get_best_block_id()?, new_id);
        //     let block_id = consensus.get_best_block_id()?.unwrap();
        //     assert_eq!(
        //         consensus.get_block(block_id)?.unwrap().get_prev_block_id(),
        //         previous_block_id
        //     )
        // }
        Ok(())
    }

    // TODO: Not ready tests for this PR related to:
    //  Fail block processing
    fn test_fail_block_processing() {}

    //  More cases for reorg
    fn test_reorg_simple() {}

    fn test_reorg_simple() {}

    //  Tests with chain trust
}
