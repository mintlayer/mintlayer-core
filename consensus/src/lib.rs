use crate::orphan_blocks::{OrphanAddError, OrphanBlocksPool};
use blockchain_storage::BlockchainStorage;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::chain::Transaction;
use common::primitives::{time, BlockHeight, Id, Idable};
mod chain_state;
use chain_state::*;
mod orphan_blocks;

// struct BlockIndexCandidates {
//     inner: Vec<BlockIndex>,
// }
//
// impl BlockIndexCandidates {
//     pub fn insertion_sort<T>(values: &mut [T])
//     where
//         T: Ord,
//     {
//         for i in 0..values.len() {
//             for j in (0..i).rev() {
//                 if values[j] >= values[j + 1] {
//                     values.swap(j, j + 1);
//                 } else {
//                     break;
//                 }
//             }
//         }
//     }
//
//     fn insert(&mut self, block_index: BlockIndex) -> bool {
//         self.inner.insert(block_index)
//     }
//
//     fn erase(&mut self, block_index: &BlockIndex) -> bool {
//         self.inner.remove(block_index)
//     }
//
//     fn get_best_candidate(&self) -> BlockIndex {
//         unimplemented!()
//     }
//
//     fn compare(pa: &BlockIndex, pb: &BlockIndex) -> bool {
//         // First sort by most total trust
//         if pa.chain_trust > pb.chain_trust {
//             return false;
//         }
//         if pa.chain_trust < pb.chain_trust {
//             return true;
//         }
//         // ... then be earliest time received
//         if pa.time < pb.time {
//             return false;
//         }
//         if pa.time > pb.time {
//             return true;
//         }
//         false
//     }
// }

#[allow(dead_code)]
// TODO: We will generalize it when Lukas will be ready for that. At the moment, he recommended use
//  types directly.
// struct Consensus<'a, S: Transactional<'a> + BlockchainStorage> {
struct Consensus {
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store, //&'a mut S,
    orphan_blocks: OrphanBlocksPool,
    highest_block_trust: u64,
}

type PeerId = u32;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum BlockSource {
    Peer(PeerId),
    Local,
}

impl Consensus {
    // TODO: Make fn that will return tx

    #[allow(dead_code)]
    pub fn new(chain_config: ChainConfig, blockchain_storage: blockchain_storage::Store) -> Self {
        Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
            highest_block_trust: 0,
        }
    }

    #[allow(dead_code)]
    pub fn process_block(
        &mut self,
        block: Block,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        // self.check_block(&block)?; // Might data will change during the reading from DB? If not, we can move it back here
        let db_tx = self.blockchain_storage.start_transaction_rw();
        let mut consensus_ref = ConsensusRef {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &mut self.orphan_blocks,
            highest_block_trust: self.highest_block_trust,
        };
        consensus_ref.check_block(&block)?;
        let block_index = consensus_ref.accept_block(&block);
        if BlockSource::Local == block_source && block_index == Err(BlockError::Orphan) {
            consensus_ref.new_orphan_block(block)?;
        }
        let block_index = block_index?;
        let result = consensus_ref.activate_best_chain(block_index)?;
        consensus_ref.commit().expect("Committing transactions to DB failed");
        Ok(result)
    }
}

struct ConsensusRef<'a> {
    chain_config: &'a ChainConfig,
    db_tx: <blockchain_storage::Store as Transactional<'a>>::TransactionRw, // TODO: make this generic over Rw and Ro
    orphan_blocks: &'a mut OrphanBlocksPool,
    highest_block_trust: u64,
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

    fn apply_tx_in_undo(&mut self, _tx: &Transaction) {
        //TODO: not implemented yet
    }

    fn disconnect_one_block(&mut self, block_index: &mut BlockIndex) -> Result<(), BlockError> {
        let block = self
            .db_tx
            .get_block(
                //TODO: Remove clone() when Lukas code will be ready
                block_index.get_block_id().clone(),
            )?
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
        self.db_tx.set_best_block_id(
            block_index.get_prev_block_id().as_ref().ok_or(BlockError::Unknown)?,
        )?;
        // Update connection
        block_index.next_block_id = None;
        self.db_tx.set_block_index(block_index)?;
        Ok(())
    }

    fn connect_blocks(&mut self, top_block_index: &BlockIndex) -> Result<(), BlockError> {
        // Disconnect the current chain
        if let Some(best_block_id) = self.db_tx.get_best_block_id()? {
            let mut ancestor = self
                .db_tx
                .get_block_index(&best_block_id)?
                .expect("Can't get block index. Inconsistent DB");
            while !self.is_block_in_main_chain(&ancestor) {
                self.disconnect_one_block(&mut ancestor)?;
                ancestor = self.get_ancestor(ancestor.get_block_id())?;
            }
        }

        // Connect the new chain
        let mut ancestor = top_block_index.clone();
        while !self.is_block_in_main_chain(&ancestor) {
            self.connect_one_block(&ancestor)?;
            ancestor = self.get_ancestor(ancestor.get_block_id())?;
        }
        Ok(())
    }

    // Connect mew block
    fn connect_one_block(&mut self, block: &BlockIndex) -> Result<(), BlockError> {
        assert_eq!(
            self.db_tx.get_best_block_id().expect("Only fails at genesis"),
            block.prev_block_id
        );

        match &block.prev_block_id {
            Some(prev_block_id) => {
                // TODO: Check tx outputs to prevent the overwriting of the transaction
                // TODO: Check tx inputs:
                //  - Any transaction validation failure in connect_block is a block consensus failure
                //  - Check fee in the block
                //  - Check script
                // TODO: Check tx fees
                // TODO: Connect transactions

                // CONNECT: Set-up the next_block_id
                let mut prev_block = self
                    .db_tx
                    .get_block_index(prev_block_id)?
                    .expect("Can't get block index. Inconsistent DB");
                prev_block.next_block_id = Some(block.block_id.clone());
                self.db_tx
                    .set_block_index(&prev_block)
                    .expect("Can't set block index. Inconsistent DB");
                self.db_tx.set_block_index(block)?;
                Ok(())
            }
            None => panic!("Inconsistent block hash"),
        }
    }

    fn store_index_without_connect(&mut self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // TODO: Add checks
        self.db_tx.set_block_index(block_index)?;
        Ok(())
    }

    fn set_best_block_params(
        &mut self,
        block_index: BlockIndex,
    ) -> Result<Option<BlockIndex>, BlockError> {
        self.highest_block_trust = block_index.chain_trust;
        self.db_tx
            .set_best_block_id(block_index.get_block_id())
            .map_err(BlockError::from)?;
        Ok(Some(block_index))
    }

    fn activate_best_chain(
        &mut self,
        block_index: BlockIndex,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let best_block_id = self.db_tx.get_best_block_id()?;
        if *block_index.get_block_id() == self.chain_config.genesis_block().get_id() {
            if best_block_id.is_some() {
                panic!("Inconsistent DB: There is exist the best block, but at the same time was tried processing genesis block")
            }
            self.connect_one_block(&block_index)?;
            return self.set_best_block_params(block_index);
        }

        if let Some(best_block_id) = best_block_id {
            // Chain trust is higher than the best block
            if self.highest_block_trust < block_index.chain_trust {
                // is the main net?
                if block_index.get_prev_block_id() == &Some(best_block_id) {
                    // .. just connect the new block
                    self.connect_one_block(&block_index)?;
                    return self.set_best_block_params(block_index);
                }
                // It's not in the main net? Ok, let's do reorg
                self.connect_blocks(&block_index)?;
                return self.set_best_block_params(block_index);
            }

            // Equal chain trust or less
            if self.highest_block_trust >= block_index.chain_trust {
                self.store_index_without_connect(&block_index)?;
            }
        }
        Ok(None)
    }

    fn get_block_proof(&self, _block: &Block) -> u64 {
        //TODO: We have to make correct one
        10
    }

    fn add_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        // TODO: Check for duplicate block index
        let prev_block_index = self
            .db_tx
            .get_block_index(&block.get_prev_block_id().ok_or(BlockError::Unknown)?.into())
            .map_err(BlockError::from)?;
        // Set the block height
        let height = match &prev_block_index {
            Some(prev_block_index) => prev_block_index.height + 1,
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
        let block_index = self.add_block_index(block)?;
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

        match &block.get_prev_block_id() {
            Some(block_id) => {
                let previous_block = self
                    .db_tx
                    .get_block_index(&Id::<Block>::from(block_id))?
                    .ok_or(BlockError::NotFound)?;
                // Time
                let block_time = block.get_block_time();
                if previous_block.get_block_time() > block_time {
                    return Err(BlockError::Unknown);
                }
                if i64::from(block_time) > time::get() {
                    return Err(BlockError::Unknown);
                }
            }
            None => (),
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
        let input = TxInput::new(Id::new(&H256::zero()), 0, witness);
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
    //  More cases for reorg
    //  Tests with chain trust
}
