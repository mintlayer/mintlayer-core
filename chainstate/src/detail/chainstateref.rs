use std::collections::BTreeSet;

use blockchain_storage::{BlockchainStorageRead, BlockchainStorageWrite, TransactionRw};
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, Block, BlockHeader, BlockIndex,
        },
        calculate_tx_index_from_block,
        config::MAX_BLOCK_WEIGHT,
        ChainConfig, OutPointSourceId, Transaction,
    },
    primitives::{BlockDistance, BlockHeight, Id, Idable},
};
use itertools::Itertools;
use logging::log;
use serialization::Encode;

use crate::{detail::block_index_history_iter::BlockIndexHistoryIterator, BlockError, BlockSource};

use super::{
    consensus_validator::{self, BlockIndexHandle},
    orphan_blocks::OrphanBlocksPool,
    spend_cache::{BlockTransactableRef, CachedInputs},
    CheckBlockError, CheckBlockTransactionsError, OrphanCheckError, PropertyQueryError, TimeGetter,
};

pub(crate) struct ChainstateRef<'a, S> {
    chain_config: &'a ChainConfig,
    db_tx: S,
    // TODO: get rid of the Option<>. The Option is here because mutability abstraction wasn't done for orphans while it was done for db transaction
    orphan_blocks: Option<&'a mut OrphanBlocksPool>,
    time_getter: &'a TimeGetter,
}

impl<'a, S: BlockchainStorageRead> BlockIndexHandle for ChainstateRef<'a, S> {
    fn get_block_index(
        &self,
        block_index: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.get_block_index(block_index)
    }
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, PropertyQueryError> {
        self.get_ancestor(block_index, ancestor_height)
    }
}

impl<'a, S: TransactionRw<Error = blockchain_storage::Error>> ChainstateRef<'a, S> {
    pub fn commit_db_tx(self) -> blockchain_storage::Result<()> {
        self.db_tx.commit()
    }
}

impl<'a, S: BlockchainStorageRead> ChainstateRef<'a, S> {
    pub fn new_rw(
        chain_config: &'a ChainConfig,
        db_tx: S,
        orphan_blocks: Option<&'a mut OrphanBlocksPool>,
        time_getter: &'a TimeGetter,
    ) -> ChainstateRef<'a, S> {
        ChainstateRef {
            chain_config,
            db_tx,
            orphan_blocks,
            time_getter,
        }
    }

    pub fn new_ro(
        chain_config: &'a ChainConfig,
        db_tx: S,
        time_getter: &'a TimeGetter,
    ) -> ChainstateRef<'a, S> {
        ChainstateRef {
            chain_config,
            db_tx,
            orphan_blocks: None,
            time_getter,
        }
    }

    pub fn current_time(&self) -> i64 {
        (self.time_getter)()
    }

    pub fn calculate_median_time_past(&self, starting_block: &Id<Block>) -> u32 {
        // TODO: add tests for this function
        const MEDIAN_TIME_SPAN: usize = 11;

        let iter = BlockIndexHistoryIterator::new(starting_block.clone(), self);
        let time_values = iter
            .take(MEDIAN_TIME_SPAN)
            .map(|bi| bi.get_block_time())
            .sorted()
            .collect::<Vec<_>>();

        time_values[time_values.len() / 2]
    }

    pub fn get_best_block_id(&self) -> Result<Option<Id<Block>>, PropertyQueryError> {
        self.db_tx.get_best_block_id().map_err(PropertyQueryError::from)
    }

    pub fn get_block_index(
        &self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        log::trace!("Loading block index of id: {}", block_id);
        self.db_tx.get_block_index(block_id).map_err(PropertyQueryError::from)
    }

    pub fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, PropertyQueryError> {
        self.db_tx.get_block_id_by_height(height).map_err(PropertyQueryError::from)
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.db_tx.get_block(block_id).map_err(PropertyQueryError::from)
    }

    pub fn is_block_in_main_chain(
        &self,
        block_index: &BlockIndex,
    ) -> Result<bool, PropertyQueryError> {
        let height = block_index.get_block_height();
        let id_at_height =
            self.db_tx.get_block_id_by_height(&height).map_err(PropertyQueryError::from)?;
        match id_at_height {
            Some(id) => Ok(id == *block_index.get_block_id()),
            None => Ok(false),
        }
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_previous_block_index(
        &self,
        block_index: &BlockIndex,
    ) -> Result<BlockIndex, PropertyQueryError> {
        let prev_block_id = block_index.get_prev_block_id().as_ref().ok_or_else(|| {
            PropertyQueryError::BlockIndexHasNoPrevBlock(block_index.get_block_id().clone())
        })?;
        self.db_tx
            .get_block_index(prev_block_id)?
            .ok_or_else(|| PropertyQueryError::PrevBlockIndexNotFound(prev_block_id.clone()))
    }

    // TODO improve using pskip
    pub fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, PropertyQueryError> {
        if ancestor_height > block_index.get_block_height() {
            return Err(PropertyQueryError::InvalidAncestorHeight {
                block_height: block_index.get_block_height(),
                ancestor_height,
            });
        }

        let mut height_walk = block_index.get_block_height();
        let mut block_index_walk = block_index.clone();
        while height_walk > ancestor_height {
            block_index_walk = self.get_previous_block_index(&block_index_walk)?;
            height_walk =
                (height_walk - BlockDistance::from(1)).expect("height_walk is greater than height");
        }
        Ok(block_index_walk)
    }

    #[allow(unused)]
    pub fn last_common_ancestor(
        &self,
        first_block_index: &BlockIndex,
        second_block_index: &BlockIndex,
    ) -> Result<BlockIndex, PropertyQueryError> {
        let mut first_block_index = first_block_index.clone();
        let mut second_block_index = second_block_index.clone();
        match first_block_index.get_block_height().cmp(&second_block_index.get_block_height()) {
            std::cmp::Ordering::Greater => {
                first_block_index =
                    self.get_ancestor(&first_block_index, second_block_index.get_block_height())?;
            }
            std::cmp::Ordering::Less => {
                second_block_index =
                    self.get_ancestor(&second_block_index, first_block_index.get_block_height())?;
            }
            std::cmp::Ordering::Equal => {}
        }

        while first_block_index.get_block_id() != second_block_index.get_block_id()
            && !first_block_index.is_genesis(self.chain_config)
            && !second_block_index.is_genesis(self.chain_config)
        {
            first_block_index = self.get_previous_block_index(&first_block_index)?;
            second_block_index = self.get_previous_block_index(&second_block_index)?;
        }
        assert_eq!(
            first_block_index.get_block_id(),
            second_block_index.get_block_id()
        );
        Ok(first_block_index)
    }

    pub fn get_best_block_index(&self) -> Result<Option<BlockIndex>, PropertyQueryError> {
        let best_block_id = match self.get_best_block_id()? {
            Some(id) => id,
            None => return Ok(None),
        };
        self.get_block_index(&best_block_id)
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        let id = self
            .get_block_id_by_height(height)?
            .ok_or(PropertyQueryError::BlockForHeightNotFound(*height))?;
        Ok(self.get_block_index(&id)?.map(|block_index| block_index.into_block_header()))
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        let block_index = self.get_block_index(id)?;
        let block_index =
            block_index.ok_or_else(|| PropertyQueryError::BlockNotFound(id.clone()))?;
        if block_index.get_block_id() == id {
            Ok(Some(block_index.get_block_height()))
        } else {
            Ok(None)
        }
    }

    // Get indexes for a new longest chain
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, PropertyQueryError> {
        let mut result = Vec::new();
        let mut block_index = new_tip_block_index.clone();
        while !self.is_block_in_main_chain(&block_index)? {
            result.push(block_index.clone());
            block_index = self.get_previous_block_index(&block_index)?;
        }
        result.reverse();
        debug_assert!(!result.is_empty()); // there has to always be at least one new block
        Ok(result)
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.get_block_id())?.is_some() {
            return Err(BlockError::BlockAlreadyExists(
                block_index.get_block_id().clone(),
            ));
        }
        // TODO: Will be expanded
        Ok(())
    }

    fn check_block_detail(&self, block: &Block) -> Result<(), CheckBlockError> {
        block.check_version()?;

        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.transactions()).map_or(
            Err(CheckBlockError::MerkleRootMismatch),
            |merkle_tree| {
                if merkle_tree_root != merkle_tree {
                    Err(CheckBlockError::MerkleRootMismatch)
                } else {
                    Ok(())
                }
            },
        )?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.transactions()).map_or(
            Err(CheckBlockError::WitnessMerkleRootMismatch),
            |witness_merkle| {
                if witness_merkle_root != witness_merkle {
                    Err(CheckBlockError::WitnessMerkleRootMismatch)
                } else {
                    Ok(())
                }
            },
        )?;

        match &block.prev_block_id() {
            Some(prev_block_id) => {
                let median_time_past = self.calculate_median_time_past(prev_block_id);
                if block.block_time() < median_time_past {
                    // TODO: test submitting a block that fails this
                    return Err(CheckBlockError::BlockTimeOrderInvalid);
                }

                let max_future_offset = self.chain_config.max_future_block_time_offset();
                let current_time = self.current_time();
                if i64::from(block.block_time()) > current_time + max_future_offset.as_secs() as i64
                {
                    // TODO: test submitting a block that fails this
                    return Err(CheckBlockError::BlockFromTheFuture);
                }
            }
            None => {
                // This is only for genesis, AND should never come from a peer
                if !block.is_genesis(self.chain_config) {
                    return Err(CheckBlockError::InvalidBlockNoPrevBlock);
                }
            }
        }

        self.check_transactions(block)
            .map_err(CheckBlockError::CheckTransactionFailed)?;

        // TODO: Size limits
        if block.encoded_size() > MAX_BLOCK_WEIGHT {
            return Err(CheckBlockError::BlockTooLarge);
        }

        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), CheckBlockTransactionsError> {
        // check for duplicate inputs (see CVE-2018-17144)
        {
            let mut block_inputs = BTreeSet::new();
            for tx in block.transactions() {
                let mut tx_inputs = BTreeSet::new();
                for input in tx.get_inputs() {
                    if !block_inputs.insert(input.get_outpoint()) {
                        return Err(CheckBlockTransactionsError::DuplicateInputInBlock(
                            block.get_id(),
                        ));
                    }
                    if !tx_inputs.insert(input.get_outpoint()) {
                        return Err(CheckBlockTransactionsError::DuplicateInputInTransaction(
                            tx.get_id(),
                            block.get_id(),
                        ));
                    }
                }
            }
        }

        {
            // check duplicate transactions
            let mut txs_ids = BTreeSet::new();
            for tx in block.transactions() {
                let tx_id = tx.get_id();
                let already_in_tx_id = txs_ids.get(&tx_id);
                match already_in_tx_id {
                    Some(_) => {
                        return Err(CheckBlockTransactionsError::DuplicatedTransactionInBlock(
                            tx_id,
                            block.get_id(),
                        ))
                    }
                    None => txs_ids.insert(tx_id),
                };
            }
        }

        // TODO: Check signatures will be added when BLS is ready
        Ok(())
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(block_index.get_block_id().clone())?)
    }

    pub fn check_block(&self, block: &Block) -> Result<(), CheckBlockError> {
        consensus_validator::validate_consensus(self.chain_config, block.header(), self)
            .map_err(CheckBlockError::ConsensusVerificationFailed)?;
        self.check_block_detail(block)?;
        Ok(())
    }

    fn get_block_proof(&self, _block: &Block) -> u128 {
        // TODO: Make correct block proof calculation based on consensus
        1
    }

    fn check_tx_outputs(&self, transactions: &[Transaction]) -> Result<(), BlockError> {
        for tx in transactions {
            for _output in tx.get_outputs() {
                // TODO: Check tx outputs to prevent the overwriting of the transaction
            }
        }
        Ok(())
    }

    fn make_cache_with_connected_transactions(
        &self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<CachedInputs<S>, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);

        cached_inputs.spend(
            BlockTransactableRef::BlockReward(block),
            spend_height,
            blockreward_maturity,
        )?;

        for (tx_num, _tx) in block.transactions().iter().enumerate() {
            cached_inputs.spend(
                BlockTransactableRef::Transaction(block, tx_num),
                spend_height,
                blockreward_maturity,
            )?;
        }

        let block_subsidy = self.chain_config.block_subsidy_at_height(spend_height);
        cached_inputs.check_block_reward(block, block_subsidy)?;

        Ok(cached_inputs)
    }

    fn make_cache_with_disconnected_transactions(
        &self,
        block: &Block,
    ) -> Result<CachedInputs<S>, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);
        block.transactions().iter().enumerate().try_for_each(|(tx_num, _tx)| {
            cached_inputs.unspend(BlockTransactableRef::Transaction(block, tx_num))
        })?;
        cached_inputs.unspend(BlockTransactableRef::BlockReward(block))?;
        Ok(cached_inputs)
    }
}

impl<'a, S: BlockchainStorageWrite> ChainstateRef<'a, S> {
    pub fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: Block,
    ) -> Result<Block, OrphanCheckError> {
        let prev_block_id = &match block.prev_block_id() {
            Some(id) => id,
            None => {
                if block.is_genesis(self.chain_config) {
                    return Ok(block);
                } else {
                    return Err(OrphanCheckError::PrevBlockIdNotFound);
                }
            }
        };

        let block_index_found = self
            .get_block_index(prev_block_id)
            .map_err(OrphanCheckError::PrevBlockIndexNotFound)?
            .is_some();

        if block_source == BlockSource::Local
            && !block.is_genesis(self.chain_config)
            && !block_index_found
        {
            self.new_orphan_block(block)?;
            return Err(OrphanCheckError::LocalOrphan);
        }
        Ok(block)
    }

    fn disconnect_until(
        &mut self,
        to_disconnect: &BlockIndex,
        last_to_remain_connected: &Id<Block>,
    ) -> Result<(), BlockError> {
        if to_disconnect.get_block_id() == last_to_remain_connected {
            return Ok(());
        }

        let current_mainchain_tip = self.disconnect_tip(Some(to_disconnect.get_block_id()))?;
        self.disconnect_until(&current_mainchain_tip, last_to_remain_connected)
    }

    fn reorganize(
        &mut self,
        best_block_id: &Id<Block>,
        new_block_index: &BlockIndex,
    ) -> Result<(), BlockError> {
        let new_chain = self.get_new_chain(new_block_index).map_err(|e| {
            BlockError::InvariantErrorFailedToFindNewChainPath(
                new_block_index.get_block_id().clone(),
                best_block_id.clone(),
                e,
            )
        })?;

        let common_ancestor_id = {
            let err = "This vector cannot be empty since there is at least one block to connect";
            let first_block = &new_chain.first().expect(err);
            &first_block.get_prev_block_id().as_ref().expect("This can never be genesis")
        };

        // Disconnect the current chain if it is not a genesis
        {
            let mainchain_tip = self
                .db_tx
                .get_block_index(best_block_id)?
                .expect("Can't get block index. Inconsistent DB");

            // Disconnect blocks
            self.disconnect_until(&mainchain_tip, common_ancestor_id)?;
        }

        // Connect the new chain
        for block_index in new_chain {
            self.connect_tip(&block_index)?;
        }

        Ok(())
    }

    fn connect_transactions(
        &mut self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let cached_inputs =
            self.make_cache_with_connected_transactions(block, spend_height, blockreward_maturity)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn disconnect_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        let cached_inputs = self.make_cache_with_disconnected_transactions(block)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn connect_genesis_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        for (num, tx) in block.transactions().iter().enumerate() {
            self.db_tx.set_mainchain_tx_index(
                &OutPointSourceId::from(tx.get_id()),
                &calculate_tx_index_from_block(block, num)
                    .expect("Index calculation for genesis failed"),
            )?;
        }
        Ok(())
    }

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        if &self.db_tx.get_best_block_id()? != new_tip_block_index.get_prev_block_id() {
            return Err(BlockError::InvariantErrorInvalidTip);
        }
        let block = self.get_block_from_index(new_tip_block_index)?.expect("Inconsistent DB");
        self.check_tx_outputs(block.transactions())?;

        if block.is_genesis(self.chain_config) {
            self.connect_genesis_transactions(&block)?
        } else {
            self.connect_transactions(
                &block,
                &new_tip_block_index.get_block_height(),
                self.chain_config.get_blockreward_maturity(),
            )?;
        }

        self.db_tx.set_block_id_at_height(
            &new_tip_block_index.get_block_height(),
            new_tip_block_index.get_block_id(),
        )?;
        self.db_tx.set_block_index(new_tip_block_index)?;
        self.db_tx.set_best_block_id(new_tip_block_index.get_block_id())?;
        Ok(())
    }

    /// Does a read-modify-write operation on the database and disconnects a block
    /// by unsetting the `next` pointer.
    /// Returns the previous block (the last block in the main-chain)
    fn disconnect_tip(
        &mut self,
        expected_tip_block_id: Option<&Id<Block>>,
    ) -> Result<BlockIndex, BlockError> {
        let best_block_id =
            self.db_tx.get_best_block_id().ok().flatten().expect("Only fails at genesis");

        // Optionally, we can double-check that the tip is what we're discconnecting
        match expected_tip_block_id {
            None => {}
            Some(expected_tip_block_id) => debug_assert!(expected_tip_block_id == &best_block_id),
        }

        let block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .expect("Database error on retrieving current best block index")
            .expect("Also only genesis fails at this");
        let block = self.get_block_from_index(&block_index)?.expect("Inconsistent DB");
        // Disconnect transactions
        self.disconnect_transactions(&block)?;
        self.db_tx.set_best_block_id(
            block_index
                .get_prev_block_id()
                .as_ref()
                .ok_or(BlockError::InvariantErrorPrevBlockNotFound)?,
        )?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.get_block_height())?;

        let prev_block_index = self
            .get_previous_block_index(&block_index)
            .expect("Failed to continue disconnection of blocks and reached genesis");
        Ok(prev_block_index)
    }

    fn try_connect_genesis_block(
        &mut self,
        genesis_block_index: &BlockIndex,
        best_block_id: &Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        if best_block_id.is_none() && genesis_block_index.is_genesis(self.chain_config) {
            self.connect_tip(genesis_block_index)?;
            return Ok(Some(genesis_block_index.clone()));
        }
        Ok(None)
    }

    pub fn activate_best_chain(
        &mut self,
        new_block_index: BlockIndex,
        best_block_id: Option<Id<Block>>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let connected_genesis = self.try_connect_genesis_block(&new_block_index, &best_block_id)?;
        if connected_genesis.is_some() {
            return Ok(connected_genesis);
        }

        let best_block_id = best_block_id.expect("Best block must be set at this point");
        // Chain trust is higher than the best block
        let current_best_block_index = self
            .db_tx
            .get_block_index(&best_block_id)
            .map_err(BlockError::from)?
            .expect("Inconsistent DB");

        if new_block_index.get_chain_trust() > current_best_block_index.get_chain_trust() {
            self.reorganize(&best_block_id, &new_block_index)?;
            return Ok(Some(new_block_index));
        }

        Ok(None)
    }

    fn add_to_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let prev_block_index = if block.is_genesis(self.chain_config) {
            // Genesis case. We should use then_some when stabilized feature(bool_to_option)
            None
        } else {
            block.prev_block_id().map_or(Err(BlockError::PrevBlockNotFound), |prev_block| {
                self.db_tx.get_block_index(&prev_block).map_err(BlockError::from)
            })?
        };
        // Set the block height
        let height = prev_block_index.as_ref().map_or(BlockHeight::zero(), |prev_block_index| {
            prev_block_index.get_block_height().next_height()
        });

        // Set Time Max
        let time_max = prev_block_index.as_ref().map_or(block.block_time(), |prev_block_index| {
            std::cmp::max(prev_block_index.get_block_time_max(), block.block_time())
        });

        // Set Chain Trust
        let chain_trust = prev_block_index
            .map_or(0, |prev_block_index| prev_block_index.get_chain_trust())
            + self.get_block_proof(block);
        let block_index = BlockIndex::new(block, chain_trust, height, time_max);
        Ok(block_index)
    }

    pub fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        // TODO: before doing anything, we should ensure the block isn't already known
        let block_index = self.add_to_block_index(block)?;
        self.check_block_index(&block_index)?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        Ok(block_index)
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: Block) -> Result<(), OrphanCheckError> {
        // It can't be a genesis block
        assert!(!block.is_genesis(self.chain_config));
        match self.orphan_blocks {
            Some(ref mut orphans) => match orphans.add_block(block) {
                Ok(_) => Ok(()),
                Err(err) => err.into(),
            },
            None => Ok(()),
        }
    }
}
