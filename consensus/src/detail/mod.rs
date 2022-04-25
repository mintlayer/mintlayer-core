// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach, A. Sinitsyn

use crate::detail::orphan_blocks::{OrphanAddError, OrphanBlocksPool};
use blockchain_storage::BlockchainStorageRead;
use blockchain_storage::BlockchainStorageWrite;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::calculate_tx_index_from_block;
use common::chain::config::ChainConfig;
use common::chain::{OutPointSourceId, Transaction};
use common::primitives::BlockDistance;
use common::primitives::{time, BlockHeight, Id, Idable};
use std::collections::BTreeSet;
mod orphan_blocks;
use parity_scale_codec::Encode;

mod error;
pub use error::*;

mod pow;

type PeerId = u32;
type TxRw<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRw;
type TxRo<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRo;

mod spend_cache;

use spend_cache::CachedInputs;

// DSA allows us to have blocks up to 1mb
const MAX_BLOCK_WEIGHT: usize = 1_048_576;

// TODO: ISSUE #129 - https://github.com/mintlayer/mintlayer-core/issues/129
pub struct Consensus {
    chain_config: ChainConfig,
    blockchain_storage: blockchain_storage::Store,
    orphan_blocks: OrphanBlocksPool,
}

#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub enum BlockSource {
    Peer(PeerId),
    Local,
}

impl Consensus {
    fn make_db_tx(&mut self) -> ConsensusRef {
        let db_tx = self.blockchain_storage.transaction_rw();
        ConsensusRef {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &mut self.orphan_blocks,
        }
    }

    fn make_ro_db_tx(&self) -> ConsensusRefRo {
        let db_tx = self.blockchain_storage.transaction_ro();
        ConsensusRefRo {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &self.orphan_blocks,
        }
    }

    pub fn new(
        chain_config: ChainConfig,
        blockchain_storage: blockchain_storage::Store,
    ) -> Result<Self, BlockError> {
        let mut cons = Self::new_no_genesis(chain_config, blockchain_storage)?;
        let best_block_id = cons.get_best_block_id()?;
        if best_block_id.is_none() {
            cons.process_block(
                cons.chain_config.genesis_block().clone(),
                BlockSource::Local,
            )?;
        }
        Ok(cons)
    }

    fn new_no_genesis(
        chain_config: ChainConfig,
        blockchain_storage: blockchain_storage::Store,
    ) -> Result<Self, BlockError> {
        let cons = Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
        };
        Ok(cons)
    }

    pub fn process_block(
        &mut self,
        block: Block,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut consensus_ref = self.make_db_tx();
        // Reasonable reduce amount of calls to DB
        let best_block_id = consensus_ref.db_tx.get_best_block_id().map_err(BlockError::from)?;
        // TODO: this seems to require block index, which doesn't seem to be the case in bitcoin, as otherwise orphans can't be checked
        consensus_ref.check_block(&block, block_source)?;
        let block_index = consensus_ref.accept_block(&block);
        if block_index == Err(BlockError::Orphan) {
            if BlockSource::Local == block_source {
                // TODO: Discuss with Sam about it later (orphans should be searched for children of any newly accepted block)
                consensus_ref.new_orphan_block(block)?;
            }
            return Err(BlockError::Orphan);
        }
        let result = consensus_ref.activate_best_chain(block_index?, best_block_id)?;
        consensus_ref.commit_db_tx().expect("Committing transactions to DB failed");
        Ok(result)
    }

    pub fn get_best_block_id(&self) -> Result<Option<Id<Block>>, BlockError> {
        let consensus_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let best_block_id = consensus_ref.db_tx.get_best_block_id().map_err(BlockError::from)?;
        Ok(best_block_id)
    }
}

struct ConsensusRef<'a> {
    chain_config: &'a ChainConfig,
    // TODO: make this generic over Rw and Ro
    db_tx: TxRw<'a>,
    orphan_blocks: &'a mut OrphanBlocksPool,
}

struct ConsensusRefRo<'a> {
    #[allow(dead_code)]
    chain_config: &'a ChainConfig,
    // TODO: make this generic over Rw and Ro
    db_tx: TxRo<'a>,
    #[allow(dead_code)]
    orphan_blocks: &'a OrphanBlocksPool,
}

impl<'a> ConsensusRef<'a> {
    fn commit_db_tx(self) -> blockchain_storage::Result<()> {
        self.db_tx.commit()
    }

    /// Allow to read from storage the previous block and return itself BlockIndex
    fn get_previous_block_index(&self, block_index: &BlockIndex) -> Result<BlockIndex, BlockError> {
        let prev_block_id = block_index.get_prev_block_id().as_ref().ok_or(BlockError::NotFound)?;
        self.db_tx.get_block_index(prev_block_id)?.ok_or(BlockError::NotFound)
    }

    // Get indexes for a new longest chain
    fn get_new_chain(
        &self,
        new_tip_block_index: &BlockIndex,
    ) -> Result<Vec<BlockIndex>, BlockError> {
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
        let new_chain = self.get_new_chain(new_block_index)?;

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

    fn connect_transactions_inner(
        &self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<CachedInputs, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);
        for (tx_num, _tx) in block.transactions().iter().enumerate() {
            cached_inputs.spend(block, tx_num, spend_height, blockreward_maturity)?;
        }
        Ok(cached_inputs)
    }

    fn connect_transactions(
        &mut self,
        block: &Block,
        spend_height: &BlockHeight,
        blockreward_maturity: &BlockDistance,
    ) -> Result<(), BlockError> {
        let cached_inputs =
            self.connect_transactions_inner(block, spend_height, blockreward_maturity)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn disconnect_transactions_inner(
        &mut self,
        transactions: &[Transaction],
    ) -> Result<CachedInputs, BlockError> {
        let mut cached_inputs = CachedInputs::new(&self.db_tx);
        transactions.iter().try_for_each(|tx| cached_inputs.unspend(tx))?;
        Ok(cached_inputs)
    }

    fn disconnect_transactions(&mut self, transactions: &[Transaction]) -> Result<(), BlockError> {
        let cached_inputs = self.disconnect_transactions_inner(transactions)?;
        let cached_inputs = cached_inputs.consume()?;

        CachedInputs::flush_to_storage(&mut self.db_tx, cached_inputs)?;
        Ok(())
    }

    fn check_tx_outputs(&self, transactions: &[Transaction]) -> Result<(), BlockError> {
        for tx in transactions {
            for _output in tx.get_outputs() {
                // TODO: Check tx outputs to prevent the overwriting of the transaction
            }
        }
        Ok(())
    }

    fn connect_genesis_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        for (num, tx) in block.transactions().iter().enumerate() {
            self.db_tx.set_mainchain_tx_index(
                &OutPointSourceId::from(tx.get_id()),
                &calculate_tx_index_from_block(block, num)?,
            )?;
        }
        Ok(())
    }

    // Connect new block
    fn connect_tip(&mut self, new_tip_block_index: &BlockIndex) -> Result<(), BlockError> {
        if &self.db_tx.get_best_block_id()? != new_tip_block_index.get_prev_block_id() {
            return Err(BlockError::Unknown);
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
        self.disconnect_transactions(block.transactions())?;
        self.db_tx.set_best_block_id(
            block_index.get_prev_block_id().as_ref().ok_or(BlockError::Unknown)?,
        )?;
        // Disconnect block
        self.db_tx.del_block_id_at_height(&block_index.get_block_height())?;

        let prev_block_index = self.get_previous_block_index(&block_index)?;
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

    fn activate_best_chain(
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

    fn get_block_proof(&self, _block: &Block) -> u128 {
        //TODO: We have to make correct one
        1
    }

    fn add_to_block_index(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let prev_block_index = if block.is_genesis(self.chain_config) {
            // Genesis case. We should use then_some when stabilized feature(bool_to_option)
            None
        } else {
            block.prev_block_id().map_or(Err(BlockError::Orphan), |prev_block| {
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

    fn accept_block(&mut self, block: &Block) -> Result<BlockIndex, BlockError> {
        let block_index = self.add_to_block_index(block)?;
        self.check_block_index(&block_index)?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        Ok(block_index)
    }

    fn check_block_index(&self, block_index: &BlockIndex) -> Result<(), BlockError> {
        // BlockIndex is already known or block exists
        if self.db_tx.get_block_index(block_index.get_block_id())?.is_some() {
            return Err(BlockError::Unknown);
        }
        // TODO: Will be expanded
        Ok(())
    }

    fn check_block_detail(
        &self,
        block: &Block,
        block_source: BlockSource,
    ) -> Result<(), BlockError> {
        // Allows the previous block to be None only if the block hash is genesis
        if !block.is_genesis(self.chain_config) && block.prev_block_id().is_none() {
            return Err(BlockError::Unknown);
        }

        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.transactions()).map_or(
            Err(BlockError::Unknown),
            |merkle_tree| {
                if merkle_tree_root != merkle_tree {
                    Err(BlockError::Unknown)
                } else {
                    Ok(())
                }
            },
        )?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.transactions()).map_or(
            Err(BlockError::Unknown),
            |witness_merkle| {
                if witness_merkle_root != witness_merkle {
                    Err(BlockError::Unknown)
                } else {
                    Ok(())
                }
            },
        )?;

        match &block.prev_block_id() {
            Some(block_id) => {
                let previous_block = self
                    .db_tx
                    .get_block_index(&Id::<Block>::new(&block_id.get()))?
                    .ok_or(BlockError::Orphan)?;
                // Time
                let block_time = block.block_time();
                if previous_block.get_block_time() > block_time {
                    return Err(BlockError::Unknown);
                }
                if i64::from(block_time) > time::get() {
                    return Err(BlockError::Unknown);
                }
            }
            None => {
                // This is only for genesis, AND should never come from a peer
                if block_source != BlockSource::Local {
                    return Err(BlockError::InvalidBlockSource);
                };
            }
        }

        self.check_transactions(block)?;
        Ok(())
    }

    fn check_consensus(&self, block: &Block) -> Result<(), BlockError> {
        let _consensus_data = block.consensus_data();
        // TODO: PoW is not in master at the moment =(
        Ok(())
    }

    fn check_transactions(&self, block: &Block) -> Result<(), BlockError> {
        // check for duplicate inputs (see CVE-2018-17144)
        {
            let mut block_inputs = BTreeSet::new();
            for tx in block.transactions() {
                let mut tx_inputs = BTreeSet::new();
                for input in tx.get_inputs() {
                    if !block_inputs.insert(input.get_outpoint()) {
                        return Err(BlockError::DuplicateInputInBlock(block.get_id()));
                    }
                    if !tx_inputs.insert(input.get_outpoint()) {
                        return Err(BlockError::DuplicateInputInTransaction(tx.get_id()));
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
                    Some(_) => return Err(BlockError::DuplicatedTransactionInBlock),
                    None => txs_ids.insert(tx_id),
                };
            }
        }

        //TODO: Size limits
        if block.encoded_size() > MAX_BLOCK_WEIGHT {
            return Err(BlockError::Unknown);
        }
        //TODO: Check signatures will be added when BLS is ready
        Ok(())
    }

    fn check_block(&self, block: &Block, block_source: BlockSource) -> Result<(), BlockError> {
        self.check_consensus(block)?;
        self.check_block_detail(block, block_source)?;
        Ok(())
    }

    fn is_block_in_main_chain(&self, block_index: &BlockIndex) -> Result<bool, BlockError> {
        let height = block_index.get_block_height();
        let id_at_height = self.db_tx.get_block_id_by_height(&height).map_err(BlockError::from)?;
        match id_at_height {
            Some(id) => Ok(id == *block_index.get_block_id()),
            None => Ok(false),
        }
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: Block) -> Result<(), BlockError> {
        // It can't be a genesis block
        assert!(!block.is_genesis(self.chain_config));
        self.orphan_blocks.add_block(block).map_err(|err| match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => BlockError::Orphan,
        })?;
        Ok(())
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(block_index.get_block_id().clone())?)
    }
}

#[cfg(test)]
mod test;
