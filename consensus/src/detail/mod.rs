// Copyright (c) 2022 RBB S.r.l
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
use crate::detail::pow::work::check_proof_of_work;
use crate::detail::pow::PoW;
use crate::ConsensusEvent;
use blockchain_storage::BlockchainStorageRead;
use blockchain_storage::BlockchainStorageWrite;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{calculate_tx_merkle_root, calculate_witness_merkle_root, Block};
use common::chain::config::ChainConfig;
use common::chain::config::MAX_BLOCK_WEIGHT;
use common::chain::PoWStatus;
use common::chain::{calculate_tx_index_from_block, ConsensusStatus};
use common::chain::{OutPointSourceId, Transaction};
use common::primitives::BlockDistance;
use common::primitives::{time, BlockHeight, Id, Idable};
use std::collections::BTreeSet;
use std::sync::Arc;
mod orphan_blocks;
use serialization::Encode;

mod error;
pub use error::*;
mod pow;

type PeerId = u32;
type TxRw<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRw;
type TxRo<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRo;
type EventHandler = Arc<dyn Fn(ConsensusEvent) + Send + Sync>;

mod spend_cache;
use spend_cache::CachedInputs;

// TODO: ISSUE #129 - https://github.com/mintlayer/mintlayer-core/issues/129
pub struct Consensus {
    chain_config: Arc<ChainConfig>,
    blockchain_storage: blockchain_storage::Store,
    orphan_blocks: OrphanBlocksPool,
    event_subscribers: Vec<EventHandler>,
    events_broadcaster: slave_pool::ThreadPool,
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

    pub fn subscribe_to_events(&mut self, handler: EventHandler) {
        self.event_subscribers.push(handler)
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        blockchain_storage: blockchain_storage::Store,
    ) -> Result<Self, crate::ConsensusError> {
        use crate::ConsensusError;

        let mut cons = Self::new_no_genesis(chain_config, blockchain_storage)?;
        let best_block_id = cons.get_best_block_id().map_err(|e| {
            ConsensusError::FailedToInitializeConsensus(format!("Database read error: {:?}", e))
        })?;
        if best_block_id.is_none() {
            cons.process_block(
                cons.chain_config.genesis_block().clone(),
                BlockSource::Local,
            )
            .map_err(|e| {
                ConsensusError::FailedToInitializeConsensus(format!(
                    "Genesis block processing error: {:?}",
                    e
                ))
            })?;
        }
        Ok(cons)
    }

    fn new_no_genesis(
        chain_config: Arc<ChainConfig>,
        blockchain_storage: blockchain_storage::Store,
    ) -> Result<Self, crate::ConsensusError> {
        let event_broadcaster = slave_pool::ThreadPool::new();
        event_broadcaster.set_threads(1).expect("Event thread-pool starting failed");
        let cons = Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
            event_subscribers: Vec::new(),
            events_broadcaster: event_broadcaster,
        };
        Ok(cons)
    }

    fn broadcast_new_tip_event(&self, new_block_index: &Option<BlockIndex>) {
        match new_block_index {
            Some(ref new_block_index) => self.event_subscribers.iter().cloned().for_each(|f| {
                let new_height = new_block_index.get_block_height();
                let new_id = new_block_index.get_block_id().clone();
                self.events_broadcaster
                    .spawn(move || f(ConsensusEvent::NewTip(new_id, new_height)))
            }),
            None => (),
        }
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
        self.broadcast_new_tip_event(&result);
        Ok(result)
    }

    pub fn get_best_block_id(&self) -> Result<Option<Id<Block>>, BlockError> {
        let consensus_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let best_block_id = consensus_ref.db_tx.get_best_block_id().map_err(BlockError::from)?;
        Ok(best_block_id)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, BlockError> {
        let consensus_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let block_index = consensus_ref.db_tx.get_block_index(id).map_err(BlockError::from)?;
        let block_index = block_index.ok_or(BlockError::NotFound)?;
        if block_index.get_block_id() == id {
            Ok(Some(block_index.get_block_height()))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, BlockError> {
        let consensus_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let block_id =
            consensus_ref.db_tx.get_block_id_by_height(height).map_err(BlockError::from)?;
        Ok(block_id)
    }

    pub fn get_block(&self, id: Id<Block>) -> Result<Option<Block>, BlockError> {
        let consensus_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let block = consensus_ref.db_tx.get_block(id).map_err(BlockError::from)?;
        Ok(block)
    }
}

pub(crate) struct ConsensusRef<'a> {
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

    // TODO improve using pskip
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, BlockError> {
        if ancestor_height > block_index.get_block_height() {
            return Err(BlockError::InvalidAncestorHeight {
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
        block.check_version()?;

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
        let block_height = if block.is_genesis(self.chain_config) {
            BlockHeight::from(0)
        } else {
            let prev_block_id =
                block.prev_block_id().expect("Block not genesis so must have a prev_block_id");
            self.db_tx
                .get_block_index(&prev_block_id)?
                .ok_or(BlockError::Orphan)?
                .get_block_height()
                .checked_add(1)
                .expect("max block height reached")
        };

        match self.chain_config.net_upgrade().consensus_status(block_height) {
            ConsensusStatus::PoW(pow_status) => self.check_pow_consensus(block, pow_status),
            ConsensusStatus::IgnoreConsensus => Ok(()),
            ConsensusStatus::PoS => todo!(),
            ConsensusStatus::DSA => todo!(),
        }
    }

    fn check_pow_consensus(&self, block: &Block, pow_status: PoWStatus) -> Result<(), BlockError> {
        let work_required = match pow_status {
            PoWStatus::Threshold { initial_difficulty } => initial_difficulty,
            PoWStatus::Ongoing => {
                let prev_block_id = block
                    .prev_block_id()
                    .expect("If PoWStatus is `Onging` then we cannot be at genesis");
                let prev_block_index =
                    self.db_tx.get_block_index(&prev_block_id)?.ok_or(BlockError::NotFound)?;
                PoW::new(self.chain_config).get_work_required(
                    &prev_block_index,
                    block.block_time(),
                    self,
                )?
            }
        };

        if check_proof_of_work(block.get_id().get(), work_required)? {
            Ok(())
        } else {
            Err(BlockError::InvalidPoW)
        }
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
        //TODO: The parts that check the block in isolation without the knowledge of the state should not take
        //      storage as an argument (either directly or indirectly as done here through self)
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
mod tests;
