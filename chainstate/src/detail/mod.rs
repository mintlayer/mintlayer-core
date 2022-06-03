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

use crate::detail::orphan_blocks::OrphanBlocksPool;
use crate::ChainstateEvent;
use blockchain_storage::BlockchainStorageRead;
use blockchain_storage::BlockchainStorageWrite;
use blockchain_storage::TransactionRw;
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{
    calculate_tx_merkle_root, calculate_witness_merkle_root, Block, BlockHeader,
};
use common::chain::calculate_tx_index_from_block;
use common::chain::config::ChainConfig;
use common::chain::config::MAX_BLOCK_WEIGHT;
use common::chain::{OutPointSourceId, Transaction};
use common::primitives::{time, BlockDistance, BlockHeight, Id, Idable};
use itertools::Itertools;
use std::collections::BTreeSet;
use std::sync::Arc;
use utils::eventhandler::{EventHandler, EventsController};
mod consensus_validator;
mod orphan_blocks;
use serialization::Encode;

mod error;
pub use error::*;
mod pow;

type TxRw<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRw;
type TxRo<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRo;
type ChainstateEventHandler = EventHandler<ChainstateEvent>;

const HEADER_LIMIT: BlockDistance = BlockDistance::new(2000);

mod spend_cache;
use consensus_validator::BlockIndexHandle;
use spend_cache::BlockTransactableRef;
use spend_cache::CachedInputs;

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;

// TODO: ISSUE #129 - https://github.com/mintlayer/mintlayer-core/issues/129
pub struct Chainstate {
    chain_config: Arc<ChainConfig>,
    blockchain_storage: blockchain_storage::Store,
    orphan_blocks: OrphanBlocksPool,
    custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    events_controller: EventsController<ChainstateEvent>,
}

#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub enum BlockSource {
    Peer,
    Local,
}

impl Chainstate {
    pub fn wait_for_all_events(&self) {
        self.events_controller.wait_for_all_events();
    }

    fn make_db_tx(&mut self) -> ChainstateRef {
        let db_tx = self.blockchain_storage.transaction_rw();
        ChainstateRef {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &mut self.orphan_blocks,
        }
    }

    fn make_ro_db_tx(&self) -> ChainstateRefRo {
        let db_tx = self.blockchain_storage.transaction_ro();
        ChainstateRefRo {
            chain_config: &self.chain_config,
            db_tx,
            orphan_blocks: &self.orphan_blocks,
        }
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.events_controller.subscribe_to_events(handler);
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        blockchain_storage: blockchain_storage::Store,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    ) -> Result<Self, crate::ChainstateError> {
        use crate::ChainstateError;

        let mut cons =
            Self::new_no_genesis(chain_config, blockchain_storage, custom_orphan_error_hook)?;
        let best_block_id = cons.get_best_block_id().map_err(|e| {
            ChainstateError::FailedToInitializeChainstate(format!("Database read error: {:?}", e))
        })?;
        if best_block_id.is_none() {
            cons.process_block(
                cons.chain_config.genesis_block().clone(),
                BlockSource::Local,
            )
            .map_err(|e| {
                ChainstateError::FailedToInitializeChainstate(format!(
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
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    ) -> Result<Self, crate::ChainstateError> {
        let cons = Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
            custom_orphan_error_hook,
            events_controller: EventsController::new(),
        };
        Ok(cons)
    }

    fn broadcast_new_tip_event(&self, new_block_index: &Option<BlockIndex>) {
        match new_block_index {
            Some(ref new_block_index) => {
                let new_height = new_block_index.get_block_height();
                let new_id = new_block_index.get_block_id().clone();
                self.events_controller.broadcast(ChainstateEvent::NewTip(new_id, new_height))
            }
            None => (),
        }
    }

    /// returns the new block index, which is the new tip, if any
    fn process_orphans(&mut self, last_processed_block: &Id<Block>) -> Option<BlockIndex> {
        let orphans = self.orphan_blocks.take_all_children_of(last_processed_block);
        let (block_indexes, block_errors): (Vec<Option<BlockIndex>>, Vec<BlockError>) = orphans
            .into_iter()
            .map(|blk| self.process_block(blk, BlockSource::Local))
            .partition_result();

        block_errors.into_iter().for_each(|e| match &self.custom_orphan_error_hook {
            Some(handler) => handler(&e),
            None => logging::log::error!("Failed to process a chain of orphan blocks: {}", e),
        });

        // since we processed the blocks in order, the last one is the best tip
        block_indexes.into_iter().flatten().rev().next()
    }

    fn process_db_commit_error(
        &mut self,
        db_error: blockchain_storage::Error,
        block: Block,
        block_source: BlockSource,
        attempt_number: usize,
    ) -> Result<Option<BlockIndex>, BlockError> {
        // TODO: move to a configuration object that loads from command line arguments
        const MAX_DB_COMMIT_COUNT: usize = 10;

        if attempt_number >= MAX_DB_COMMIT_COUNT {
            Err(BlockError::DatabaseCommitError(
                block.get_id(),
                MAX_DB_COMMIT_COUNT,
                db_error,
            ))
        } else {
            // TODO: test reattempts using mocks of the database that emulate failure
            self.attempt_to_process_block(block, block_source, attempt_number + 1)
        }
    }

    pub fn attempt_to_process_block(
        &mut self,
        block: Block,
        block_source: BlockSource,
        attempt_number: usize,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut chainstate_ref = self.make_db_tx();

        let block = chainstate_ref.check_legitimate_orphan(block_source, block)?;

        // Reasonable reduce amount of calls to DB
        let best_block_id = chainstate_ref.db_tx.get_best_block_id().map_err(BlockError::from)?;

        // TODO: this seems to require block index, which doesn't seem to be the case in bitcoin, as otherwise orphans can't be checked
        chainstate_ref.check_block(&block, block_source)?;
        let block_index = chainstate_ref.accept_block(&block)?;
        let result = chainstate_ref.activate_best_chain(block_index, best_block_id)?;
        let db_commit_result = chainstate_ref.commit_db_tx();
        match db_commit_result {
            Ok(_) => {}
            Err(err) => {
                return self.process_db_commit_error(err, block, block_source, attempt_number)
            }
        }

        let new_block_index_after_orphans = self.process_orphans(&block.get_id());
        let result = match new_block_index_after_orphans {
            Some(result_from_orphan) => Some(result_from_orphan),
            None => result,
        };

        self.broadcast_new_tip_event(&result);

        Ok(result)
    }

    /// returns the block index of the new tip
    pub fn process_block(
        &mut self,
        block: Block,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        self.attempt_to_process_block(block, block_source, 0)
    }

    // TODO: used to check block size + other preliminary check before giving the block to process_block
    pub fn preliminary_block_check(&self, _block: Block) -> Result<(), BlockError> {
        Ok(())
    }

    pub fn get_best_block_id(&self) -> Result<Option<Id<Block>>, BlockError> {
        let chainstate_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let best_block_id = chainstate_ref.db_tx.get_best_block_id().map_err(BlockError::from)?;
        Ok(best_block_id)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, BlockError> {
        let chainstate_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let block_index = chainstate_ref.db_tx.get_block_index(id).map_err(BlockError::from)?;
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
        let chainstate_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let block_id =
            chainstate_ref.db_tx.get_block_id_by_height(height).map_err(BlockError::from)?;
        Ok(block_id)
    }

    pub fn get_block(&self, id: Id<Block>) -> Result<Option<Block>, BlockError> {
        let chainstate_ref = self.make_ro_db_tx();
        // Reasonable reduce amount of calls to DB
        let block = chainstate_ref.db_tx.get_block(id).map_err(BlockError::from)?;
        Ok(block)
    }

    pub fn get_block_index(&self, id: &Id<Block>) -> Result<Option<BlockIndex>, BlockError> {
        self.make_ro_db_tx().db_tx.get_block_index(id).map_err(BlockError::from)
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, BlockError> {
        let chainstate_ref = self.make_ro_db_tx();
        let id = chainstate_ref
            .db_tx
            .get_block_id_by_height(height)?
            .ok_or(BlockError::NotFound)?;
        Ok(chainstate_ref
            .db_tx
            .get_block_index(&id)?
            .map(|block_index| block_index.into_block_header()))
    }

    pub fn get_locator(&self) -> Result<Vec<BlockHeader>, BlockError> {
        let id = self.get_best_block_id()?.ok_or(BlockError::NotFound)?;
        let height = self.get_block_height_in_main_chain(&id)?.ok_or(BlockError::NotFound)?;

        let headers = itertools::iterate(0, |&i| if i == 0 { 1 } else { i * 2 })
            .take_while(|i| (height - BlockDistance::new(*i)).is_some())
            .map(|i| {
                self.get_header_from_height(
                    &(height - BlockDistance::new(i)).expect("distance to be valid"),
                )
            });

        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
    }

    // TODO: use `ChainstateRef::is_block_in_main_chain()` implementation instead, how?
    fn is_block_in_main_chain(&self, block_index: &BlockIndex) -> Result<bool, BlockError> {
        let chainstate_ref = self.make_ro_db_tx();
        let height = block_index.get_block_height();
        let id_at_height =
            chainstate_ref.db_tx.get_block_id_by_height(&height).map_err(BlockError::from)?;
        Ok(id_at_height.map_or(false, |id| id == *block_index.get_block_id()))
    }

    pub fn get_headers(&self, locator: Vec<BlockHeader>) -> Result<Vec<BlockHeader>, BlockError> {
        // use genesis block if no common ancestor with better block height is found
        let mut best = BlockHeight::new(0);

        for header in locator.iter() {
            if let Some(block_index) = self.get_block_index(&header.get_id())? {
                if self.is_block_in_main_chain(&block_index)? {
                    best = block_index.get_block_height();
                    break;
                }
            }
        }

        // get headers until either the best block or header limit is reached
        let limit = std::cmp::min(
            (best + HEADER_LIMIT).expect("BlockHeight limit reached"),
            self.get_block_height_in_main_chain(
                &self.get_best_block_id()?.expect("best block to exist"),
            )?
            .expect("best block's height to exist"),
        );

        let headers = itertools::iterate(best.next_height(), |iter| iter.next_height())
            .take_while(|height| height <= &limit)
            .map(|height| self.get_header_from_height(&height));
        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
    }

    pub fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, BlockError> {
        // verify that the first block attaches to our chain
        match headers.get(0).ok_or(BlockError::NotFound)?.get_prev_block_id() {
            None => return Err(BlockError::PrevBlockInvalid),
            Some(id) => {
                if self.get_block_index(id)?.is_none() {
                    return Err(BlockError::NotFound);
                }
            }
        }

        for (num, header) in headers.iter().enumerate() {
            if self.get_block_index(&header.get_id())?.is_none() {
                return Ok(headers[num..].to_vec());
            }
        }

        Ok(vec![])
    }
}

pub(crate) struct ChainstateRef<'a> {
    chain_config: &'a ChainConfig,
    // TODO: make this generic over Rw and Ro
    db_tx: TxRw<'a>,
    orphan_blocks: &'a mut OrphanBlocksPool,
}

struct ChainstateRefRo<'a> {
    #[allow(dead_code)]
    chain_config: &'a ChainConfig,
    // TODO: make this generic over Rw and Ro
    db_tx: TxRo<'a>,
    #[allow(dead_code)]
    orphan_blocks: &'a OrphanBlocksPool,
}

impl<'a> BlockIndexHandle for ChainstateRef<'a> {
    fn get_block_index(
        &self,
        block_index: &Id<Block>,
    ) -> blockchain_storage::Result<Option<BlockIndex>> {
        self.db_tx.get_block_index(block_index)
    }
    fn get_ancestor(
        &self,
        block_index: &BlockIndex,
        ancestor_height: BlockHeight,
    ) -> Result<BlockIndex, BlockError> {
        self.get_ancestor(block_index, ancestor_height)
    }
}

impl<'a> ChainstateRef<'a> {
    fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: Block,
    ) -> Result<Block, BlockError> {
        if block_source == BlockSource::Local
            && !block.is_genesis(self.chain_config)
            && self
                .get_block_index(&block.prev_block_id().ok_or(BlockError::PrevBlockInvalid)?)?
                .is_none()
        {
            self.new_orphan_block(block)?;
            return Err(BlockError::LocalOrphan);
        }
        Ok(block)
    }

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

    #[allow(unused)]
    fn last_common_ancestor(
        &self,
        first_block_index: &BlockIndex,
        second_block_index: &BlockIndex,
    ) -> Result<BlockIndex, BlockError> {
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
        let mut cached_inputs = CachedInputs::new(self.chain_config, &self.db_tx);

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

    fn disconnect_transactions_inner(&mut self, block: &Block) -> Result<CachedInputs, BlockError> {
        let mut cached_inputs = CachedInputs::new(self.chain_config, &self.db_tx);
        block.transactions().iter().enumerate().try_for_each(|(tx_num, _tx)| {
            cached_inputs.unspend(BlockTransactableRef::Transaction(block, tx_num))
        })?;
        cached_inputs.unspend(BlockTransactableRef::BlockReward(block))?;
        Ok(cached_inputs)
    }

    fn disconnect_transactions(&mut self, block: &Block) -> Result<(), BlockError> {
        let cached_inputs = self.disconnect_transactions_inner(block)?;
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
            block.prev_block_id().map_or(Err(BlockError::IllegalOrphan), |prev_block| {
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
        // TODO: before doing anything, we should ensure the block isn't already known
        let block_index = self.add_to_block_index(block)?;
        self.check_block_index(&block_index)?;
        self.db_tx.set_block_index(&block_index).map_err(BlockError::from)?;
        self.db_tx.add_block(block).map_err(BlockError::from)?;
        Ok(block_index)
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

    fn check_block_detail(
        &self,
        block: &Block,
        block_source: BlockSource,
    ) -> Result<(), BlockError> {
        block.check_version()?;

        // Allows the previous block to be None only if the block hash is genesis
        if !block.is_genesis(self.chain_config) && block.prev_block_id().is_none() {
            return Err(BlockError::InvalidBlockNoPrevBlock);
        }

        // MerkleTree root
        let merkle_tree_root = block.merkle_root();
        calculate_tx_merkle_root(block.transactions()).map_or(
            Err(BlockError::MerkleRootMismatch),
            |merkle_tree| {
                if merkle_tree_root != merkle_tree {
                    Err(BlockError::MerkleRootMismatch)
                } else {
                    Ok(())
                }
            },
        )?;

        // Witness merkle root
        let witness_merkle_root = block.witness_merkle_root();
        calculate_witness_merkle_root(block.transactions()).map_or(
            Err(BlockError::WitnessMerkleRootMismatch),
            |witness_merkle| {
                if witness_merkle_root != witness_merkle {
                    Err(BlockError::WitnessMerkleRootMismatch)
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
                    .ok_or(BlockError::IllegalOrphan)?;
                // Time
                let block_time = block.block_time();
                if previous_block.get_block_time() > block_time {
                    return Err(BlockError::BlockTimeOrderInvalid);
                }
                if i64::from(block_time) > time::get() {
                    return Err(BlockError::BlockFromTheFuture);
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
            return Err(BlockError::BlockTooLarge);
        }
        //TODO: Check signatures will be added when BLS is ready
        Ok(())
    }

    fn check_block(&self, block: &Block, block_source: BlockSource) -> Result<(), BlockError> {
        //TODO: The parts that check the block in isolation without the knowledge of the state should not take
        //      storage as an argument (either directly or indirectly as done here through self)
        consensus_validator::validate_consensus(self.chain_config, block.header(), self)?;
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
        match self.orphan_blocks.add_block(block) {
            Ok(_) => Ok(()),
            Err(err) => err.into(),
        }
    }

    fn get_block_from_index(&self, block_index: &BlockIndex) -> Result<Option<Block>, BlockError> {
        Ok(self.db_tx.get_block(block_index.get_block_id().clone())?)
    }
}

#[cfg(test)]
mod tests;
