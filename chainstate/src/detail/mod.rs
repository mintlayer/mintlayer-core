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
use blockchain_storage::Transactional;
use common::chain::block::block_index::BlockIndex;
use common::chain::block::{Block, BlockHeader};
use common::chain::config::ChainConfig;
use common::primitives::{BlockDistance, BlockHeight, Id, Idable};
use itertools::Itertools;
use logging::log;
use std::sync::Arc;
use utils::eventhandler::{EventHandler, EventsController};
mod consensus_validator;
mod orphan_blocks;

mod error;
pub use error::*;

mod pow;

pub mod ban_score;
mod block_index_history_iter;
mod median_time;

mod chainstateref;

type TxRw<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRw;
type TxRo<'a> = <blockchain_storage::Store as Transactional<'a>>::TransactionRo;
type ChainstateEventHandler = EventHandler<ChainstateEvent>;

const HEADER_LIMIT: BlockDistance = BlockDistance::new(2000);

mod spend_cache;

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;

pub mod time_getter;
use time_getter::TimeGetter;

#[must_use]
pub struct Chainstate {
    chain_config: Arc<ChainConfig>,
    blockchain_storage: blockchain_storage::Store,
    orphan_blocks: OrphanBlocksPool,
    custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    events_controller: EventsController<ChainstateEvent>,
    time_getter: TimeGetter,
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

    #[must_use]
    fn make_db_tx(&mut self) -> chainstateref::ChainstateRef<TxRw> {
        let db_tx = self.blockchain_storage.transaction_rw();
        chainstateref::ChainstateRef::new_rw(
            &self.chain_config,
            db_tx,
            Some(&mut self.orphan_blocks),
            self.time_getter.getter(),
        )
    }

    #[must_use]
    fn make_db_tx_ro(&self) -> chainstateref::ChainstateRef<TxRo> {
        let db_tx = self.blockchain_storage.transaction_ro();
        chainstateref::ChainstateRef::new_ro(&self.chain_config, db_tx, self.time_getter.getter())
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.events_controller.subscribe_to_events(handler);
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        blockchain_storage: blockchain_storage::Store,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        custom_time_getter: TimeGetter,
    ) -> Result<Self, crate::ChainstateError> {
        use crate::ChainstateError;

        let mut cons = Self::new_no_genesis(
            chain_config,
            blockchain_storage,
            custom_orphan_error_hook,
            custom_time_getter,
        )?;

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
        custom_time_getter: TimeGetter,
    ) -> Result<Self, crate::ChainstateError> {
        let cons = Self {
            chain_config,
            blockchain_storage,
            orphan_blocks: OrphanBlocksPool::new_default(),
            custom_orphan_error_hook,
            events_controller: EventsController::new(),
            time_getter: custom_time_getter,
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
        log::info!("Processing block: {}", block.get_id());

        if block.is_genesis(&self.chain_config) && block_source != BlockSource::Local {
            return Err(BlockError::InvalidBlockSource);
        }

        let mut chainstate_ref = self.make_db_tx();

        let block = chainstate_ref.check_legitimate_orphan(block_source, block)?;

        let best_block_id =
            chainstate_ref.get_best_block_id().map_err(BlockError::BestBlockLoadError)?;

        chainstate_ref.check_block(&block).map_err(BlockError::CheckBlockFailed)?;

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

        if let Some(ref bi) = result {
            log::info!(
                "New tip in chainstate {} with height {}",
                bi.get_block_id(),
                bi.get_block_height()
            );
        }

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

    pub fn preliminary_block_check(&self, block: Block) -> Result<(), BlockError> {
        let chainstate_ref = self.make_db_tx_ro();
        chainstate_ref.check_block(&block)?;
        Ok(())
    }

    pub fn get_best_block_id(&self) -> Result<Option<Id<Block>>, PropertyQueryError> {
        self.make_db_tx_ro().get_best_block_id()
    }

    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        self.make_db_tx_ro().get_header_from_height(height)
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<Block>>, PropertyQueryError> {
        self.make_db_tx_ro().get_block_id_by_height(height)
    }

    pub fn get_block(&self, id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.make_db_tx_ro().get_block(id)
    }

    pub fn get_block_index(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.make_db_tx_ro().get_block_index(id)
    }

    pub fn get_best_block_index(&self) -> Result<Option<BlockIndex>, PropertyQueryError> {
        self.make_db_tx_ro().get_best_block_index()
    }

    pub fn get_locator(&self) -> Result<Vec<BlockHeader>, PropertyQueryError> {
        let chainstate_ref = self.make_db_tx_ro();
        let best_block_index = chainstate_ref
            .get_best_block_index()?
            .ok_or(PropertyQueryError::BestBlockIndexNotFound)?;
        let height = best_block_index.get_block_height();

        let headers = itertools::iterate(0, |&i| if i == 0 { 1 } else { i * 2 })
            .take_while(|i| (height - BlockDistance::new(*i)).is_some())
            .map(|i| {
                chainstate_ref.get_header_from_height(
                    &(height - BlockDistance::new(i)).expect("distance to be valid"),
                )
            });

        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<Block>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        self.make_db_tx_ro().get_block_height_in_main_chain(id)
    }

    pub fn get_headers(
        &self,
        locator: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, PropertyQueryError> {
        // use genesis block if no common ancestor with better block height is found
        let chainstate_ref = self.make_db_tx_ro();
        let mut best = BlockHeight::new(0);

        for header in locator.iter() {
            if let Some(block_index) = chainstate_ref.get_block_index(&header.get_id())? {
                if chainstate_ref.is_block_in_main_chain(&block_index)? {
                    best = block_index.get_block_height();
                    break;
                }
            }
        }

        // get headers until either the best block or header limit is reached
        let best_height = chainstate_ref
            .get_best_block_index()?
            .expect("best block's height to exist")
            .get_block_height();

        let limit = std::cmp::min(
            (best + HEADER_LIMIT).expect("BlockHeight limit reached"),
            best_height,
        );

        let headers = itertools::iterate(best.next_height(), |iter| iter.next_height())
            .take_while(|height| height <= &limit)
            .map(|height| chainstate_ref.get_header_from_height(&height));
        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
    }

    pub fn filter_already_existing_blocks(
        &self,
        headers: Vec<BlockHeader>,
    ) -> Result<Vec<BlockHeader>, PropertyQueryError> {
        let first_block = headers.get(0).ok_or(PropertyQueryError::InvalidInputEmpty)?;
        // verify that the first block attaches to our chain
        match first_block.get_prev_block_id() {
            None => return Err(PropertyQueryError::InvalidInputForPrevBlock),
            Some(id) => {
                if self.get_block_index(id)?.is_none() {
                    return Err(PropertyQueryError::BlockNotFound(id.clone()));
                }
            }
        }

        // TODO: this does some unnecessary copying of the headers; make this loop consume the vec
        for (num, header) in headers.iter().enumerate() {
            if self.get_block_index(&header.get_id())?.is_none() {
                return Ok(headers[num..].to_vec());
            }
        }

        Ok(vec![])
    }
}

#[cfg(test)]
mod tests;
