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

use crate::{detail::orphan_blocks::OrphanBlocksPool, ChainstateConfig, ChainstateEvent};
use chainstate_storage::Transactional;
use chainstate_types::block_index::BlockIndex;
use common::chain::config::ChainConfig;
use common::chain::{block::BlockHeader, Block, GenBlock};
use common::primitives::{BlockDistance, BlockHeight, Id, Idable};
use itertools::Itertools;
use logging::log;
use std::sync::Arc;
use utils::eventhandler::{EventHandler, EventsController};
mod consensus_validator;
mod orphan_blocks;

mod error;
pub use error::*;

use self::orphan_blocks::{OrphanBlocksRef, OrphanBlocksRefMut};

mod pow;

pub mod ban_score;
mod block_index_history_iter;
mod median_time;

pub use chainstate_types::locator::Locator;

mod chainstateref;
mod gen_block_index;

use gen_block_index::GenBlockIndex;

type TxRw<'a> = <chainstate_storage::Store as Transactional<'a>>::TransactionRw;
type TxRo<'a> = <chainstate_storage::Store as Transactional<'a>>::TransactionRo;
type ChainstateEventHandler = EventHandler<ChainstateEvent>;

const HEADER_LIMIT: BlockDistance = BlockDistance::new(2000);

mod spend_cache;

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;

pub mod time_getter;
use time_getter::TimeGetter;

#[must_use]
pub struct Chainstate {
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: chainstate_storage::Store,
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
    #[allow(dead_code)]
    pub fn wait_for_all_events(&self) {
        self.events_controller.wait_for_all_events();
    }

    #[must_use]
    fn make_db_tx(&mut self) -> chainstateref::ChainstateRef<TxRw, OrphanBlocksRefMut> {
        let db_tx = self.chainstate_storage.transaction_rw();
        chainstateref::ChainstateRef::new_rw(
            &self.chain_config,
            &self.chainstate_config,
            db_tx,
            self.orphan_blocks.as_rw_ref(),
            self.time_getter.getter(),
        )
    }

    #[must_use]
    fn make_db_tx_ro(&self) -> chainstateref::ChainstateRef<TxRo, OrphanBlocksRef> {
        let db_tx = self.chainstate_storage.transaction_ro();
        chainstateref::ChainstateRef::new_ro(
            &self.chain_config,
            &self.chainstate_config,
            db_tx,
            self.orphan_blocks.as_ro_ref(),
            self.time_getter.getter(),
        )
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.events_controller.subscribe_to_events(handler);
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_config: ChainstateConfig,
        chainstate_storage: chainstate_storage::Store,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        time_getter: TimeGetter,
    ) -> Result<Self, crate::ChainstateError> {
        use crate::ChainstateError;
        use chainstate_storage::BlockchainStorageRead;

        let best_block_id = chainstate_storage.get_best_block_id().map_err(|e| {
            ChainstateError::FailedToInitializeChainstate(format!("Database read error: {:?}", e))
        })?;

        let mut chainstate = Self::new_no_genesis(
            chain_config,
            chainstate_config,
            chainstate_storage,
            custom_orphan_error_hook,
            time_getter,
        );

        if best_block_id.is_none() {
            chainstate
                .process_genesis()
                .map_err(crate::ChainstateError::ProcessBlockError)?;
        }
        Ok(chainstate)
    }

    fn new_no_genesis(
        chain_config: Arc<ChainConfig>,
        chainstate_config: ChainstateConfig,
        chainstate_storage: chainstate_storage::Store,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        time_getter: TimeGetter,
    ) -> Self {
        let orphan_blocks = OrphanBlocksPool::new(chainstate_config.max_orphan_blocks);
        Self {
            chain_config,
            chainstate_config,
            chainstate_storage,
            orphan_blocks,
            custom_orphan_error_hook,
            events_controller: EventsController::new(),
            time_getter,
        }
    }

    fn broadcast_new_tip_event(&self, new_block_index: &Option<BlockIndex>) {
        match new_block_index {
            Some(ref new_block_index) => {
                let new_height = new_block_index.block_height();
                let new_id = *new_block_index.block_id();
                self.events_controller.broadcast(ChainstateEvent::NewTip(new_id, new_height))
            }
            None => (),
        }
    }

    /// returns the new block index, which is the new tip, if any
    fn process_orphans(&mut self, last_processed_block: &Id<Block>) -> Option<BlockIndex> {
        let orphans = self.orphan_blocks.take_all_children_of(&(*last_processed_block).into());
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
        db_error: chainstate_storage::Error,
        block: Block,
        block_source: BlockSource,
        attempt_number: usize,
    ) -> Result<Option<BlockIndex>, BlockError> {
        if attempt_number >= self.chainstate_config.max_db_commit_attempts {
            Err(BlockError::DatabaseCommitError(
                block.get_id(),
                self.chainstate_config.max_db_commit_attempts,
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
                bi.block_id(),
                bi.block_height()
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

    /// Initialize chainstate with genesis block
    pub fn process_genesis(&mut self) -> Result<(), BlockError> {
        use chainstate_storage::{BlockchainStorageWrite, TransactionRw};

        // Gather information about genesis.
        let genesis = self.chain_config.genesis_block();
        let genesis_id = self.chain_config.genesis_block_id();
        let utxo_count = genesis.utxos().len() as u32;
        let genesis_index = common::chain::TxMainChainIndex::new(genesis_id.into(), utxo_count)
            .expect("Genesis not constructed correctly");

        // Initialize storage with given info
        let mut db_tx = self.chainstate_storage.transaction_rw();
        db_tx.set_best_block_id(&genesis_id).map_err(BlockError::StorageError)?;
        db_tx
            .set_block_id_at_height(&BlockHeight::zero(), &genesis_id)
            .map_err(BlockError::StorageError)?;
        db_tx
            .set_mainchain_tx_index(&genesis_id.into(), &genesis_index)
            .map_err(BlockError::StorageError)?;
        db_tx.commit().expect("Genesis database initialization failed");
        Ok(())
    }

    pub fn preliminary_block_check(&self, block: Block) -> Result<Block, BlockError> {
        let chainstate_ref = self.make_db_tx_ro();
        chainstate_ref.check_block(&block)?;
        Ok(block)
    }

    pub fn get_best_block_id(&self) -> Result<Id<GenBlock>, PropertyQueryError> {
        self.make_db_tx_ro().get_best_block_id()
    }

    #[allow(dead_code)]
    pub fn get_header_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockHeader>, PropertyQueryError> {
        self.make_db_tx_ro().get_header_from_height(height)
    }

    pub fn get_block_id_from_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, PropertyQueryError> {
        self.make_db_tx_ro()
            .get_block_id_by_height(height)
            .map(|res| res.map(Into::into))
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

    pub fn get_best_block_index(&self) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
        self.make_db_tx_ro().get_best_block_index()
    }

    fn locator_tip_distances() -> impl Iterator<Item = BlockDistance> {
        itertools::iterate(0, |&i| std::cmp::max(1, i * 2)).map(BlockDistance::new)
    }

    pub fn get_locator(&self) -> Result<Locator, PropertyQueryError> {
        let chainstate_ref = self.make_db_tx_ro();
        let best_block_index = chainstate_ref
            .get_best_block_index()?
            .ok_or(PropertyQueryError::BestBlockIndexNotFound)?;
        let height = best_block_index.block_height();

        let headers = Self::locator_tip_distances()
            .map_while(|dist| height - dist)
            .map(|ht| chainstate_ref.get_block_id_by_height(&ht));

        itertools::process_results(headers, |iter| iter.flatten().collect::<Vec<_>>())
            .map(Locator::new)
    }

    pub fn get_block_height_in_main_chain(
        &self,
        id: &Id<GenBlock>,
    ) -> Result<Option<BlockHeight>, PropertyQueryError> {
        self.make_db_tx_ro().get_block_height_in_main_chain(id)
    }

    pub fn get_headers(&self, locator: Locator) -> Result<Vec<BlockHeader>, PropertyQueryError> {
        // use genesis block if no common ancestor with better block height is found
        let chainstate_ref = self.make_db_tx_ro();
        let mut best = BlockHeight::new(0);

        for block_id in locator.iter() {
            if let Some(block_index) = chainstate_ref.get_gen_block_index(block_id)? {
                if chainstate_ref.is_block_in_main_chain(block_id)? {
                    best = block_index.block_height();
                    break;
                }
            }
        }

        // get headers until either the best block or header limit is reached
        let best_height = chainstate_ref
            .get_best_block_index()?
            .expect("best block's height to exist")
            .block_height();

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
        let config = &self.chain_config;
        // verify that the first block attaches to our chain
        if let Some(id) = first_block.prev_block_id().classify(config).chain_block_id() {
            utils::ensure!(
                self.get_block_index(&id)?.is_some(),
                PropertyQueryError::BlockNotFound(id)
            );
        }

        let res = headers
            .into_iter()
            .skip_while(|header| {
                self.get_block_index(&header.get_id()).expect("Database failure").is_some()
            })
            .collect::<Vec<_>>();

        Ok(res)
    }
}

#[cfg(test)]
mod tests;
