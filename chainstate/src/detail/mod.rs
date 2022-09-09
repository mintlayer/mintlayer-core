// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod ban_score;

pub use self::error::*;
pub use self::median_time::calculate_median_time_past;
pub use chainstate_types::Locator;
use common::time_getter::TimeGetter;
pub use error::BlockError;
pub use error::CheckBlockError;
pub use error::CheckBlockTransactionsError;
pub use error::OrphanCheckError;
pub use transaction_verifier::ConnectTransactionError;

mod block_index_history_iter;
mod chainstateref;
mod error;
mod median_time;
mod orphan_blocks;
pub mod query;
mod transaction_verifier;

use std::sync::Arc;

use itertools::Itertools;

use chainstate_storage::{BlockchainStorage, Transactional};
use chainstate_types::{BlockIndex, GenBlockIndex};
use common::{
    chain::{block::BlockHeader, config::ChainConfig, Block},
    primitives::{id::WithId, BlockDistance, BlockHeight, Id, Idable},
};
use logging::log;
use utils::eventhandler::{EventHandler, EventsController};
use utxo::UtxosDBMut;

use self::{
    orphan_blocks::{OrphanBlocksRef, OrphanBlocksRefMut},
    query::ChainstateQuery,
};
use crate::{detail::orphan_blocks::OrphanBlocksPool, ChainstateConfig, ChainstateEvent};

type TxRw<'a, S> = <S as Transactional<'a>>::TransactionRw;
type TxRo<'a, S> = <S as Transactional<'a>>::TransactionRo;
type ChainstateEventHandler = EventHandler<ChainstateEvent>;

// TODO: move this to some configuration, maybe p2p?
pub const HEADER_LIMIT: BlockDistance = BlockDistance::new(2000);

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;

#[must_use]
pub struct Chainstate<S> {
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: S,
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

impl<S: BlockchainStorage> Chainstate<S> {
    #[allow(dead_code)]
    pub fn wait_for_all_events(&self) {
        self.events_controller.wait_for_all_events();
    }

    #[must_use]
    fn make_db_tx(&mut self) -> chainstateref::ChainstateRef<TxRw<'_, S>, OrphanBlocksRefMut> {
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
    pub(crate) fn make_db_tx_ro(
        &self,
    ) -> chainstateref::ChainstateRef<TxRo<'_, S>, OrphanBlocksRef> {
        let db_tx = self.chainstate_storage.transaction_ro();
        chainstateref::ChainstateRef::new_ro(
            &self.chain_config,
            &self.chainstate_config,
            db_tx,
            self.orphan_blocks.as_ro_ref(),
            self.time_getter.getter(),
        )
    }

    #[must_use]
    pub fn query(&self) -> ChainstateQuery<TxRo<'_, S>, OrphanBlocksRef> {
        ChainstateQuery::new(self.make_db_tx_ro())
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.events_controller.subscribe_to_events(handler);
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_config: ChainstateConfig,
        chainstate_storage: S,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        time_getter: TimeGetter,
    ) -> Result<Self, crate::ChainstateError> {
        use crate::ChainstateError;

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
        chainstate_storage: S,
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
        block: WithId<Block>,
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
        block: WithId<Block>,
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
        block: WithId<Block>,
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

        // initialize the utxo-set by adding genesis outputs to it
        UtxosDBMut::initialize_db(&mut db_tx, &self.chain_config);

        db_tx.commit().expect("Genesis database initialization failed");
        Ok(())
    }

    pub fn preliminary_block_check(
        &self,
        block: WithId<Block>,
    ) -> Result<WithId<Block>, BlockError> {
        let chainstate_ref = self.make_db_tx_ro();
        chainstate_ref.check_block(&block)?;
        Ok(block)
    }

    pub fn preliminary_header_check(&self, block: BlockHeader) -> Result<(), BlockError> {
        let chainstate_ref = self.make_db_tx_ro();
        chainstate_ref.check_block_header(&block)?;
        Ok(())
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    pub fn chainstate_config(&self) -> &ChainstateConfig {
        &self.chainstate_config
    }

    pub fn orphan_blocks_pool(&self) -> &OrphanBlocksPool {
        &self.orphan_blocks
    }

    pub fn events_controller(&self) -> &EventsController<ChainstateEvent> {
        &self.events_controller
    }
}

#[cfg(test)]
mod test;
