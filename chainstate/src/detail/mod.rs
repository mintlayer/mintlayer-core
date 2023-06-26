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
pub mod bootstrap;
pub mod query;
pub mod tokens;
pub mod tx_verification_strategy;

mod chainstateref;
mod error;
mod info;
mod median_time;
mod orphan_blocks;

pub use self::{
    error::*, info::ChainInfo, median_time::calculate_median_time_past,
    tokens::is_rfc3986_valid_symbol,
};
pub use chainstate_types::Locator;
pub use error::{
    BlockError, CheckBlockError, CheckBlockTransactionsError, InitializationError, OrphanCheckError,
};

use pos_accounting::{PoSAccountingDB, PoSAccountingOperations};
pub use transaction_verifier::{
    error::{ConnectTransactionError, SpendStakeError, TokensError, TxIndexError},
    storage::TransactionVerifierStorageError,
};
use tx_verifier::transaction_verifier;

use std::{collections::VecDeque, sync::Arc};

use itertools::Itertools;

use chainstate_storage::{
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw, Transactional,
};
use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, BlockStatus, BlockValidationStage, EpochData,
    EpochStorageWrite, PropertyQueryError,
};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp},
        config::ChainConfig,
        Block, TxOutput,
    },
    primitives::{id::WithId, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use utils::{
    eventhandler::{EventHandler, EventsController},
    tap_error_log::LogError,
};
use utxo::UtxosDB;

use self::{
    orphan_blocks::OrphanBlocksMut, orphan_blocks::OrphansProxy, query::ChainstateQuery,
    tx_verification_strategy::TransactionVerificationStrategy,
};
use crate::{ChainstateConfig, ChainstateEvent};
pub use orphan_blocks::OrphanBlocksRef;

type TxRw<'a, S> = <S as Transactional<'a>>::TransactionRw;
type TxRo<'a, S> = <S as Transactional<'a>>::TransactionRo;
type ChainstateEventHandler = EventHandler<ChainstateEvent>;

pub type OrphanErrorHandler = dyn Fn(&BlockError) + Send + Sync;

#[must_use]
pub struct Chainstate<S, V> {
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: S,
    tx_verification_strategy: V,
    orphan_blocks: OrphansProxy,
    custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
    events_controller: EventsController<ChainstateEvent>,
    time_getter: TimeGetter,
    is_initial_block_download_finished: bool,
}

#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub enum BlockSource {
    Peer,
    Local,
}

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
    #[allow(dead_code)]
    pub fn wait_for_all_events(&self) {
        self.events_controller.wait_for_all_events();
    }

    fn make_db_tx(
        &mut self,
    ) -> chainstate_storage::Result<chainstateref::ChainstateRef<TxRw<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_rw(None)?;
        Ok(chainstateref::ChainstateRef::new_rw(
            &self.chain_config,
            &self.chainstate_config,
            &self.tx_verification_strategy,
            db_tx,
            &self.time_getter,
        ))
    }

    pub(crate) fn make_db_tx_ro(
        &self,
    ) -> chainstate_storage::Result<chainstateref::ChainstateRef<TxRo<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_ro()?;
        Ok(chainstateref::ChainstateRef::new_ro(
            &self.chain_config,
            &self.chainstate_config,
            &self.tx_verification_strategy,
            db_tx,
            &self.time_getter,
        ))
    }

    pub fn query(&self) -> Result<ChainstateQuery<TxRo<'_, S>, V>, PropertyQueryError> {
        self.make_db_tx_ro().map(ChainstateQuery::new).map_err(PropertyQueryError::from)
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.events_controller.subscribe_to_events(handler);
    }

    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_config: ChainstateConfig,
        chainstate_storage: S,
        tx_verification_strategy: V,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        time_getter: TimeGetter,
    ) -> Result<Self, crate::ChainstateError> {
        use crate::ChainstateError;

        let best_block_id = chainstate_storage
            .get_best_block_id()
            .map_err(|e| ChainstateError::FailedToInitializeChainstate(e.into()))
            .log_err()?;

        let mut chainstate = Self::new_no_genesis(
            chain_config,
            chainstate_config,
            chainstate_storage,
            tx_verification_strategy,
            custom_orphan_error_hook,
            time_getter,
        );

        chainstate
            .process_tx_index_enabled_flag()
            .map_err(crate::ChainstateError::from)?;

        if best_block_id.is_none() {
            chainstate
                .process_genesis()
                .map_err(ChainstateError::ProcessBlockError)
                .log_err()?;
        } else {
            chainstate.check_genesis().map_err(crate::ChainstateError::from)?;
        }

        Ok(chainstate)
    }

    fn new_no_genesis(
        chain_config: Arc<ChainConfig>,
        chainstate_config: ChainstateConfig,
        chainstate_storage: S,
        tx_verification_strategy: V,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        time_getter: TimeGetter,
    ) -> Self {
        let orphan_blocks = OrphansProxy::new(*chainstate_config.max_orphan_blocks);
        Self {
            chain_config,
            chainstate_config,
            chainstate_storage,
            tx_verification_strategy,
            orphan_blocks,
            custom_orphan_error_hook,
            events_controller: EventsController::new(),
            time_getter,
            is_initial_block_download_finished: false,
        }
    }

    fn check_genesis(&self) -> Result<(), InitializationError> {
        let dbtx = self.make_db_tx_ro()?;

        let config_geneis_id = self.chain_config().genesis_block_id();
        if config_geneis_id == dbtx.get_best_block_id()? {
            // Best block is genesis, everything fine
            return Ok(());
        }

        // Look up the parent of block 1 to figure out the genesis ID according to storage
        let block1_id = dbtx
            .get_block_id_by_height(&BlockHeight::new(1))?
            .ok_or(InitializationError::Block1Missing)?;
        let block1 = dbtx
            .get_block(Id::new(block1_id.get()))?
            .ok_or(InitializationError::Block1Missing)?;
        let stored_genesis_id = block1.prev_block_id();

        // Check storage genesis ID matches chain config genesis ID
        utils::ensure!(
            config_geneis_id == stored_genesis_id,
            InitializationError::GenesisMismatch(config_geneis_id, stored_genesis_id),
        );

        Ok(())
    }

    /// Check that transaction index state is consistent between DB and config.
    fn process_tx_index_enabled_flag(&mut self) -> Result<(), BlockError> {
        let mut db_tx = self
            .chainstate_storage
            .transaction_rw(None)
            .map_err(BlockError::from)
            .log_err()?;

        let tx_index_enabled = db_tx
            .get_is_mainchain_tx_index_enabled()
            .map_err(BlockError::StorageError)
            .log_err()?;

        if let Some(tx_index_enabled) = tx_index_enabled {
            // Make sure DB indexing state is same as in the config.
            // TODO: Allow changing state (creating new or deleting existing index).
            utils::ensure!(
                *self.chainstate_config.tx_index_enabled == tx_index_enabled,
                BlockError::TxIndexConfigError
            );
        } else {
            // First start, enable or disable indexing depending on config.
            db_tx
                .set_is_mainchain_tx_index_enabled(*self.chainstate_config.tx_index_enabled)
                .map_err(BlockError::StorageError)
                .log_err()?;
        }

        db_tx.commit().expect("Set tx indexing failed");

        Ok(())
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

    /// Create a read-write transaction, call `main_action` on it and commit.
    /// If committing fails, repeat the whole process again until it succeeds or
    /// the maximum number of commit attempts is reached.
    /// If the maximum number of attempts is reached, use `on_db_err` to create
    /// a BlockError and return it.
    /// On each iteration, before doing anything else, call `on_new_attempt`
    /// (this can be used for logging).
    fn with_rw_tx<MainAction, OnNewAttempt, OnDbErr, Res>(
        &mut self,
        mut main_action: MainAction,
        mut on_new_attempt: OnNewAttempt,
        on_db_err: OnDbErr,
    ) -> Result<Res, BlockError>
    where
        MainAction:
            FnMut(&mut chainstateref::ChainstateRef<TxRw<'_, S>, V>) -> Result<Res, BlockError>,
        OnNewAttempt: FnMut(/*attempt_number:*/ usize),
        OnDbErr: FnOnce(/*attempts_count:*/ usize, chainstate_storage::Error) -> BlockError,
    {
        let mut attempts_count = 0;
        loop {
            on_new_attempt(attempts_count);
            attempts_count += 1;

            let mut chainstate_ref = self.make_db_tx().map_err(BlockError::from).log_err()?;
            let result = main_action(&mut chainstate_ref).log_err()?;
            let db_commit_result = chainstate_ref.commit_db_tx().log_err();

            match db_commit_result {
                Ok(_) => return Ok(result),
                Err(err) => {
                    if attempts_count >= *self.chainstate_config.max_db_commit_attempts {
                        return Err(on_db_err(attempts_count, err));
                    }
                }
            }
        }
    }

    /// This is similar to `with_rw_tx_for_block_id`, but it also maintains a mutable state that
    /// is passed to `func` and then returned to the caller.
    /// Note that the state is reset to `initial_state` on each commit attempt and the returned
    /// state is the one from the last commit attempt.
    fn with_rw_tx_and_state<State, MainAction, OnNewAttempt, OnDbErr, Res>(
        &mut self,
        initial_state: &State,
        mut main_action: MainAction,
        on_new_attempt: OnNewAttempt,
        on_db_err: OnDbErr,
    ) -> (State, Result<Res, BlockError>)
    where
        State: Clone,
        MainAction: FnMut(
            &mut chainstateref::ChainstateRef<TxRw<'_, S>, V>,
            &mut State,
        ) -> Result<Res, BlockError>,
        OnNewAttempt: FnMut(/*attempt_number:*/ usize),
        OnDbErr: FnOnce(/*attempts_count:*/ usize, chainstate_storage::Error) -> BlockError,
    {
        // Note: the purpose of the Option here is just to get rid of extra clone at the beginning.
        let mut state = None;

        let result = self.with_rw_tx(
            |chainstate_ref| main_action(chainstate_ref, state.insert(initial_state.clone())),
            on_new_attempt,
            on_db_err,
        );

        // Note: this "or_else" part is only possible in the degenerate case where with_rw_tx
        // doesn't invoke the closure even once.
        let state = state.unwrap_or_else(|| initial_state.clone());
        (state, result)
    }

    /// Integrate the block into the blocktree, performing all the necessary checks and
    /// updating `block_status` after each successful check.
    /// The returned bool indicates whether a reorg has occurred.
    fn integrate_block(
        chainstate_ref: &mut chainstateref::ChainstateRef<TxRw<'_, S>, V>,
        block: &WithId<Block>,
        block_index: &BlockIndex,
        block_status: &mut BlockStatus,
    ) -> Result<bool, BlockError> {
        // Note: at this moment check_block_parent is also performed inside check_block.
        // The only purpose of doing it here as well is to be able to distinguish the situation
        // when the parent is bad from other check_block failures.
        // Also note that we can't just check the result of check_block, see if it's not
        // InvalidParent and advance the stage to ParentOk if that's so, because this
        // will only be correct if the parent validity check is the first check in check_block
        // (which technically is true, but such a dependency will be very fragile).
        // FIXME: but do we need ParentOk as a separate stage at all? If yes, then probably
        // check_block should maintain the status itself (and then it can be as fine-grained
        // as we want), otherwise it's better to remove it.
        chainstate_ref.check_block_parent(block.header())?;
        block_status.advance_validation_stage_to(BlockValidationStage::ParentOk);

        chainstate_ref.check_block(block).map_err(BlockError::CheckBlockFailed)?;
        block_status.advance_validation_stage_to(BlockValidationStage::CheckBlockOk);

        // Note: we have to persist BlockIndex too, because it will be used
        // by activate_best_chain below. There is no point in saving
        // an intermediate BlockStatus though, so we ignore block_status here.
        chainstate_ref.set_new_block_index(block_index)?;
        chainstate_ref.persist_block(block)?;

        let best_block_id =
            chainstate_ref.get_best_block_id().map_err(BlockError::BestBlockLoadError)?;

        let reorg_occurred = chainstate_ref.activate_best_chain(block_index, &best_block_id)?;
        block_status.advance_validation_stage_to(BlockValidationStage::FullyChecked);

        Ok(reorg_occurred)
    }

    // Attempt to process the block. On success, return Some(block_index_of_the_passed_block)
    // if a reorg has occurred and the passed block is now the best block, otherwise return None.
    fn attempt_to_process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let block = self.check_legitimate_orphan(block_source, block).log_err()?;
        let block_id = block.get_id();

        // Ensure that the block being submitted is new to us. If not, bail out immediately,
        // otherwise create a new block index and continue.
        let block_index = {
            let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
            let existing_block_index = chainstate_ref
                .get_block_index(&block_id)
                .map_err(BlockError::BlockLoadError)
                .log_err()?;

            if let Some(block_index) = existing_block_index {
                return if block_index.status().is_valid() {
                    Err(BlockError::BlockAlreadyProcessed(block_id))
                } else {
                    Err(BlockError::InvalidBlockAlreadyProcessed(block_id))
                };
            }

            chainstate_ref.new_block_index(&block, BlockStatus::new()).log_err()?
        };

        // Perform block checks; `check_result` is `Result<bool>`, where the bool indicates
        // whether a reorg has occurred.
        let (block_status, check_result) = self.with_rw_tx_and_state(
            &BlockStatus::new(),
            |chainstate_ref, block_status| {
                Self::integrate_block(chainstate_ref, &block, &block_index, block_status)
            },
            |attempt_number| {
                log::info!("Processing block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| BlockError::BlockCommitError(block_id, attempts_count, db_err),
        );

        if let Err(err @ BlockError::BlockCommitError(_, _, _)) = check_result {
            // If we got here, then the block checks have succeeded, but the DB has failed.
            // Attempts to save the new status in BlockIndex in this situation will
            // probably fail too. Moreover, even if we succeed, we'll get a strange situation
            // where there is a BlockIndex in the DB with a "fully checked" status, but the
            // block itself is missing. So we bail out in this case.
            return Err(err);
        }

        let block_index = block_index.with_status(block_status);

        // Update block index status.
        let status_update_result = self.with_rw_tx(
            |chainstate_ref| chainstate_ref.set_block_status(&block_index),
            |attempt_number| {
                log::info!("Updating status for block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockError::BlockStatusCommitError(block_id, attempts_count, db_err)
            },
        );

        // If both block validation and block index update failed, we want to return the first
        // error, so we check it first.
        let result = check_result?.then_some(block_index);
        status_update_result?;
        Ok(result)
    }

    /// process orphan blocks that depend on the given block, recursively
    fn process_orphans_of(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut block_indexes = Vec::new();

        let mut orphan_process_queue: VecDeque<_> = vec![block_id].into();
        while let Some(block_id) = orphan_process_queue.pop_front() {
            let orphans = self.orphan_blocks.take_all_children_of(&block_id.into());
            // whatever was pulled from orphans should be processed next in the queue
            orphan_process_queue.extend(orphans.iter().map(|b| b.get_id()));
            let (orphan_block_indexes, block_errors): (Vec<Option<BlockIndex>>, Vec<BlockError>) =
                orphans
                    .into_iter()
                    .map(|blk| self.attempt_to_process_block(blk, BlockSource::Local))
                    .partition_result();

            block_indexes.extend(orphan_block_indexes.into_iter());

            block_errors.into_iter().for_each(|e| match &self.custom_orphan_error_hook {
                Some(handler) => handler(&e),
                None => logging::log::error!("Failed to process a chain of orphan blocks: {}", e),
            });
        }

        // since we processed blocks in order, the last one is the tip
        let new_block_index_after_orphans = block_indexes.into_iter().flatten().next_back();

        Ok(new_block_index_after_orphans)
    }

    fn process_block_and_related_orphans(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let block_id = block.get_id();

        let result = self.attempt_to_process_block(block, block_source)?;

        let new_block_index_after_orphans = self.process_orphans_of(block_id)?;

        let result = match new_block_index_after_orphans {
            Some(result_from_orphan) => Some(result_from_orphan),
            None => result,
        };

        self.broadcast_new_tip_event(&result);

        if let Some(ref bi) = result {
            log::info!(
                "New tip in chainstate {} with height {}, timestamp: {}",
                bi.block_id(),
                bi.block_height(),
                bi.block_timestamp(),
            );

            self.is_initial_block_download_finished = self.is_fresh_block(&bi.block_timestamp());
        }

        Ok(result)
    }

    /// returns the block index of the new tip
    pub fn process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        self.process_block_and_related_orphans(block, block_source)
    }

    /// Initialize chainstate with genesis block
    pub fn process_genesis(&mut self) -> Result<(), BlockError> {
        // Gather information about genesis.
        let genesis = self.chain_config.genesis_block();
        let genesis_id = self.chain_config.genesis_block_id();
        let utxo_count = genesis.utxos().len() as u32;
        let genesis_index = common::chain::TxMainChainIndex::new(genesis_id.into(), utxo_count)
            .expect("Genesis not constructed correctly");

        // Initialize storage with given info
        let mut db_tx = self
            .chainstate_storage
            .transaction_rw(None)
            .map_err(BlockError::from)
            .log_err()?;
        db_tx
            .set_best_block_id(&genesis_id)
            .map_err(BlockError::StorageError)
            .log_err()?;
        db_tx
            .set_block_id_at_height(&BlockHeight::zero(), &genesis_id)
            .map_err(BlockError::StorageError)
            .log_err()?;

        if *self.chainstate_config.tx_index_enabled {
            db_tx
                .set_mainchain_tx_index(&genesis_id.into(), &genesis_index)
                .map_err(BlockError::StorageError)
                .log_err()?;
        }

        db_tx
            .set_epoch_data(
                0,
                &EpochData::new(PoSRandomness::new(self.chain_config.initial_randomness())),
            )
            .map_err(BlockError::StorageError)
            .log_err()?;

        // initialize the utxo-set by adding genesis outputs to it
        UtxosDB::initialize_db(&mut db_tx, &self.chain_config);

        // initialize the pos accounting db by adding genesis pool to it
        let mut pos_db_tip = PoSAccountingDB::<_, TipStorageTag>::new(&mut db_tx);
        self.create_pool_in_storage(&mut pos_db_tip)?;
        let mut pos_db_sealed = PoSAccountingDB::<_, SealedStorageTag>::new(&mut db_tx);
        self.create_pool_in_storage(&mut pos_db_sealed)?;

        db_tx.commit().expect("Genesis database initialization failed");
        Ok(())
    }

    fn create_pool_in_storage(
        &self,
        db: &mut impl PoSAccountingOperations,
    ) -> Result<(), BlockError> {
        for output in self.chain_config.genesis_block().utxos().iter() {
            match output {
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _) => { /* do nothing */ }
                | TxOutput::CreateStakePool(pool_id, data) => {
                    let _ = db
                        .create_pool(*pool_id, data.as_ref().clone().into())
                        .map_err(BlockError::PoSAccountingError)
                        .log_err()?;
                }
            };
        }
        Ok(())
    }

    pub fn preliminary_block_check(
        &self,
        block: WithId<Block>,
    ) -> Result<WithId<Block>, BlockError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from)?;

        chainstate_ref.check_block(&block).log_err()?;

        Ok(block)
    }

    pub fn preliminary_header_check(&self, header: SignedBlockHeader) -> Result<(), BlockError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from)?;
        chainstate_ref.check_block_header(&header).log_err()?;
        Ok(())
    }

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    pub fn chainstate_config(&self) -> &ChainstateConfig {
        &self.chainstate_config
    }

    pub fn orphan_blocks_pool(&self) -> &OrphansProxy {
        &self.orphan_blocks
    }

    pub fn events_controller(&self) -> &EventsController<ChainstateEvent> {
        &self.events_controller
    }

    pub fn is_initial_block_download(&self) -> Result<bool, PropertyQueryError> {
        if self.is_initial_block_download_finished {
            return Ok(false);
        }

        // TODO: Add a check for importing and reindex.

        // TODO: Add a check for the chain trust.

        let tip_timestamp = match self.query()?.get_best_block_header() {
            Ok(h) => Ok(h.timestamp()),
            // There is only the genesis block, so the initial block download isn't finished yet.
            Err(PropertyQueryError::GenesisHeaderRequested) => return Ok(true),
            Err(e) => Err(e),
        }?;
        Ok(!self.is_fresh_block(&tip_timestamp))
    }

    /// Returns true if the given block timestamp is newer than `ChainstateConfig::max_tip_age`.
    fn is_fresh_block(&self, time: &BlockTimestamp) -> bool {
        let now = self.time_getter.get_time();
        time.as_duration_since_epoch() + self.chainstate_config.max_tip_age.clone().into() > now
    }

    fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: WithId<Block>,
    ) -> Result<WithId<Block>, OrphanCheckError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(OrphanCheckError::from)?;

        let prev_block_id = block.prev_block_id();

        let block_index_found = chainstate_ref
            .get_gen_block_index(&prev_block_id)
            .map_err(OrphanCheckError::PrevBlockIndexNotFound)
            .log_err()?
            .is_some();

        drop(chainstate_ref);

        if block_source == BlockSource::Local && !block_index_found {
            self.new_orphan_block(block).log_err()?;
            return Err(OrphanCheckError::LocalOrphan);
        }
        Ok(block)
    }

    /// Mark new block as an orphan
    fn new_orphan_block(&mut self, block: WithId<Block>) -> Result<(), OrphanCheckError> {
        match self.orphan_blocks.add_block(block) {
            Ok(_) => Ok(()),
            Err(err) => (*err).into(),
        }
    }
}

#[cfg(test)]
mod test;
