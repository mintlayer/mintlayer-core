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

mod chainstateref;
mod error;
mod info;
mod median_time;
mod orphan_blocks;

pub mod ban_score;
pub mod block_checking;
pub mod block_invalidation;
pub mod bootstrap;
pub mod query;
pub mod tx_verification_strategy;

use std::{collections::VecDeque, sync::Arc};

use itertools::Itertools;
use thiserror::Error;
use utils_networking::broadcaster;

use self::{
    block_invalidation::BlockInvalidator,
    orphan_blocks::{OrphanBlocksMut, OrphansProxy},
    query::ChainstateQuery,
    tx_verification_strategy::TransactionVerificationStrategy,
};
use crate::{ChainstateConfig, ChainstateEvent};
use chainstate_storage::{
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw, Transactional,
};
use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, BlockStatus, BlockValidationStage, EpochData,
    EpochStorageWrite, PropertyQueryError,
};
use chainstateref::{ChainstateRef, ReorgError};
use common::{
    chain::{block::timestamp::BlockTimestamp, config::ChainConfig, Block, GenBlock, TxOutput},
    primitives::{id::WithId, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use pos_accounting::{PoSAccountingDB, PoSAccountingOperations, PoSAccountingUndo};
use tx_verifier::transaction_verifier;
use utils::{
    ensure,
    eventhandler::{EventHandler, EventsController},
    log_error,
    set_flag::SetFlag,
    tap_log::TapLog,
};
use utxo::UtxosDB;

pub use self::{
    error::*, info::ChainInfo, median_time::calculate_median_time_past,
    median_time::calculate_median_time_past_from_blocktimestamps, median_time::MEDIAN_TIME_SPAN,
};
pub use chainstate_types::Locator;
pub use error::{
    BlockError, CheckBlockError, CheckBlockTransactionsError, DbCommittingContext,
    InitializationError, OrphanCheckError, StorageCompatibilityCheckError,
};
pub use orphan_blocks::OrphanBlocksRef;
pub use transaction_verifier::{
    error::{ConnectTransactionError, SpendStakeError, TokenIssuanceError, TokensError},
    storage::TransactionVerifierStorageError,
    IOPolicyError,
};

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
    subsystem_events: EventsController<ChainstateEvent>,
    rpc_events: broadcaster::Broadcaster<ChainstateEvent>,
    time_getter: TimeGetter,
    is_initial_block_download_finished: SetFlag,
}

#[derive(Copy, Clone, Eq, Debug, PartialEq)]
pub enum BlockSource {
    Peer,
    Local,
}

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
    #[allow(dead_code)]
    pub fn wait_for_all_events(&self) {
        self.subsystem_events.wait_for_all_events();
    }

    #[log_error]
    fn make_db_tx<'a>(&'a mut self) -> chainstate_storage::Result<ChainstateRef<TxRw<'a, S>, V>> {
        // Note: this is a workaround for log_error's compilation issues, see log_error docs
        // for details.
        let this = self;
        let db_tx = this.chainstate_storage.transaction_rw(None)?;
        Ok(chainstateref::ChainstateRef::new_rw(
            &this.chain_config,
            &this.chainstate_config,
            &this.tx_verification_strategy,
            db_tx,
            &this.time_getter,
        ))
    }

    #[log_error]
    pub(crate) fn make_db_tx_ro(
        &self,
    ) -> chainstate_storage::Result<ChainstateRef<TxRo<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_ro()?;
        Ok(chainstateref::ChainstateRef::new_ro(
            &self.chain_config,
            &self.chainstate_config,
            &self.tx_verification_strategy,
            db_tx,
            &self.time_getter,
        ))
    }

    #[log_error]
    pub fn query(&self) -> Result<ChainstateQuery<TxRo<'_, S>, V>, PropertyQueryError> {
        self.make_db_tx_ro().map(ChainstateQuery::new).map_err(PropertyQueryError::from)
    }

    pub fn subscribe_to_events(&mut self, handler: ChainstateEventHandler) {
        self.subsystem_events.subscribe_to_events(handler);
    }

    pub fn subscribe_to_event_broadcast(&mut self) -> broadcaster::Receiver<ChainstateEvent> {
        self.rpc_events.subscribe()
    }

    #[log_error]
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_config: ChainstateConfig,
        chainstate_storage: S,
        tx_verification_strategy: V,
        custom_orphan_error_hook: Option<Arc<OrphanErrorHandler>>,
        time_getter: TimeGetter,
    ) -> Result<Self, crate::ChainstateError> {
        use crate::ChainstateError;

        let best_block_id = {
            let db_tx = chainstate_storage
                .transaction_ro()
                .map_err(|e| ChainstateError::FailedToInitializeChainstate(e.into()))?;
            db_tx
                .get_best_block_id()
                .map_err(|e| ChainstateError::FailedToInitializeChainstate(e.into()))?
        };

        let mut chainstate = Self::new_no_genesis(
            chain_config,
            chainstate_config,
            chainstate_storage,
            tx_verification_strategy,
            custom_orphan_error_hook,
            time_getter,
        );

        if best_block_id.is_none() {
            chainstate.process_genesis().map_err(ChainstateError::ProcessBlockError)?;
        } else {
            chainstate.check_genesis().map_err(crate::ChainstateError::from)?;
        }

        chainstate.update_initial_block_download_flag()?;

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
        let subsystem_events = EventsController::new();
        let rpc_events = broadcaster::Broadcaster::new();
        Self {
            chain_config,
            chainstate_config,
            chainstate_storage,
            tx_verification_strategy,
            orphan_blocks,
            custom_orphan_error_hook,
            subsystem_events,
            rpc_events,
            time_getter,
            is_initial_block_download_finished: SetFlag::new(),
        }
    }

    #[log_error]
    fn check_genesis(&self) -> Result<(), InitializationError> {
        let dbtx = self.make_db_tx_ro()?;

        let config_geneis_id = self.chain_config.genesis_block_id();
        if config_geneis_id == dbtx.get_best_block_id()? {
            // Best block is genesis, everything fine
            return Ok(());
        }

        // Look up the parent of block 1 to figure out the genesis ID according to storage
        let block1_id = dbtx
            .get_block_id_by_height(&BlockHeight::new(1))?
            .ok_or(InitializationError::Block1Missing)?;
        let block1 = dbtx
            .get_block(Id::new(block1_id.to_hash()))?
            .ok_or(InitializationError::Block1Missing)?;
        let stored_genesis_id = block1.prev_block_id();

        // Check storage genesis ID matches chain config genesis ID
        ensure!(
            config_geneis_id == stored_genesis_id,
            InitializationError::GenesisMismatch(config_geneis_id, stored_genesis_id),
        );

        Ok(())
    }

    fn broadcast_new_tip_event(&mut self, new_block_index: &Option<BlockIndex>) {
        match new_block_index {
            Some(ref new_block_index) => {
                let new_height = new_block_index.block_height();
                let new_id = *new_block_index.block_id();
                let event = ChainstateEvent::NewTip(new_id, new_height);

                self.rpc_events.broadcast(&event);
                self.subsystem_events.broadcast(event);
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
    #[log_error]
    fn with_rw_tx<MainAction, OnNewAttempt, OnDbCommitErr, Res, Err>(
        &mut self,
        mut main_action: MainAction,
        mut on_new_attempt: OnNewAttempt,
        on_db_commit_err: OnDbCommitErr,
    ) -> Result<Res, Err>
    where
        MainAction: FnMut(&mut ChainstateRef<TxRw<'_, S>, V>) -> Result<Res, Err>,
        OnNewAttempt: FnMut(/*attempt_number:*/ usize),
        OnDbCommitErr: FnOnce(/*attempts_count:*/ usize, chainstate_storage::Error) -> Err,
        Err: From<chainstate_storage::Error> + std::fmt::Display,
    {
        let mut attempts_count = 0;
        loop {
            on_new_attempt(attempts_count);
            attempts_count += 1;

            let mut chainstate_ref = self.make_db_tx().map_err(Err::from)?;
            let result = main_action(&mut chainstate_ref).log_err()?;
            let db_commit_result = chainstate_ref.commit_db_tx();

            match db_commit_result {
                Ok(_) => return Ok(result),
                Err(err) => {
                    if attempts_count >= *self.chainstate_config.max_db_commit_attempts {
                        return Err(on_db_commit_err(attempts_count, err));
                    }
                }
            }
        }
    }

    /// Integrate the block into the blocktree, performing all the necessary checks.
    /// The returned bool indicates whether a reorg has occurred.
    #[log_error]
    fn integrate_block(
        chainstate_ref: &mut ChainstateRef<TxRw<'_, S>, V>,
        block: &WithId<Block>,
        block_index: BlockIndex,
    ) -> Result<bool, BlockIntegrationError> {
        let mut block_status = BlockStatus::new();

        let result = chainstate_ref.check_block(block);
        if result.is_err() {
            // TODO: "technical" errors (e.g. a DB error) should not lead to permanent
            // block invalidation. The same applies to the other unconditional
            // call of "set_validation_failed" below.
            // See https://github.com/mintlayer/mintlayer-core/issues/1033 (item #3).
            block_status.set_validation_failed();
        }

        result
            .map_err(BlockError::CheckBlockFailed)
            .map_err(|err| BlockIntegrationError::OtherValidationError(err, block_status))?;

        block_status.advance_validation_stage_to(BlockValidationStage::CheckBlockOk);
        let block_status = block_status;

        let block_index = block_index.with_status(block_status);
        chainstate_ref
            .set_new_block_index(&block_index)
            .and_then(|_| chainstate_ref.persist_block(block))
            .map_err(|err| BlockIntegrationError::OtherValidationError(err, block_status))?;

        // Note: we don't advance the stage to FullyChecked if activate_best_chain succeeds even
        // if we know that a reorg has occurred, because during a reorg multiple blocks get
        // checked. It's activate_best_chain's responsibility to update their statuses.
        // Likewise, we don't set the failure flag here, because the activation could also fail
        // due to a bad parent. This will be done by the caller code.
        let result = chainstate_ref.activate_best_chain(&block_index);

        chainstate_ref
            .update_min_height_with_allowed_reorg()
            .map_err(BlockIntegrationError::OtherNonValidationError)?;

        result.map_err(|err| match err {
            ReorgError::ConnectTipFailed(block_id, block_err) => {
                BlockIntegrationError::ConnectBlockErrorDuringReorg(
                    block_err,
                    block_status,
                    block_id,
                )
            }
            ReorgError::BlockDataMissing(block_id) => {
                BlockIntegrationError::ConnectBlockErrorDuringReorg(
                    BlockError::BlockDataMissingForValidBlockIndex(block_id),
                    block_status,
                    block_id,
                )
            }
            ReorgError::OtherError(block_err) => {
                BlockIntegrationError::OtherValidationError(block_err, block_status)
            }
        })
    }

    /// Attempt to process the block. On success, return Some(block_index_of_the_passed_block)
    /// if a reorg has occurred and the passed block is now the best block, otherwise return None.
    #[log_error]
    fn attempt_to_process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let block = self.check_legitimate_orphan(block_source, block)?;
        let block_id = block.get_id();

        // Ensure that the block being submitted is new to us. If not, bail out immediately,
        // otherwise create a new block index and continue.
        let block_index = {
            let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from)?;
            let existing_block_index = get_block_index(&chainstate_ref, &block_id)?;

            if let Some(block_index) = existing_block_index {
                return if block_index.status().is_ok() {
                    Err(BlockError::BlockAlreadyProcessed(block_id))
                } else {
                    Err(BlockError::InvalidBlockAlreadyProcessed(block_id))
                };
            }

            chainstate_ref.create_block_index_for_new_block(&block, BlockStatus::new())?
        };

        // Perform block checks; `integrate_block_result` is `Result<bool>`, where the bool
        // indicates whether a reorg has occurred.
        let integrate_block_result = self.with_rw_tx(
            |chainstate_ref| Self::integrate_block(chainstate_ref, &block, block_index.clone()),
            |attempt_number| {
                log::info!("Processing block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockIntegrationError::BlockCommitError(block_id, attempts_count, db_err)
            },
        );

        // Check the result and bail out on success or on a db error.
        // On a validation error, retrieve its data for the next step.
        let (err, status, first_invalid_block_id) = match integrate_block_result {
            Ok(reorg_occurred) => {
                // If the above code has succeeded, then the block_index must be present in the DB.
                // Note that we can't return the initially obtained block_index, because its
                // block status is outdated.
                let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from)?;
                let saved_block_index = get_existing_block_index(&chainstate_ref, &block_id)?;

                assert!(saved_block_index.status().is_ok());
                return Ok(reorg_occurred.then_some(saved_block_index));
            }
            Err(BlockIntegrationError::BlockCommitError(block_id, attempts_count, db_err)) => {
                return Err(BlockError::DbCommitError(
                    attempts_count,
                    db_err,
                    DbCommittingContext::Block(block_id),
                ))
            }
            Err(BlockIntegrationError::OtherNonValidationError(err)) => {
                return Err(err);
            }
            Err(BlockIntegrationError::ConnectBlockErrorDuringReorg(
                err,
                status,
                first_invalid_block_id,
            )) => (err, status, Some(first_invalid_block_id)),
            Err(BlockIntegrationError::OtherValidationError(err, status)) => (err, status, None),
        };

        // Update the block status; note that this is needed even if we're going to call
        // invalidate_stale_block below, because it expects that all block indices
        // already exist (also, it will update this block's status, setting the appropriate
        // failure bit).
        {
            // Note: we already have an error to return, so we ignore the result of
            // the following call.
            let _result = self.with_rw_tx(
                |chainstate_ref| chainstate_ref.update_block_status(block_index.clone(), status),
                |attempt_number| {
                    log::info!("Updating status for block {block_id}, attempt #{attempt_number}");
                },
                |attempts_count, db_err| {
                    BlockError::DbCommitError(
                        attempts_count,
                        db_err,
                        DbCommittingContext::BlockStatus(block_id),
                    )
                },
            );
        }

        if let Some(first_invalid_block_id) = first_invalid_block_id {
            let is_block_in_main_chain = {
                let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from)?;
                is_block_in_main_chain(&chainstate_ref, &first_invalid_block_id.into())?
            };
            assert!(!is_block_in_main_chain);
            // Again, we ignore the result here.
            let _result = BlockInvalidator::new(self)
                .invalidate_block(&first_invalid_block_id, block_invalidation::IsExplicit::No);
        }

        Err(err)
    }

    /// process orphan blocks that depend on the given block, recursively
    #[log_error]
    fn process_orphans_of(
        &mut self,
        block_id: &Id<Block>,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let mut block_indexes = Vec::new();

        let mut orphan_process_queue: VecDeque<_> = vec![*block_id].into();
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

    /// remove orphan blocks that depend on the given block, recursively
    fn remove_orphans_of(&mut self, block_id: &Id<Block>) {
        let mut orphan_process_queue: VecDeque<_> = vec![*block_id].into();
        while let Some(block_id) = orphan_process_queue.pop_front() {
            let orphans = self.orphan_blocks.take_all_children_of(&block_id.into());
            orphan_process_queue.extend(orphans.iter().map(|b| b.get_id()));
        }
    }

    #[log_error]
    fn process_block_and_related_orphans(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        let block_id = block.get_id();

        let result = self.attempt_to_process_block(block, block_source)?;

        let new_block_index_after_orphans = self.process_orphans_of(&block_id)?;

        let result = match new_block_index_after_orphans {
            Some(result_from_orphan) => Some(result_from_orphan),
            None => result,
        };

        self.broadcast_new_tip_event(&result);

        if let Some(ref bi) = result {
            log::info!(
                "New tip in chainstate {} with height {}, timestamp: {} ({})",
                bi.block_id(),
                bi.block_height(),
                bi.block_timestamp(),
                bi.block_timestamp().into_time(),
            );

            self.update_initial_block_download_flag()
                .map_err(BlockError::BestBlockIdQueryError)?;
        }

        Ok(result)
    }

    /// returns the block index of the new tip
    #[log_error]
    pub fn process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        self.process_block_and_related_orphans(block, block_source)
    }

    /// Initialize chainstate with genesis block
    #[log_error]
    pub fn process_genesis(&mut self) -> Result<(), BlockError> {
        // Gather information about genesis.
        let genesis_id = self.chain_config.genesis_block_id();

        // Initialize storage with given info
        let mut db_tx = self.chainstate_storage.transaction_rw(None).map_err(BlockError::from)?;
        db_tx.set_best_block_id(&genesis_id).map_err(BlockError::StorageError)?;
        db_tx
            .set_block_id_at_height(&BlockHeight::zero(), &genesis_id)
            .map_err(BlockError::StorageError)?;

        db_tx
            .set_epoch_data(
                0,
                &EpochData::new(PoSRandomness::new(self.chain_config.initial_randomness())),
            )
            .map_err(BlockError::StorageError)?;

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

    #[log_error]
    fn create_pool_in_storage(
        &self,
        db: &mut impl PoSAccountingOperations<PoSAccountingUndo>,
    ) -> Result<(), BlockError> {
        for output in self.chain_config.genesis_block().utxos().iter() {
            match output {
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_) => { /* do nothing */ }
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

    pub fn chain_config(&self) -> &Arc<ChainConfig> {
        &self.chain_config
    }

    pub fn chainstate_config(&self) -> &ChainstateConfig {
        &self.chainstate_config
    }

    pub fn orphan_blocks_pool(&self) -> &OrphansProxy {
        &self.orphan_blocks
    }

    pub fn subscribers(&self) -> &[EventHandler<ChainstateEvent>] {
        self.subsystem_events.subscribers()
    }

    pub fn is_initial_block_download(&self) -> bool {
        !self.is_initial_block_download_finished.test()
    }

    /// Returns true if the given block timestamp is newer than `ChainstateConfig::max_tip_age`.
    fn is_fresh_block(&self, time: &BlockTimestamp) -> bool {
        let now = self.time_getter.get_time().as_duration_since_epoch();
        time.as_duration_since_epoch()
            .checked_add(self.chainstate_config().max_tip_age.clone().into())
            .map_or(true, |max_tip_time| max_tip_time > now)
    }

    /// Update `is_initial_block_download_finished` when tip changes (can only be set once)
    #[log_error]
    fn update_initial_block_download_flag(&mut self) -> Result<(), PropertyQueryError> {
        if self.is_initial_block_download_finished.test() {
            return Ok(());
        }

        // TODO: Add a check for importing and reindex.

        // TODO: Add a check for the chain trust.

        let tip_timestamp = self.query()?.get_best_block_index()?.block_timestamp();

        if self.is_fresh_block(&tip_timestamp) {
            self.is_initial_block_download_finished.set();
        }

        Ok(())
    }

    #[log_error]
    fn check_legitimate_orphan(
        &mut self,
        block_source: BlockSource,
        block: WithId<Block>,
    ) -> Result<WithId<Block>, OrphanCheckError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(OrphanCheckError::from)?;

        let prev_block_id = block.prev_block_id();

        let block_index_found = chainstate_ref
            .get_gen_block_index(&prev_block_id)
            .map_err(OrphanCheckError::PrevBlockIndexNotFound)?
            .is_some();

        drop(chainstate_ref);

        if block_source == BlockSource::Local && !block_index_found {
            self.new_orphan_block(block)?;
            return Err(OrphanCheckError::LocalOrphan);
        }
        Ok(block)
    }

    /// Mark new block as an orphan
    #[log_error]
    fn new_orphan_block(&mut self, block: WithId<Block>) -> Result<(), OrphanCheckError> {
        match self.orphan_blocks.add_block(block) {
            Ok(_) => Ok(()),
            Err(err) => (*err).into(),
        }
    }
}

/// The error type for integrate_block.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
enum BlockIntegrationError {
    #[error("Reorg error during block integration: {0}; resulting block status is {1}; first bad block id is {2}")]
    ConnectBlockErrorDuringReorg(BlockError, BlockStatus, Id<Block>),
    #[error("Generic error during block integration: {0}; resulting block status is {1}")]
    OtherValidationError(BlockError, BlockStatus),
    #[error("Failed to commit block data for block {0} after {1} attempts: {2}")]
    BlockCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Generic error: {0}")]
    OtherNonValidationError(#[from] BlockError),
}

// This is needed by with_rw_tx
impl From<chainstate_storage::Error> for BlockIntegrationError {
    fn from(error: chainstate_storage::Error) -> Self {
        Self::OtherNonValidationError(BlockError::StorageError(error))
    }
}

#[log_error]
fn get_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<Option<BlockIndex>, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_block_index(block_id)
        .map_err(|err| BlockError::BlockIndexQueryError((*block_id).into(), err))
}

#[log_error]
fn get_existing_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<BlockIndex, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_existing_block_index(block_id)
        .map_err(|err| BlockError::BlockIndexQueryError((*block_id).into(), err))
}

#[log_error]
fn is_block_in_main_chain<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<GenBlock>,
) -> Result<bool, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .is_block_in_main_chain(block_id)
        .map_err(|err| BlockError::IsBlockInMainChainQueryError(*block_id, err))
}

#[cfg(test)]
mod test;
