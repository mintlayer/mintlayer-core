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
    error::*,
    info::ChainInfo,
    median_time::calculate_median_time_past,
    tokens::{check_nft_issuance_data, check_tokens_issuance_data, is_rfc3986_valid_symbol},
};
pub use chainstate_types::Locator;
pub use error::{
    BlockError, CheckBlockError, CheckBlockTransactionsError, DbCommittingContext,
    InitializationError, OrphanCheckError, StorageCompatibilityCheckError,
};

use pos_accounting::{PoSAccountingDB, PoSAccountingOperations};
pub use transaction_verifier::{
    error::{
        ConnectTransactionError, SpendStakeError, TokenIssuanceError, TokensError, TxIndexError,
    },
    storage::TransactionVerifierStorageError,
    IOPolicyError,
};
use tx_verifier::transaction_verifier;

use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};

use itertools::Itertools;
use thiserror::Error;

use chainstate_storage::{
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw, Transactional,
};
use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, BlockStatus, BlockValidationStage, EpochData,
    EpochStorageWrite, PropertyQueryError,
};
use chainstateref::ReorgError;
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
    fn with_rw_tx<MainAction, OnNewAttempt, OnDbCommitErr, Res, Err>(
        &mut self,
        mut main_action: MainAction,
        mut on_new_attempt: OnNewAttempt,
        on_db_commit_err: OnDbCommitErr,
    ) -> Result<Res, Err>
    where
        MainAction: FnMut(&mut chainstateref::ChainstateRef<TxRw<'_, S>, V>) -> Result<Res, Err>,
        OnNewAttempt: FnMut(/*attempt_number:*/ usize),
        OnDbCommitErr: FnOnce(/*attempts_count:*/ usize, chainstate_storage::Error) -> Err,
        Err: From<chainstate_storage::Error> + std::fmt::Display,
    {
        let mut attempts_count = 0;
        loop {
            on_new_attempt(attempts_count);
            attempts_count += 1;

            let mut chainstate_ref = self.make_db_tx().map_err(Err::from).log_err()?;
            let result = main_action(&mut chainstate_ref).log_err()?;
            let db_commit_result = chainstate_ref.commit_db_tx().log_err();

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
    fn integrate_block(
        chainstate_ref: &mut chainstateref::ChainstateRef<TxRw<'_, S>, V>,
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

        let block_index = block_index.with_status(block_status);
        chainstate_ref
            .set_new_block_index(&block_index)
            .and_then(|_| chainstate_ref.persist_block(block))
            .map_err(|err| BlockIntegrationError::OtherValidationError(err, block_status))?;

        // Note: we don't advance the stage to FullyChecked if activate_best_chain succeeds even
        // if we know that a reorg has occurred, because during a reorg multiple blocks get
        // checked. It's activate_best_chain's responsibility to update their statuses.
        chainstate_ref.activate_best_chain(&block_index).map_err(|err| match err {
            ReorgError::ConnectBlockError(block_id, block_err) => {
                block_status.set_validation_failed();
                BlockIntegrationError::ConnectBlockErrorDuringReorg(
                    block_err,
                    block_status,
                    block_id,
                )
            }
            ReorgError::OtherError(block_err) => {
                BlockIntegrationError::OtherValidationError(block_err, block_status)
            }
        })
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
            let existing_block_index = get_block_index(&chainstate_ref, &block_id).log_err()?;

            if let Some(block_index) = existing_block_index {
                return if block_index.status().is_ok() {
                    Err(BlockError::BlockAlreadyProcessed(block_id))
                } else {
                    Err(BlockError::InvalidBlockAlreadyProcessed(block_id))
                };
            }

            chainstate_ref
                .create_block_index_for_new_block(&block, BlockStatus::new())
                .log_err()?
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
                let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
                let saved_block_index =
                    get_existing_block_index(&chainstate_ref, &block_id).log_err()?;

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
            Err(BlockIntegrationError::OtherDbError(db_err)) => {
                return Err(BlockError::StorageError(db_err));
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
        // already exist (also, it will update this block's status, indicating that it has
        // a bad parent).
        {
            let block_index = block_index.with_status(status);
            // Note: we already have an error to return, so we ignore the result of
            // the following call.
            let _result = self
                .with_rw_tx(
                    |chainstate_ref| chainstate_ref.set_block_status(&block_index),
                    |attempt_number| {
                        log::info!(
                            "Updating status for block {block_id}, attempt #{attempt_number}"
                        );
                    },
                    |attempts_count, db_err| {
                        BlockError::DbCommitError(
                            attempts_count,
                            db_err,
                            DbCommittingContext::BlockStatus(block_id),
                        )
                    },
                )
                .log_err();
        }

        if let Some(first_invalid_block_id) = first_invalid_block_id {
            // Again, we ignore the result here.
            let _result = self.invalidate_stale_block(&first_invalid_block_id).log_err();
        }

        Err(err)
    }

    fn invalidate_stale_block(&mut self, block_id: &Id<Block>) -> Result<(), BlockError> {
        let block_indices_to_invalidate = {
            let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
            assert!(!chainstate_ref
                .is_block_in_main_chain(&(*block_id).into())
                .map_err(|err| BlockError::IsBlockInMainChainQueryError(err, (*block_id).into()))
                .log_err()?);

            let block_index = get_existing_block_index(&chainstate_ref, block_id).log_err()?;
            let next_block_height = block_index.block_height().next_height();

            // TODO: get_block_id_tree_top_as_list here is an expensive call, because
            // under the hood it'll iterate over all block indices in the DB.
            let maybe_descendant_block_ids = chainstate_ref
                .get_block_id_tree_top_as_list(next_block_height)
                .map_err(|err| BlockError::BlockIdTreeTopQueryError(err, next_block_height))?;

            let mut block_indices_to_invalidate = Vec::new();
            let mut seen_invalid_block_ids = BTreeSet::new();
            block_indices_to_invalidate.push(block_index);
            seen_invalid_block_ids.insert(*block_id);

            for cur_block_id in maybe_descendant_block_ids {
                let block_index =
                    get_existing_block_index(&chainstate_ref, &cur_block_id).log_err()?;
                let prev_block_id = block_index
                    .prev_block_id()
                    .classify(&self.chain_config)
                    .chain_block_id()
                    .expect("Genesis at non-zero height");

                if seen_invalid_block_ids.contains(&prev_block_id) {
                    block_indices_to_invalidate.push(block_index);
                    seen_invalid_block_ids.insert(cur_block_id);
                }
            }

            block_indices_to_invalidate
        };

        self.with_rw_tx(
            |chainstate_ref| {
                for (i, block_index) in block_indices_to_invalidate.iter().enumerate() {
                    let mut status = block_index.status();
                    if i == 0 {
                        status.set_validation_failed()
                    } else {
                        status.set_has_invalid_parent();
                    }

                    let block_index = block_index.clone().with_status(status);
                    chainstate_ref.set_block_index(&block_index)?;
                }

                Ok(())
            },
            |attempt_number| {
                log::info!("Invalidating block {block_id}, attempt #{attempt_number}");
            },
            |attempts_count, db_err| {
                BlockError::DbCommitError(
                    attempts_count,
                    db_err,
                    DbCommittingContext::InvalidatedBlockStatuses,
                )
            },
        )
        .log_err()?;

        self.remove_orphans_of(block_id);

        Ok(())
    }

    /// process orphan blocks that depend on the given block, recursively
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

#[derive(Error, Debug, PartialEq, Eq, Clone)]
enum BlockIntegrationError {
    #[error("Reorg error during block integration: {0}; resulting block status is {1}; first bad block id is {2}")]
    ConnectBlockErrorDuringReorg(BlockError, BlockStatus, Id<Block>),
    #[error("Generic error during block integration: {0}; resulting block status is {1}")]
    OtherValidationError(BlockError, BlockStatus),
    #[error("Failed to commit block data for block {0} after {1} attempts: {2}")]
    BlockCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Database error: {0}")]
    OtherDbError(#[from] chainstate_storage::Error),
}

fn get_block_index<S, V>(
    chainstate_ref: &chainstateref::ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<Option<BlockIndex>, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_block_index(block_id)
        .map_err(|err| BlockError::BlockIndexQueryError(err, (*block_id).into()))
}

fn get_existing_block_index<S, V>(
    chainstate_ref: &chainstateref::ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<BlockIndex, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    get_block_index(chainstate_ref, block_id)?.ok_or(BlockError::InvariantErrorBlockIndexNotFound(
        (*block_id).into(),
    ))
}

#[cfg(test)]
mod test;
