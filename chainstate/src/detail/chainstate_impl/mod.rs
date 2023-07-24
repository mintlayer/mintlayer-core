// Copyright (c) 2023 RBB S.r.l
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

use std::{collections::VecDeque, sync::Arc};

use itertools::Itertools;
use thiserror::Error;

use self::{
    best_chain_candidates::BestChainCandidates, block_checker::BlockChecker,
    block_invalidator::BlockInvalidator, block_processor::BlockProcessor,
};
use super::{chainstateref::ChainstateRef, orphan_blocks::OrphansProxy, query::ChainstateQuery};
use crate::{
    BlockError, ChainstateConfig, ChainstateEvent, InitializationError,
    TransactionVerificationStrategy,
};
use chainstate_storage::{
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw, Transactional,
};
use chainstate_types::{
    pos_randomness::PoSRandomness, BlockIndex, BlockStatus, EpochData, EpochStorageWrite,
    GenBlockIndex, PropertyQueryError,
};
use common::{
    chain::{
        block::{signed_block_header::SignedBlockHeader, timestamp::BlockTimestamp},
        config::ChainConfig,
        Block, GenBlock, TxOutput,
    },
    primitives::{id::WithId, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
    Uint256,
};
use logging::log;
use pos_accounting::{PoSAccountingDB, PoSAccountingOperations};
use utils::{
    ensure,
    eventhandler::{EventHandler, EventsController},
    tap_error_log::LogError,
};
use utxo::UtxosDB;

mod block_checker;
mod block_invalidator;
mod block_processor;

pub use block_invalidator::best_chain_candidates;

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

    fn make_db_tx(&mut self) -> chainstate_storage::Result<ChainstateRef<TxRw<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_rw(None)?;
        Ok(ChainstateRef::new_rw(
            &self.chain_config,
            &self.chainstate_config,
            &self.tx_verification_strategy,
            db_tx,
            &self.time_getter,
        ))
    }

    pub(crate) fn make_db_tx_ro(
        &self,
    ) -> chainstate_storage::Result<ChainstateRef<TxRo<'_, S>, V>> {
        let db_tx = self.chainstate_storage.transaction_ro()?;
        Ok(ChainstateRef::new_ro(
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

    pub(in crate::detail) fn new_no_genesis(
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
            .get_block(Id::new(block1_id.get()))?
            .ok_or(InitializationError::Block1Missing)?;
        let stored_genesis_id = block1.prev_block_id();

        // Check storage genesis ID matches chain config genesis ID
        ensure!(
            config_geneis_id == stored_genesis_id,
            InitializationError::GenesisMismatch(config_geneis_id, stored_genesis_id),
        );

        Ok(())
    }

    /// Check that transaction index state is consistent between DB and config.
    pub(in crate::detail) fn process_tx_index_enabled_flag(&mut self) -> Result<(), BlockError> {
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
            ensure!(
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
        MainAction: FnMut(&mut ChainstateRef<TxRw<'_, S>, V>) -> Result<Res, Err>,
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

    /// Invalidate the specified block and its descendants.
    pub fn invalidate_block(&mut self, block_id: &Id<Block>) -> Result<(), BlockError> {
        BlockInvalidator::new(self).invalidate_block(block_id)
    }

    /// Reset fail flags in all blocks in the subtree that starts at the specified block.
    pub fn reset_block_failure_flags(&mut self, block_id: &Id<Block>) -> Result<(), BlockError> {
        BlockInvalidator::new(self).reset_block_failure_flags(block_id)
    }

    /// returns the block index of the new tip
    pub fn process_block(
        &mut self,
        block: WithId<Block>,
        block_source: BlockSource,
    ) -> Result<Option<BlockIndex>, BlockError> {
        BlockProcessor::new(self).process_block_and_related_orphans(block, block_source)
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
        BlockChecker::new(self).preliminary_block_check(block)
    }

    pub fn preliminary_header_check(&self, header: SignedBlockHeader) -> Result<(), BlockError> {
        BlockChecker::new(self).preliminary_header_check(header)
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

    pub fn orphan_blocks_pool_mut(&mut self) -> &mut OrphansProxy {
        &mut self.orphan_blocks
    }

    pub fn events_controller(&self) -> &EventsController<ChainstateEvent> {
        &self.events_controller
    }

    pub(super) fn custom_orphan_error_hook(&self) -> &Option<Arc<OrphanErrorHandler>> {
        &self.custom_orphan_error_hook
    }

    pub(super) fn set_is_initial_block_download_finished(&mut self, val: bool) {
        self.is_initial_block_download_finished = val;
    }

    pub fn get_best_chain_candidates(
        &self,
        min_chain_trust: Uint256,
    ) -> Result<BestChainCandidates, BlockError> {
        let chainstate_ref = self.make_db_tx_ro().map_err(BlockError::from).log_err()?;
        Ok(BestChainCandidates::new(&chainstate_ref, min_chain_trust)?)
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

// TODO: move these functions into chainstateref/mod.rs, into an inline submodule
// "block_utils", so that they can be re-used at least there.
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
        .map_err(|err| BlockError::BlockIndexQueryError(err, (*block_id).into()))
}

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
        .map_err(|err| BlockError::BlockIndexQueryError(err, (*block_id).into()))
}

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
        .map_err(|err| BlockError::IsBlockInMainChainQueryError(err, *block_id))
}

fn get_min_height_with_allowed_reorg<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
) -> Result<BlockHeight, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_min_height_with_allowed_reorg()
        .map_err(BlockError::MinHeightForReorgQueryError)
}

fn get_best_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
) -> Result<GenBlockIndex, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_best_block_index()
        .map_err(BlockError::BestBlockIndexQueryError)
}
