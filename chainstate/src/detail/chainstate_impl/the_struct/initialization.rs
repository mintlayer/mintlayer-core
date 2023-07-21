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

use std::sync::Arc;

use super::{Chainstate, OrphanErrorHandler};
use crate::{
    detail::orphan_blocks::OrphansProxy, BlockError, ChainstateConfig, InitializationError,
    TransactionVerificationStrategy,
};
use chainstate_storage::{
    BlockchainStorage, BlockchainStorageRead, BlockchainStorageWrite, SealedStorageTag,
    TipStorageTag, TransactionRw,
};
use chainstate_types::{pos_randomness::PoSRandomness, EpochData, EpochStorageWrite};
use common::{
    chain::{ChainConfig, TxOutput},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use pos_accounting::{PoSAccountingDB, PoSAccountingOperations};
use utils::{ensure, eventhandler::EventsController, tap_error_log::LogError};
use utxo::UtxosDB;

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
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

    /// Initialize chainstate with genesis block
    pub(in crate::detail) fn process_genesis(&mut self) -> Result<(), BlockError> {
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
}
