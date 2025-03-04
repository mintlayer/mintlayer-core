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

use std::error::Error;

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{
    BlockIndex, ConsumedEpochDataCache, EpochDataCache, GenBlockIndex, PropertyQueryError,
    TipStorageTag,
};
use common::{
    chain::{Block, ChainConfig, GenBlock, GenBlockId},
    primitives::{id::WithId, Id},
};
use orders_accounting::OrdersAccountingDB;
use pos_accounting::PoSAccountingDB;
use thiserror::Error;
use tokens_accounting::TokensAccountingDB;
use tx_verifier::{
    error::ConnectTransactionError, flush_to_storage,
    transaction_verifier::TransactionVerifierDelta, TransactionVerifier,
    TransactionVerifierStorageError,
};
use utils::{ensure, log_error, tap_log::TapLog};
use utxo::UtxosDB;

use crate::{
    ban_score::BanScore, calculate_median_time_past, BlockProcessingErrorClass,
    BlockProcessingErrorClassification, TransactionVerificationStrategy,
};

use super::{epoch_seal, ChainstateRef, EpochSealError};

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    /// Disconnect all blocks from mainchain until the first mainchain ancestor of
    /// the provided block is met and then connect all blocks from the new branch.
    /// All operations are performed via `TransactionVerifier` without db modifications
    /// and the resulting delta is returned.
    #[log_error]
    pub fn reorganize_in_memory(
        &self,
        new_tip: &Id<GenBlock>,
    ) -> Result<(TransactionVerifierDelta, ConsumedEpochDataCache), InMemoryReorgError> {
        let new_chain = match self.get_existing_gen_block_index(new_tip)? {
            GenBlockIndex::Block(block_index) => self.get_new_chain(&block_index)?,
            GenBlockIndex::Genesis(_) => Vec::new(),
        };

        let common_ancestor_id = match new_chain.first() {
            Some(block_index) => block_index.prev_block_id(),
            None => new_tip,
        };

        let (mut tx_verifier, mut epoch_data_cache) = self
            .disconnect_tip_in_memory_until(common_ancestor_id, |_, _, _| {
                Ok::<_, InMemoryReorgError>(true)
            })?;

        // Connect the new chain
        for new_tip_block_index in new_chain {
            let new_tip: WithId<Block> = self
                .get_block_from_index(&new_tip_block_index)?
                .ok_or(InMemoryReorgError::BlockNotFound(
                    (*new_tip_block_index.block_id()).into(),
                ))?
                .into();

            // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
            let median_time_past = calculate_median_time_past(self, &new_tip.prev_block_id());

            let connected_txs = self
                .tx_verification_strategy
                .connect_block(
                    TransactionVerifier::new,
                    &tx_verifier,
                    self.chain_config,
                    &new_tip_block_index,
                    &new_tip,
                    median_time_past,
                )
                .log_err()?
                .consume()?;

            flush_to_storage(&mut tx_verifier, connected_txs)?;

            let pos_db = PoSAccountingDB::new(&tx_verifier);
            epoch_seal::update_epoch_data(
                &mut epoch_data_cache,
                &pos_db,
                self.chain_config,
                epoch_seal::BlockStateEventWithIndex::Connect(
                    new_tip_block_index.block_height(),
                    &new_tip,
                ),
            )?;
        }

        let consumed_verifier = tx_verifier.consume()?;
        let consumed_epoch_data = epoch_data_cache.consume();
        Ok((consumed_verifier, consumed_epoch_data))
    }

    /// Disconnect all blocks from mainchain until the specified block is met and return
    /// the accumulated `TransactionVerifier` and `EpochDataCache`.
    /// On each step, call `step_handler`, passing to it references to block index of the block
    /// that has just been disconnected, the current `TransactionVerifier` and `EpochDataCache`.
    /// If `step_handler` returns false, exit the loop immediately.
    #[log_error]
    pub fn disconnect_tip_in_memory_until<StepHandler, StepHandlerError>(
        &self,
        new_mainchain_tip: &Id<GenBlock>,
        mut step_handler: StepHandler,
    ) -> Result<(TxVerifier<'a, '_, S, V>, EpochDataCache<&S>), InMemoryReorgError>
    where
        StepHandler: FnMut(
            &BlockIndex,
            &TxVerifier<'a, '_, S, V>,
            &EpochDataCache<&S>,
        ) -> Result<bool, StepHandlerError>,
        StepHandlerError: Error + BanScore + BlockProcessingErrorClassification,
    {
        ensure!(
            self.is_block_in_main_chain(new_mainchain_tip)?,
            InMemoryReorgError::MainchainBlockExpected(*new_mainchain_tip)
        );

        let cur_tip = self.get_best_block_id()?;
        let mut tx_verifier = TransactionVerifier::new(self, self.chain_config);
        let mut epoch_data_cache = EpochDataCache::new(&self.db_tx);

        // Disconnect the current chain if it is not a genesis
        if let GenBlockId::Block(cur_tip) = cur_tip.classify(self.chain_config) {
            let cur_tip_index = self.get_existing_block_index(&cur_tip)?;

            let mut next_gen_index_to_disconnect = GenBlockIndex::Block(cur_tip_index);
            while next_gen_index_to_disconnect.block_id() != *new_mainchain_tip {
                let cur_index = match next_gen_index_to_disconnect {
                    GenBlockIndex::Genesis(_) => panic!("Attempt to disconnect genesis"),
                    GenBlockIndex::Block(block_index) => block_index,
                };

                let block = self.get_block_from_index(&cur_index)?.expect("Inconsistent DB");

                // Disconnect transactions
                let cached_inputs = self
                    .tx_verification_strategy
                    .disconnect_block(
                        TransactionVerifier::new,
                        &tx_verifier,
                        self.chain_config,
                        &block.into(),
                    )?
                    .consume()?;

                flush_to_storage(&mut tx_verifier, cached_inputs)?;

                next_gen_index_to_disconnect = self
                    .get_previous_block_index(&cur_index)
                    .expect("Previous block index retrieval failed");

                let pos_db = PoSAccountingDB::new(&tx_verifier);
                epoch_seal::update_epoch_data(
                    &mut epoch_data_cache,
                    &pos_db,
                    self.chain_config,
                    epoch_seal::BlockStateEventWithIndex::Disconnect(
                        next_gen_index_to_disconnect.block_height(),
                    ),
                )?;

                if !step_handler(&cur_index, &tx_verifier, &epoch_data_cache).map_err(|err| {
                    InMemoryReorgError::StepHandlerFailedWhenDisconnectingBlocks {
                        error: err.to_string(),
                        error_class: err.classify(),
                        ban_score: err.ban_score(),
                    }
                })? {
                    break;
                }
            }
        }

        Ok((tx_verifier, epoch_data_cache))
    }
}

type TxVerifier<'a, 'b, S, V> = TransactionVerifier<
    &'a ChainConfig,
    &'b ChainstateRef<'a, S, V>,
    UtxosDB<&'b ChainstateRef<'a, S, V>>,
    PoSAccountingDB<&'b ChainstateRef<'a, S, V>, TipStorageTag>,
    TokensAccountingDB<&'b ChainstateRef<'a, S, V>>,
    OrdersAccountingDB<&'b ChainstateRef<'a, S, V>>,
>;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum InMemoryReorgError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Property query error: {0}")]
    PropertyQueryError(#[from] PropertyQueryError),
    #[error("Failed to update the internal blockchain state: {0}")]
    StateUpdateFailed(#[from] ConnectTransactionError),
    #[error("TransactionVerifier error: {0}")]
    TransactionVerifierError(#[from] TransactionVerifierStorageError),
    #[error("Error during sealing an epoch: {0}")]
    EpochSealError(#[from] EpochSealError),
    #[error("Block {0} not found in the db")]
    BlockNotFound(Id<GenBlock>),
    #[error("The specified block {0} is not on the main chain")]
    MainchainBlockExpected(Id<GenBlock>),
    #[error("Step handler failed when disconnecting blocks: {error}")]
    StepHandlerFailedWhenDisconnectingBlocks {
        error: String,
        error_class: BlockProcessingErrorClass,
        ban_score: u32,
    },
}
