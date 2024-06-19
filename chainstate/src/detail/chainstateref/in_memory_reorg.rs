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
    BlockIndex, ConsumedEpochDataCache, EpochDataCache, GenBlockIndex, InMemoryBlockTreeError,
    PropertyQueryError,
};
use common::{
    chain::{Block, ChainConfig, GenBlock, GenBlockId},
    primitives::{id::WithId, Id},
};
use thiserror::Error;
use tokens_accounting::TokensAccountingDB;
use tx_verifier::{
    error::ConnectTransactionError, flush_to_storage,
    transaction_verifier::TransactionVerifierDelta, TransactionVerifier,
    TransactionVerifierStorageError,
};
use utils::{ensure, iter_utils::zip_clone, log_error, tap_log::TapLog};
use utxo::UtxosDB;

use crate::{
    ban_score::BanScore, calculate_median_time_past,
    detail::in_memory_block_tree::InMemoryBlockTreeNodeId, BlockProcessingErrorClass,
    BlockProcessingErrorClassification, InMemoryBlockTreeRef, TransactionVerificationStrategy,
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
            self.connect_block_in_memory(
                &new_tip_block_index,
                &mut tx_verifier,
                &mut epoch_data_cache,
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

        // Disconnect the current chain if it is not the genesis
        if let GenBlockId::Block(cur_tip) = cur_tip.classify(self.chain_config) {
            let cur_tip_index = self.get_existing_block_index(&cur_tip)?;

            let mut next_gen_index_to_disconnect = GenBlockIndex::Block(cur_tip_index);
            while next_gen_index_to_disconnect.block_id() != *new_mainchain_tip {
                let cur_index = match next_gen_index_to_disconnect {
                    GenBlockIndex::Genesis(_) => panic!("Attempt to disconnect genesis"),
                    GenBlockIndex::Block(block_index) => block_index,
                };

                self.disconnect_block_in_memory(
                    &cur_index,
                    &mut tx_verifier,
                    &mut epoch_data_cache,
                )?;

                if !step_handler(&cur_index, &tx_verifier, &epoch_data_cache)
                    .map_err(convert_step_handler_error)?
                {
                    break;
                }

                next_gen_index_to_disconnect = self.get_previous_block_index(&cur_index)?;
            }
        }

        Ok((tx_verifier, epoch_data_cache))
    }

    fn connect_block_in_memory(
        &self,
        block_index: &BlockIndex,
        tx_verifier: &mut TxVerifier<'a, '_, S, V>,
        epoch_data_cache: &mut EpochDataCache<&S>,
    ) -> Result<(), InMemoryReorgError> {
        let block: WithId<Block> = self
            .get_block_from_index(block_index)?
            .ok_or_else(|| InMemoryReorgError::BlockNotFound(*block_index.block_id()))?
            .into();

        // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
        let median_time_past = calculate_median_time_past(self, &block.prev_block_id());

        let connected_txs = self
            .tx_verification_strategy
            .connect_block(
                TransactionVerifier::new,
                &*tx_verifier,
                self.chain_config,
                block_index,
                &block,
                median_time_past,
            )
            .log_err()?
            .consume()?;

        flush_to_storage(tx_verifier, connected_txs)?;

        epoch_seal::update_epoch_data(
            epoch_data_cache,
            &*tx_verifier,
            self.chain_config,
            epoch_seal::BlockStateEventWithIndex::Connect(block_index.block_height(), &block),
        )?;

        Ok(())
    }

    fn disconnect_block_in_memory(
        &self,
        block_index: &BlockIndex,
        tx_verifier: &mut TxVerifier<'a, '_, S, V>,
        epoch_data_cache: &mut EpochDataCache<&S>,
    ) -> Result<(), InMemoryReorgError> {
        let block = self
            .get_block_from_index(block_index)?
            .ok_or_else(|| InMemoryReorgError::BlockNotFound(*block_index.block_id()))?;

        // Disconnect transactions
        let cached_inputs = self
            .tx_verification_strategy
            .disconnect_block(
                TransactionVerifier::new,
                &*tx_verifier,
                self.chain_config,
                &block.into(),
            )?
            .consume()?;

        flush_to_storage(tx_verifier, cached_inputs)?;

        let prev_height = block_index
            .block_height()
            .prev_height()
            .expect("Non genesis can't have zero height");

        epoch_seal::update_epoch_data(
            epoch_data_cache,
            &*tx_verifier,
            self.chain_config,
            epoch_seal::BlockStateEventWithIndex::Disconnect(prev_height),
        )?;

        Ok(())
    }

    /// Iterate over the passed tree, disconnecting main chain blocks and connecting stale chain
    /// blocks, if any. Call the provided `step_handler` after each step, passing to it the block
    /// index of the current step's "base" block (which is either the parent of the mainchain block
    /// that has just been disconnected, or the stale block that has just been connected).
    /// If the passed index is `None`, this means that the root of the tree has just been
    /// disconnected (which will only happen if disconnect_root is true).
    ///
    /// The passed tree must contain the current mainchain tip.
    #[log_error]
    pub fn iterate_block_tree_and_reorganize_in_memory<'tree, StepHandler, StepHandlerError>(
        &self,
        tree: InMemoryBlockTreeRef<'tree>,
        disconnect_root: bool,
        mut step_handler: StepHandler,
    ) -> Result<(), InMemoryReorgError>
    where
        StepHandler: FnMut(
            Option<&'tree BlockIndex>,
            &TxVerifier<'a, '_, S, V>,
            &EpochDataCache<&S>,
        ) -> Result<(), StepHandlerError>,
        StepHandlerError: Error + BanScore + BlockProcessingErrorClassification,
    {
        // Note: we shouldn't have been able to construct a block tree if genesis is the best block.
        let cur_tip = self
            .get_best_block_id()?
            .classify(self.chain_config())
            .chain_block_id()
            .ok_or(InMemoryReorgError::IterateBlockTreeInvariantErrorBestBlockIsGenesis)?;

        let mut cur_mainchain_node_id = tree
            .find_node_id(&cur_tip)?
            .ok_or(InMemoryReorgError::IterateBlockTreeInvariantErrorMainChainTipNotInTree)?;
        // Node id from the previous iteration.
        let mut prev_mainchain_node_id = None;

        let mut tx_verifier = TransactionVerifier::new(self, self.chain_config);
        let mut epoch_data_cache = EpochDataCache::new(&self.db_tx);

        loop {
            for child_node_id in tree.child_node_ids_iter_for(cur_mainchain_node_id)? {
                if Some(child_node_id) != prev_mainchain_node_id {
                    self.iterate_block_tree_up_stale_chain_and_reorganize_in_memory(
                        tree,
                        child_node_id,
                        tx_verifier.clone(),
                        epoch_data_cache.clone(),
                        &mut step_handler,
                    )?;
                }
            }

            let cur_block_index = tree.get_block_index(cur_mainchain_node_id)?;

            let (parent_node_id, base_block_index) =
                if let Some(parent_node_id) = tree.get_parent(cur_mainchain_node_id)? {
                    let parent_block_index = tree.get_block_index(parent_node_id)?;
                    (Some(parent_node_id), Some(parent_block_index))
                } else if disconnect_root {
                    (None, None)
                } else {
                    break;
                };

            self.disconnect_block_in_memory(
                cur_block_index,
                &mut tx_verifier,
                &mut epoch_data_cache,
            )?;

            step_handler(base_block_index, &tx_verifier, &epoch_data_cache)
                .map_err(convert_step_handler_error)?;

            if let Some(parent_node_id) = parent_node_id {
                prev_mainchain_node_id = Some(cur_mainchain_node_id);
                cur_mainchain_node_id = parent_node_id;
            } else {
                break;
            }
        }

        Ok(())
    }

    #[log_error]
    fn iterate_block_tree_up_stale_chain_and_reorganize_in_memory<
        'tree,
        StepHandler,
        StepHandlerError,
    >(
        &self,
        tree: InMemoryBlockTreeRef<'tree>,
        cur_id: InMemoryBlockTreeNodeId,
        tx_verifier: TxVerifier<'a, '_, S, V>,
        epoch_data_cache: EpochDataCache<&S>,
        step_handler: &mut StepHandler,
    ) -> Result<(), InMemoryReorgError>
    where
        StepHandler: FnMut(
            Option<&'tree BlockIndex>,
            &TxVerifier<'a, '_, S, V>,
            &EpochDataCache<&S>,
        ) -> Result<(), StepHandlerError>,
        StepHandlerError: Error + BanScore + BlockProcessingErrorClassification,
    {
        let mut stack = Vec::new();
        stack.push((cur_id, tx_verifier, epoch_data_cache));

        while let Some((cur_node_id, mut tx_verifier, mut epoch_data_cache)) = stack.pop() {
            let cur_node_block_index = tree.get_block_index(cur_node_id)?;

            // First check if the block has ok status. It makes no sense to try to reorg to a bad block.
            if cur_node_block_index.status().is_ok() {
                // Even if the block status was ok, the block may still be bad (we may have never tried reorging to it),
                let reorg_result = self.connect_block_in_memory(
                    cur_node_block_index,
                    &mut tx_verifier,
                    &mut epoch_data_cache,
                );

                let is_good = match reorg_result {
                    Ok(()) => true,
                    Err(err) => {
                        match err.classify() {
                            // If the block is bad, skip it.
                            // Note: at the time of writing this, it's not possible to get `TemporarilyBadBlock` here.
                            BlockProcessingErrorClass::BadBlock
                            | BlockProcessingErrorClass::TemporarilyBadBlock => false,
                            // If the error is not related to the block itself, return immediately.
                            BlockProcessingErrorClass::General => {
                                return Err(err);
                            }
                        }
                    }
                };

                if is_good {
                    step_handler(Some(cur_node_block_index), &tx_verifier, &epoch_data_cache)
                        .map_err(convert_step_handler_error)?;

                    for (child_id, (tx_verifier, epoch_data_cache)) in zip_clone(
                        tree.child_node_ids_iter_for(cur_node_id)?,
                        (tx_verifier, epoch_data_cache),
                    ) {
                        stack.push((child_id, tx_verifier, epoch_data_cache));
                    }
                }
            }
        }

        Ok(())
    }
}

type TxVerifier<'a, 'b, S, V> = TransactionVerifier<
    &'a ChainConfig,
    &'b ChainstateRef<'a, S, V>,
    UtxosDB<&'b ChainstateRef<'a, S, V>>,
    &'b ChainstateRef<'a, S, V>,
    TokensAccountingDB<&'b ChainstateRef<'a, S, V>>,
>;

fn convert_step_handler_error<StepHandlerError>(err: StepHandlerError) -> InMemoryReorgError
where
    StepHandlerError: Error + BanScore + BlockProcessingErrorClassification,
{
    InMemoryReorgError::StepHandlerFailed {
        error: err.to_string(),
        error_class: err.classify(),
        ban_score: err.ban_score(),
    }
}

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
    BlockNotFound(Id<Block>),
    #[error("The specified block {0} is not on the main chain")]
    MainchainBlockExpected(Id<GenBlock>),
    #[error("Step handler failed: {error}")]
    StepHandlerFailed {
        error: String,
        error_class: BlockProcessingErrorClass,
        ban_score: u32,
    },
    #[error("Invariant error in iterate_block_tree - the best block is the genesis")]
    IterateBlockTreeInvariantErrorBestBlockIsGenesis,
    #[error("Invariant error in iterate_block_tree - the mainchain tip is not in the tree")]
    IterateBlockTreeInvariantErrorMainChainTipNotInTree,
    #[error("In-memory block tree error: {0}")]
    InMemoryBlockTreeError(#[from] InMemoryBlockTreeError),
}
