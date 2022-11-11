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

use super::{
    cached_operation::CachedInputsOperation,
    storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp},
    BlockUndoEntry, TransactionSource, TransactionVerifier,
};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, GenBlock, OutPoint, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::Id,
};
use utxo::{BlockUndo, ConsumedUtxoCache, FlushableUtxoView, UtxosStorageRead, UtxosView};

impl<'a, S: TransactionVerifierStorageRef, U: UtxosView> TransactionVerifierStorageRef
    for TransactionVerifier<'a, S, U>
{
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        match self.token_issuance_cache.txid_from_issuance().get(&tx_id) {
            Some(v) => match v {
                CachedTokenIndexOp::Write(id) => Ok(Some(*id)),
                CachedTokenIndexOp::Read(id) => Ok(Some(*id)),
                CachedTokenIndexOp::Erase => Ok(None),
            },
            None => self.storage_ref.get_token_id_from_issuance_tx(tx_id),
        }
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        self.storage_ref.get_gen_block_index(block_id)
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError> {
        let tx_index_cache = self
            .get_tx_cache_ref()
            .ok_or(TransactionVerifierStorageError::TransactionIndexDisabled)?;
        match tx_index_cache.get_from_cached(tx_id) {
            Some(v) => match v {
                CachedInputsOperation::Write(idx) => Ok(Some(idx.clone())),
                CachedInputsOperation::Read(idx) => Ok(Some(idx.clone())),
                CachedInputsOperation::Erase => Ok(None),
            },
            None => self.storage_ref.get_mainchain_tx_index(tx_id),
        }
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        match self.token_issuance_cache.data().get(token_id) {
            Some(v) => match v {
                CachedAuxDataOp::Write(t) => Ok(Some(t.clone())),
                CachedAuxDataOp::Read(t) => Ok(Some(t.clone())),
                CachedAuxDataOp::Erase => Ok(None),
            },
            None => self.storage_ref.get_token_aux_data(token_id),
        }
    }
}

impl<'a, S: TransactionVerifierStorageRef, U: UtxosView> UtxosStorageRead
    for TransactionVerifier<'a, S, U>
{
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<utxo::Utxo>, storage_result::Error> {
        Ok(self.utxo_cache.utxo(outpoint))
    }

    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, storage_result::Error> {
        Ok(Some(self.best_block))
    }

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> Result<Option<utxo::BlockUndo>, storage_result::Error> {
        match self.utxo_block_undo.get(&TransactionSource::Chain(id)) {
            Some(v) => Ok(Some(v.undo.clone())),
            None => self.storage_ref.get_undo_data(id),
        }
    }
}

impl<'a, S: TransactionVerifierStorageRef, U: UtxosView> TransactionVerifierStorageMut
    for TransactionVerifier<'a, S, U>
{
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError> {
        let tx_index_cache = self
            .get_tx_cache_mut()
            .ok_or(TransactionVerifierStorageError::TransactionIndexDisabled)?;
        tx_index_cache
            .set_tx_index(tx_id, tx_index.clone())
            .map_err(TransactionVerifierStorageError::TxIndexError)
    }

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), TransactionVerifierStorageError> {
        let tx_index_cache = self
            .get_tx_cache_mut()
            .ok_or(TransactionVerifierStorageError::TransactionIndexDisabled)?;
        tx_index_cache
            .remove_tx_index_by_id(tx_id.clone())
            .map_err(TransactionVerifierStorageError::TxIndexError)
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.token_issuance_cache
            .set_token_aux_data(token_id, data.clone())
            .map_err(TransactionVerifierStorageError::TokensError)
    }

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.token_issuance_cache
            .del_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::TokensError)
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.token_issuance_cache
            .set_token_id(issuance_tx_id, token_id)
            .map_err(TransactionVerifierStorageError::TokensError)
    }

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.token_issuance_cache
            .del_token_id(issuance_tx_id)
            .map_err(TransactionVerifierStorageError::TokensError)
    }

    fn set_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &BlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        match self.utxo_block_undo.entry(tx_source) {
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(BlockUndoEntry {
                    undo: new_undo.clone(),
                    is_fresh: true,
                });
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                e.get_mut().undo.combine(new_undo.clone())?;
            }
        };
        Ok(())
    }

    fn del_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        // delete undo from current cache
        if self.utxo_block_undo.remove(&tx_source).is_none() {
            // if current cache doesn't have such data - insert empty undo to be flushed to the parent
            self.utxo_block_undo.insert(
                tx_source,
                BlockUndoEntry {
                    undo: Default::default(),
                    is_fresh: false,
                },
            );
        }
        Ok(())
    }
}

impl<'a, S: TransactionVerifierStorageRef, U: UtxosView> FlushableUtxoView
    for TransactionVerifier<'a, S, U>
{
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        self.utxo_cache.batch_write(utxos)
    }
}
