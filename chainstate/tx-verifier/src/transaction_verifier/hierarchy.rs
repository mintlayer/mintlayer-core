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

use std::collections::BTreeMap;

use super::{
    cached_operation::CachedInputsOperation,
    storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp},
    TransactionSource, TransactionVerifier,
};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        Block, GenBlock, OutPoint, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::{Amount, Id},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DelegationId, FlushablePoSAccountingView,
    PoSAccountingDeltaData, PoSAccountingView, PoolData, PoolId,
};
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosBlockUndo, UtxosStorageRead, UtxosView};

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A: PoSAccountingView>
    TransactionVerifierStorageRef for TransactionVerifier<C, S, U, A>
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
            None => self.storage.get_token_id_from_issuance_tx(tx_id),
        }
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        self.storage.get_gen_block_index(block_id)
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError> {
        let tx_index_cache = self
            .tx_index_cache
            .as_ref()
            .ok_or(TransactionVerifierStorageError::TransactionIndexDisabled)?;
        match tx_index_cache.get_from_cached(tx_id) {
            Some(v) => match v {
                CachedInputsOperation::Write(idx) => Ok(Some(idx.clone())),
                CachedInputsOperation::Read(idx) => Ok(Some(idx.clone())),
                CachedInputsOperation::Erase => Ok(None),
            },
            None => self.storage.get_mainchain_tx_index(tx_id),
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
            None => self.storage.get_token_aux_data(token_id),
        }
    }

    fn get_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> Result<Option<AccountingBlockUndo>, TransactionVerifierStorageError> {
        match self.accounting_delta_undo.data().get(&TransactionSource::Chain(id)) {
            Some(v) => Ok(Some(v.undo.clone())),
            None => self.storage.get_accounting_undo(id),
        }
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A: PoSAccountingView> UtxosStorageRead
    for TransactionVerifier<C, S, U, A>
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
    ) -> Result<Option<UtxosBlockUndo>, storage_result::Error> {
        match self.utxo_block_undo.data().get(&TransactionSource::Chain(id)) {
            Some(v) => Ok(Some(v.undo.clone())),
            None => self.storage.get_undo_data(id),
        }
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A: PoSAccountingView>
    TransactionVerifierStorageMut for TransactionVerifier<C, S, U, A>
{
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError> {
        let tx_index_cache = self
            .tx_index_cache
            .as_mut()
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
            .tx_index_cache
            .as_mut()
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

    fn set_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &UtxosBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.utxo_block_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(TransactionVerifierStorageError::UtxoBlockUndoError)
    }

    fn del_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.utxo_block_undo
            .del_undo_data(tx_source)
            .map_err(TransactionVerifierStorageError::UtxoBlockUndoError)
    }

    fn set_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &AccountingBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.accounting_delta_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(TransactionVerifierStorageError::AccountingBlockUndoError)
    }

    fn del_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.accounting_delta_undo
            .del_undo_data(tx_source)
            .map_err(TransactionVerifierStorageError::AccountingBlockUndoError)
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A: PoSAccountingView> FlushableUtxoView
    for TransactionVerifier<C, S, U, A>
{
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        self.utxo_cache.batch_write(utxos)
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A: PoSAccountingView> PoSAccountingView
    for TransactionVerifier<C, S, U, A>
{
    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, pos_accounting::Error> {
        self.accounting_delta.pool_exists(pool_id)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, pos_accounting::Error> {
        self.accounting_delta.get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, pos_accounting::Error> {
        self.accounting_delta.get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, pos_accounting::Error> {
        self.accounting_delta.get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, pos_accounting::Error> {
        self.accounting_delta.get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, pos_accounting::Error> {
        self.accounting_delta.get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, pos_accounting::Error> {
        self.accounting_delta.get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<C, S, U, A: PoSAccountingView> FlushablePoSAccountingView for TransactionVerifier<C, S, U, A> {
    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<(), pos_accounting::Error> {
        self.accounting_delta.batch_write_delta(data)
    }
}
