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
    cached_inputs_operation::CachedInputsOperation,
    storage::{
        HasTxIndexDisabledError, TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp},
    CachedOperation, TransactionSource, TransactionVerifier,
};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, OutPointSourceId, PoolId,
        Transaction, TxMainChainIndex, UtxoOutPoint,
    },
    primitives::{Amount, Id},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DeltaMergeUndo, FlushablePoSAccountingView,
    PoSAccountingDeltaData, PoSAccountingView, PoolData,
};
use tokens_accounting::{TokensAccountingStorageRead, TokensAccountingView};
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosBlockUndo, UtxosStorageRead, UtxosView};

impl<
        C,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
    > TransactionVerifierStorageRef for TransactionVerifier<C, S, U, A, T>
where
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
{
    type Error = <S as TransactionVerifierStorageRef>::Error;

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, <Self as TransactionVerifierStorageRef>::Error> {
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
    ) -> Result<Option<TxMainChainIndex>, <Self as TransactionVerifierStorageRef>::Error> {
        let tx_index_cache = self.tx_index_cache.as_ref().ok_or_else(|| {
            <<Self as TransactionVerifierStorageRef>::Error>::tx_index_disabled_error()
        })?;
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
    ) -> Result<Option<TokenAuxiliaryData>, <Self as TransactionVerifierStorageRef>::Error> {
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
    ) -> Result<Option<AccountingBlockUndo>, <Self as TransactionVerifierStorageRef>::Error> {
        match self.accounting_block_undo.data().get(&TransactionSource::Chain(id)) {
            Some(v) => Ok(Some(v.undo.clone())),
            None => self.storage.get_accounting_undo(id),
        }
    }

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, <Self as TransactionVerifierStorageRef>::Error> {
        match self.account_nonce.get(&account) {
            Some(op) => match *op {
                CachedOperation::Write(nonce) => Ok(Some(nonce)),
                CachedOperation::Read(nonce) => Ok(Some(nonce)),
                CachedOperation::Erase => Ok(None),
            },
            None => self.storage.get_account_nonce_count(account),
        }
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A, T> UtxosStorageRead
    for TransactionVerifier<C, S, U, A, T>
where
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
{
    type Error = <S as utxo::UtxosStorageRead>::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<utxo::Utxo>, Self::Error> {
        self.utxo_cache.utxo(outpoint).map_err(|e| e.into())
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Self::Error> {
        Ok(self.best_block)
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<UtxosBlockUndo>, Self::Error> {
        match self.utxo_block_undo.data().get(&TransactionSource::Chain(id)) {
            Some(v) => Ok(Some(v.undo.clone())),
            None => self.storage.get_undo_data(id),
        }
    }
}

impl<C, S, U, A, T> TransactionVerifierStorageMut for TransactionVerifier<C, S, U, A, T>
where
    S: TransactionVerifierStorageRef,
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    <S as TransactionVerifierStorageRef>::Error: From<TransactionVerifierStorageError>,
    U: UtxosView,
    A: PoSAccountingView,
    T: TokensAccountingView,
{
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.tx_index_cache
            .as_mut()
            .ok_or(TransactionVerifierStorageError::TransactionIndexDisabled)?
            .set_tx_index(tx_id, tx_index.clone())
            .map_err(|e| TransactionVerifierStorageError::TxIndexError(e).into())
    }

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.tx_index_cache
            .as_mut()
            .ok_or(TransactionVerifierStorageError::TransactionIndexDisabled)?
            .remove_tx_index_by_id(tx_id.clone())
            .map_err(|e| TransactionVerifierStorageError::TxIndexError(e).into())
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.token_issuance_cache
            .set_token_aux_data(token_id, data.clone())
            .map_err(|e| TransactionVerifierStorageError::TokensError(e).into())
    }

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.token_issuance_cache
            .del_token_aux_data(token_id)
            .map_err(|e| TransactionVerifierStorageError::TokensError(e).into())
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.token_issuance_cache
            .set_token_id(issuance_tx_id, token_id)
            .map_err(|e| TransactionVerifierStorageError::TokensError(e).into())
    }

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.token_issuance_cache
            .del_token_id(issuance_tx_id)
            .map_err(|e| TransactionVerifierStorageError::TokensError(e).into())
    }

    fn set_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &UtxosBlockUndo,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.utxo_block_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(|e| TransactionVerifierStorageError::UtxoBlockUndoError(e).into())
    }

    fn del_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.utxo_block_undo
            .del_undo_data(tx_source)
            .map_err(|e| TransactionVerifierStorageError::UtxoBlockUndoError(e).into())
    }

    fn set_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &AccountingBlockUndo,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.accounting_block_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn del_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.accounting_block_undo
            .del_undo_data(tx_source)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn apply_accounting_delta(
        &mut self,
        tx_source: TransactionSource,
        delta: &PoSAccountingDeltaData,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.accounting_delta_adapter
            .apply_accounting_delta(tx_source, delta)
            .map_err(TransactionVerifierStorageError::from)?;
        Ok(())
    }

    fn set_account_nonce_count(
        &mut self,
        account: AccountType,
        nonce: AccountNonce,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.account_nonce.insert(account, CachedOperation::Write(nonce));
        Ok(())
    }

    fn del_account_nonce_count(
        &mut self,
        account: AccountType,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.account_nonce.insert(account, CachedOperation::<AccountNonce>::Erase);
        Ok(())
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A: PoSAccountingView, T> FlushableUtxoView
    for TransactionVerifier<C, S, U, A, T>
{
    type Error = utxo::Error;

    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        self.utxo_cache.batch_write(utxos)
    }
}

impl<
        C,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
    > PoSAccountingView for TransactionVerifier<C, S, U, A, T>
{
    type Error = pos_accounting::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, pos_accounting::Error> {
        self.accounting_delta_adapter.accounting_delta().pool_exists(pool_id)
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        self.accounting_delta_adapter.accounting_delta().get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.accounting_delta_adapter.accounting_delta().get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.accounting_delta_adapter
            .accounting_delta()
            .get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        self.accounting_delta_adapter
            .accounting_delta()
            .get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        self.accounting_delta_adapter
            .accounting_delta()
            .get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.accounting_delta_adapter
            .accounting_delta()
            .get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<C, S, U, A: PoSAccountingView, T> FlushablePoSAccountingView
    for TransactionVerifier<C, S, U, A, T>
{
    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, pos_accounting::Error> {
        self.accounting_delta_adapter.batch_write_delta(data)
    }
}

impl<
        C,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
    > TokensAccountingStorageRead for TransactionVerifier<C, S, U, A, T>
{
    type Error = tokens_accounting::Error;

    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        todo!()
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        todo!()
    }
}
