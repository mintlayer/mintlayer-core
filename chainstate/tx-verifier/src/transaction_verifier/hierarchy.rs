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
    accounting_undo_cache::CachedBlockUndo,
    storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    token_issuance_cache::{CachedAuxDataOp, CachedTokenIndexOp},
    utxos_undo_cache::CachedUtxosBlockUndo,
    CachedOperation, TransactionSource, TransactionVerifier,
};
use chainstate_types::{storage_result, GenBlockIndex, TipStorageTag};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, DelegationId, GenBlock, OrderId, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{Amount, Id},
};
use orders_accounting::{
    FlushableOrdersAccountingView, OrderData, OrdersAccountingDeltaData,
    OrdersAccountingDeltaUndoData, OrdersAccountingStorageRead, OrdersAccountingUndo,
    OrdersAccountingView,
};
use pos_accounting::{
    DelegationData, DeltaMergeUndo, FlushablePoSAccountingView, PoSAccountingDeltaData,
    PoSAccountingStorageRead, PoSAccountingUndo, PoSAccountingView, PoolData,
};
use tokens_accounting::{
    FlushableTokensAccountingView, TokenAccountingUndo, TokensAccountingDeltaData,
    TokensAccountingDeltaUndoData, TokensAccountingStorageRead, TokensAccountingView,
};
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosStorageRead, UtxosView};

impl<
        C,
        S: TransactionVerifierStorageRef,
        U: UtxosView,
        A: PoSAccountingView,
        T: TokensAccountingView,
        O: OrdersAccountingView,
    > TransactionVerifierStorageRef for TransactionVerifier<C, S, U, A, T, O>
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

    fn get_undo_data(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedUtxosBlockUndo>, <Self as TransactionVerifierStorageRef>::Error> {
        match self.utxo_block_undo.data().get(&tx_source) {
            Some(op) => Ok(op.get().cloned()),
            None => self.storage.get_undo_data(tx_source),
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

    fn get_pos_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<
        Option<CachedBlockUndo<PoSAccountingUndo>>,
        <Self as TransactionVerifierStorageRef>::Error,
    > {
        match self.pos_accounting_block_undo.data().get(&tx_source) {
            Some(op) => Ok(op.get().cloned()),
            None => self.storage.get_pos_accounting_undo(tx_source),
        }
    }

    fn get_tokens_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<
        Option<CachedBlockUndo<TokenAccountingUndo>>,
        <Self as TransactionVerifierStorageRef>::Error,
    > {
        match self.tokens_accounting_block_undo.data().get(&tx_source) {
            Some(op) => Ok(op.get().cloned()),
            None => self.storage.get_tokens_accounting_undo(tx_source),
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

    fn get_orders_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<
        Option<CachedBlockUndo<OrdersAccountingUndo>>,
        <Self as TransactionVerifierStorageRef>::Error,
    > {
        match self.orders_accounting_block_undo.data().get(&tx_source) {
            Some(op) => Ok(op.get().cloned()),
            None => self.storage.get_orders_accounting_undo(tx_source),
        }
    }
}

impl<C, S: TransactionVerifierStorageRef, U: UtxosView, A, T, O> UtxosStorageRead
    for TransactionVerifier<C, S, U, A, T, O>
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
}

impl<C, S, U, A, T, O> TransactionVerifierStorageMut for TransactionVerifier<C, S, U, A, T, O>
where
    S: TransactionVerifierStorageRef,
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
    <S as TransactionVerifierStorageRef>::Error: From<TransactionVerifierStorageError>,
    U: UtxosView,
    A: PoSAccountingView,
    T: TokensAccountingView,
    O: OrdersAccountingView,
{
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
        new_undo: &CachedUtxosBlockUndo,
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

    fn set_pos_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &CachedBlockUndo<PoSAccountingUndo>,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.pos_accounting_block_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn del_pos_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.pos_accounting_block_undo
            .del_undo_data(tx_source)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn apply_accounting_delta(
        &mut self,
        tx_source: TransactionSource,
        delta: &PoSAccountingDeltaData,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.pos_accounting_adapter.apply_accounting_delta(tx_source, delta)?;
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

    fn set_tokens_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &CachedBlockUndo<TokenAccountingUndo>,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.tokens_accounting_block_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn del_tokens_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.tokens_accounting_block_undo
            .del_undo_data(tx_source)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn set_orders_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &CachedBlockUndo<OrdersAccountingUndo>,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.orders_accounting_block_undo
            .set_undo_data(tx_source, new_undo)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }

    fn del_orders_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.orders_accounting_block_undo
            .del_undo_data(tx_source)
            .map_err(|e| TransactionVerifierStorageError::AccountingBlockUndoError(e).into())
    }
}

impl<C, S, U, A, T, O> FlushableUtxoView for TransactionVerifier<C, S, U, A, T, O> {
    type Error = utxo::Error;

    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        self.utxo_cache.batch_write(utxos)
    }
}

impl<C, S, U, A: PoSAccountingView, T, O> PoSAccountingStorageRead<TipStorageTag>
    for TransactionVerifier<C, S, U, A, T, O>
{
    type Error = pos_accounting::Error;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        self.pos_accounting_adapter
            .accounting_delta()
            .get_pool_balance(pool_id)
            .map(Some)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        self.pos_accounting_adapter.accounting_delta().get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.pos_accounting_adapter
            .accounting_delta()
            .get_delegation_balance(delegation_id)
            .map(Some)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        self.pos_accounting_adapter
            .accounting_delta()
            .get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        self.pos_accounting_adapter
            .accounting_delta()
            .get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        self.pos_accounting_adapter
            .accounting_delta()
            .get_pool_delegation_share(pool_id, delegation_id)
            .map(Some)
    }
}

impl<C, S, U, A: PoSAccountingView, T, O> FlushablePoSAccountingView
    for TransactionVerifier<C, S, U, A, T, O>
{
    type Error = pos_accounting::Error;

    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, pos_accounting::Error> {
        self.pos_accounting_adapter.batch_write_delta(data)
    }
}

impl<C, S, U, A, T: TokensAccountingView, O> TokensAccountingStorageRead
    for TransactionVerifier<C, S, U, A, T, O>
{
    type Error = tokens_accounting::Error;

    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        self.tokens_accounting_cache.get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.tokens_accounting_cache.get_circulating_supply(id).map(Some)
    }
}

impl<C, S, U, A, T, O> FlushableTokensAccountingView for TransactionVerifier<C, S, U, A, T, O> {
    type Error = tokens_accounting::Error;

    fn batch_write_tokens_data(
        &mut self,
        data: TokensAccountingDeltaData,
    ) -> Result<TokensAccountingDeltaUndoData, Self::Error> {
        self.tokens_accounting_cache.batch_write_tokens_data(data)
    }
}

impl<C, S, U, A, T, O: OrdersAccountingView> OrdersAccountingStorageRead
    for TransactionVerifier<C, S, U, A, T, O>
{
    type Error = orders_accounting::Error;

    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        self.orders_accounting_cache.get_order_data(id)
    }

    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.orders_accounting_cache.get_ask_balance(id).map(Some)
    }

    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.orders_accounting_cache.get_give_balance(id).map(Some)
    }
}

impl<C, S, U, A, T, O> FlushableOrdersAccountingView for TransactionVerifier<C, S, U, A, T, O> {
    type Error = orders_accounting::Error;

    fn batch_write_orders_data(
        &mut self,
        data: OrdersAccountingDeltaData,
    ) -> Result<OrdersAccountingDeltaUndoData, Self::Error> {
        self.orders_accounting_cache.batch_write_orders_data(data)
    }
}
