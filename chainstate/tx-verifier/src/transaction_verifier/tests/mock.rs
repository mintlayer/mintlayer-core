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

use crate::transaction_verifier::TransactionSource;

use super::{
    accounting_undo_cache::CachedBlockUndo,
    storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    CachedUtxosBlockUndo,
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
};
use pos_accounting::{
    DelegationData, DeltaMergeUndo, FlushablePoSAccountingView, PoSAccountingDeltaData,
    PoSAccountingStorageRead, PoSAccountingUndo, PoolData,
};
use tokens_accounting::{
    FlushableTokensAccountingView, TokenAccountingUndo, TokenData, TokensAccountingDeltaData,
    TokensAccountingDeltaUndoData, TokensAccountingStorageRead,
};
use utxo::{ConsumedUtxoCache, FlushableUtxoView, Utxo, UtxosStorageRead};

mockall::mock! {
    pub Store {}

    impl TransactionVerifierStorageRef for Store {
        type Error = TransactionVerifierStorageError;

        fn get_undo_data(&self, tx_source: TransactionSource) -> Result<Option<CachedUtxosBlockUndo>, TransactionVerifierStorageError>;

        fn get_token_id_from_issuance_tx(
            &self,
            tx_id: Id<Transaction>,
        ) -> Result<Option<TokenId>, TransactionVerifierStorageError>;

        fn get_gen_block_index(
            &self,
            block_id: &Id<GenBlock>,
        ) -> Result<Option<GenBlockIndex>, storage_result::Error>;

        fn get_token_aux_data(
            &self,
            token_id: &TokenId,
        ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError>;

        fn get_pos_accounting_undo(
            &self,
            tx_source: TransactionSource,
        ) -> Result<Option<CachedBlockUndo<PoSAccountingUndo>>, TransactionVerifierStorageError>;

        fn get_tokens_accounting_undo(
            &self,
            tx_source: TransactionSource,
        ) -> Result<Option<CachedBlockUndo<TokenAccountingUndo>>, TransactionVerifierStorageError>;

        fn get_account_nonce_count(
            &self,
            account: AccountType,
        ) -> Result<Option<AccountNonce>, TransactionVerifierStorageError>;

        fn get_orders_accounting_undo(
            &self,
            tx_source: TransactionSource,
        ) -> Result<Option<CachedBlockUndo<OrdersAccountingUndo>>, TransactionVerifierStorageError>;
    }

    impl TransactionVerifierStorageMut for Store {
        fn set_token_aux_data(
            &mut self,
            token_id: &TokenId,
            data: &TokenAuxiliaryData,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_token_aux_data(
            &mut self,
            token_id: &TokenId,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_token_id(
            &mut self,
            issuance_tx_id: &Id<Transaction>,
            token_id: &TokenId,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_token_id(
            &mut self,
            issuance_tx_id: &Id<Transaction>,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_utxo_undo_data(&mut self, tx_source: TransactionSource, undo: &CachedUtxosBlockUndo) -> Result<(), TransactionVerifierStorageError>;
        fn del_utxo_undo_data(&mut self, tx_source: TransactionSource) -> Result<(), TransactionVerifierStorageError>;

        fn set_pos_accounting_undo_data(
            &mut self,
            tx_source: TransactionSource,
            undo: &CachedBlockUndo<PoSAccountingUndo>,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_pos_accounting_undo_data(
            &mut self,
            tx_source: TransactionSource,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn apply_accounting_delta(
            &mut self,
            tx_source: TransactionSource,
            delta: &PoSAccountingDeltaData,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_account_nonce_count(
            &mut self,
            account: AccountType,
            nonce: AccountNonce,
        ) -> Result<(), TransactionVerifierStorageError>;
        fn del_account_nonce_count(
            &mut self,
            account: AccountType,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_tokens_accounting_undo_data(
            &mut self,
            tx_source: TransactionSource,
            undo: &CachedBlockUndo<TokenAccountingUndo>,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_tokens_accounting_undo_data(
            &mut self,
            tx_source: TransactionSource,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn set_orders_accounting_undo_data(
            &mut self,
            tx_source: TransactionSource,
            undo: &CachedBlockUndo<OrdersAccountingUndo>,
        ) -> Result<(), TransactionVerifierStorageError>;

        fn del_orders_accounting_undo_data(
            &mut self,
            tx_source: TransactionSource,
        ) -> Result<(), TransactionVerifierStorageError>;
    }

    impl UtxosStorageRead for Store {
        type Error = storage_result::Error;
        fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, storage_result::Error>;
        fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, storage_result::Error>;
    }

    impl FlushableUtxoView for Store {
        type Error = utxo::Error;
        fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error>;
    }

    impl PoSAccountingStorageRead<TipStorageTag> for Store {
        type Error = pos_accounting::Error;
        fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, pos_accounting::Error>;
        fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, pos_accounting::Error>;
        fn get_delegation_balance(
            &self,
            delegation_id: DelegationId,
        ) -> Result<Option<Amount>, pos_accounting::Error>;
        fn get_delegation_data(
            &self,
            delegation_id: DelegationId,
        ) -> Result<Option<DelegationData>, pos_accounting::Error>;
        fn get_pool_delegations_shares(
            &self,
            pool_id: PoolId,
        ) -> Result<Option<BTreeMap<DelegationId, Amount>>, pos_accounting::Error>;
        fn get_pool_delegation_share(
            &self,
            pool_id: PoolId,
            delegation_id: DelegationId,
        ) -> Result<Option<Amount>, pos_accounting::Error>;
    }

    impl FlushablePoSAccountingView for Store {
        type Error = pos_accounting::Error;
        fn batch_write_delta(&mut self, data: PoSAccountingDeltaData) -> Result<DeltaMergeUndo, pos_accounting::Error>;
    }

    impl TokensAccountingStorageRead for Store {
        type Error = tokens_accounting::Error;
        fn get_token_data(&self, id: &TokenId,) -> Result<Option<TokenData>, tokens_accounting::Error>;
        fn get_circulating_supply(&self, id: &TokenId,) -> Result<Option<Amount>, tokens_accounting::Error>;
    }

    impl FlushableTokensAccountingView for Store {
        type Error = tokens_accounting::Error;
        fn batch_write_tokens_data(&mut self, delta: TokensAccountingDeltaData) -> Result<TokensAccountingDeltaUndoData, tokens_accounting::Error>;
    }

    impl OrdersAccountingStorageRead for Store {
        type Error = orders_accounting::Error;
        fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, orders_accounting::Error>;
        fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, orders_accounting::Error>;
        fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, orders_accounting::Error>;
    }

    impl FlushableOrdersAccountingView for Store {
        type Error = orders_accounting::Error;
        fn batch_write_orders_data(
            &mut self,
            data: OrdersAccountingDeltaData,
        ) -> Result<OrdersAccountingDeltaUndoData, orders_accounting::Error>;
    }
}
