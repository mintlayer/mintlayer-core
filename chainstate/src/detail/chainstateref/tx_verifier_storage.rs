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

use crate::detail::{
    chainstateref::ChainstateRef,
    transaction_verifier::storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    tx_verification_strategy::TransactionVerificationStrategy,
};
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use chainstate_types::{storage_result, GenBlockIndex, TipStorageTag};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, ChainConfig, DelegationId, GenBlock, GenBlockId, OrderId,
        PoolId, Transaction,
    },
    primitives::{Amount, Id},
};
use orders_accounting::{
    FlushableOrdersAccountingView, OrderData, OrdersAccountingDB, OrdersAccountingStorageRead,
    OrdersAccountingUndo,
};
use pos_accounting::{
    DelegationData, DeltaMergeUndo, FlushablePoSAccountingView, PoSAccountingDB,
    PoSAccountingDeltaData, PoSAccountingStorageRead, PoSAccountingUndo, PoolData,
};
use tokens_accounting::{
    FlushableTokensAccountingView, TokenAccountingUndo, TokensAccountingDB,
    TokensAccountingDeltaUndoData, TokensAccountingStorageRead,
};
use tx_verifier::transaction_verifier::{CachedBlockUndo, CachedUtxosBlockUndo, TransactionSource};
use utils::log_error;
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosDB, UtxosStorageRead};

impl<S: BlockchainStorageRead, V: TransactionVerificationStrategy> TransactionVerifierStorageRef
    for ChainstateRef<'_, S, V>
{
    type Error = TransactionVerifierStorageError;

    #[log_error]
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        self.db_tx.get_token_id(&tx_id).map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        gen_block_index_getter(&self.db_tx, self.chain_config, block_id)
    }

    #[log_error]
    fn get_undo_data(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedUtxosBlockUndo>, TransactionVerifierStorageError> {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo =
                    self.db_tx.get_undo_data(id)?.map(CachedUtxosBlockUndo::from_utxo_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => {
                panic!("Mempool should not undo stuff in chainstate")
            }
        }
    }

    #[log_error]
    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.db_tx
            .get_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn get_pos_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedBlockUndo<PoSAccountingUndo>>, TransactionVerifierStorageError> {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo =
                    self.db_tx.get_pos_accounting_undo(id)?.map(CachedBlockUndo::from_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => {
                panic!("Mempool should not undo stuff in chainstate")
            }
        }
    }

    #[log_error]
    fn get_tokens_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedBlockUndo<TokenAccountingUndo>>, TransactionVerifierStorageError> {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo = self
                    .db_tx
                    .get_tokens_accounting_undo(id)?
                    .map(CachedBlockUndo::from_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => {
                panic!("Mempool should not undo stuff in chainstate")
            }
        }
    }

    #[log_error]
    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, TransactionVerifierStorageError> {
        self.db_tx
            .get_account_nonce_count(account)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn get_orders_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedBlockUndo<OrdersAccountingUndo>>, TransactionVerifierStorageError>
    {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo = self
                    .db_tx
                    .get_orders_accounting_undo(id)?
                    .map(CachedBlockUndo::from_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => {
                panic!("Mempool should not undo stuff in chainstate")
            }
        }
    }
}

// TODO: this function is a duplicate of one in chainstate-types; the cause for this is that BlockchainStorageRead causes a circular dependencies
// BlockchainStorageRead should probably be moved out of storage
#[log_error]
pub fn gen_block_index_getter<S: BlockchainStorageRead>(
    db_tx: &S,
    chain_config: &ChainConfig,
    block_id: &Id<GenBlock>,
) -> Result<Option<GenBlockIndex>, storage_result::Error> {
    match block_id.classify(chain_config) {
        GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::genesis(chain_config))),
        GenBlockId::Block(id) => db_tx.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block)),
    }
}

impl<S: BlockchainStorageRead, V: TransactionVerificationStrategy> UtxosStorageRead
    for ChainstateRef<'_, S, V>
{
    type Error = storage_result::Error;

    #[log_error]
    fn get_utxo(
        &self,
        outpoint: &common::chain::UtxoOutPoint,
    ) -> Result<Option<utxo::Utxo>, storage_result::Error> {
        self.db_tx.get_utxo(outpoint)
    }

    #[log_error]
    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, storage_result::Error> {
        self.db_tx.get_best_block_for_utxos()
    }
}

impl<S: BlockchainStorageWrite, V: TransactionVerificationStrategy> FlushableUtxoView
    for ChainstateRef<'_, S, V>
{
    type Error = utxo::Error;

    #[log_error]
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        let mut db = UtxosDB::new(&mut self.db_tx);
        db.batch_write(utxos)
    }
}

impl<S: BlockchainStorageWrite, V: TransactionVerificationStrategy> TransactionVerifierStorageMut
    for ChainstateRef<'_, S, V>
{
    #[log_error]
    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_token_aux_data(token_id, data)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_token_id(issuance_tx_id, token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_token_id(issuance_tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn set_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedUtxosBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .set_undo_data(id, &undo.clone().consume())
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn del_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => {
                self.db_tx.del_undo_data(id).map_err(TransactionVerifierStorageError::from)
            }
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn set_pos_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedBlockUndo<PoSAccountingUndo>,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .set_pos_accounting_undo_data(id, &undo.clone().consume())
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn del_pos_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .del_pos_accounting_undo_data(id)
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn apply_accounting_delta(
        &mut self,
        tx_source: TransactionSource,
        delta: &PoSAccountingDeltaData,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => {
                let block_index = self
                    .db_tx
                    .get_block_index(&id)
                    .map_err(TransactionVerifierStorageError::from)?
                    .ok_or_else(|| {
                        TransactionVerifierStorageError::GenBlockIndexRetrievalFailed(id.into())
                    })?;
                let current_epoch_index =
                    self.chain_config().epoch_index_from_height(&block_index.block_height());
                let mut current_epoch_delta = self
                    .db_tx
                    .get_accounting_epoch_delta(current_epoch_index)
                    .map_err(TransactionVerifierStorageError::from)?
                    .unwrap_or_default();
                current_epoch_delta.merge_with_delta(delta.clone())?;
                self.db_tx
                    .set_accounting_epoch_delta(current_epoch_index, &current_epoch_delta)
                    .map_err(TransactionVerifierStorageError::from)
            }
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn set_account_nonce_count(
        &mut self,
        account: AccountType,
        nonce: AccountNonce,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.db_tx
            .set_account_nonce_count(account, nonce)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn del_account_nonce_count(
        &mut self,
        account: AccountType,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.db_tx
            .del_account_nonce_count(account)
            .map_err(TransactionVerifierStorageError::from)
    }

    #[log_error]
    fn set_tokens_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedBlockUndo<TokenAccountingUndo>,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .set_tokens_accounting_undo_data(id, &undo.clone().consume())
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn del_tokens_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .del_tokens_accounting_undo_data(id)
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn set_orders_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedBlockUndo<OrdersAccountingUndo>,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .set_orders_accounting_undo_data(id, &undo.clone().consume())
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    #[log_error]
    fn del_orders_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .del_orders_accounting_undo_data(id)
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }
}

impl<S: BlockchainStorageRead, V: TransactionVerificationStrategy>
    PoSAccountingStorageRead<TipStorageTag> for ChainstateRef<'_, S, V>
{
    type Error = storage_result::Error;

    #[log_error]
    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_pool_balance(pool_id)
    }

    #[log_error]
    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Self::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_pool_data(pool_id)
    }

    #[log_error]
    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_delegation_balance(delegation_id)
    }

    #[log_error]
    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Self::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_delegation_data(delegation_id)
    }

    #[log_error]
    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Self::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_pool_delegations_shares(pool_id)
    }

    #[log_error]
    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx)
            .get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<S: BlockchainStorageWrite, V: TransactionVerificationStrategy> FlushablePoSAccountingView
    for ChainstateRef<'_, S, V>
{
    type Error = pos_accounting::Error;

    #[log_error]
    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, Self::Error> {
        let mut db = PoSAccountingDB::<_, TipStorageTag>::new(&mut self.db_tx);
        db.batch_write_delta(data)
    }
}

impl<S: BlockchainStorageRead, V: TransactionVerificationStrategy> TokensAccountingStorageRead
    for ChainstateRef<'_, S, V>
{
    type Error = storage_result::Error;

    #[log_error]
    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, storage_result::Error> {
        self.db_tx.get_token_data(id)
    }

    #[log_error]
    fn get_circulating_supply(
        &self,
        id: &TokenId,
    ) -> Result<Option<Amount>, storage_result::Error> {
        self.db_tx.get_circulating_supply(id)
    }
}

impl<S: BlockchainStorageWrite, V: TransactionVerificationStrategy> FlushableTokensAccountingView
    for ChainstateRef<'_, S, V>
{
    type Error = tokens_accounting::Error;

    #[log_error]
    fn batch_write_tokens_data(
        &mut self,
        delta: tokens_accounting::TokensAccountingDeltaData,
    ) -> Result<TokensAccountingDeltaUndoData, Self::Error> {
        let mut db = TokensAccountingDB::new(&mut self.db_tx);
        db.batch_write_tokens_data(delta)
    }
}

impl<S: BlockchainStorageRead, V: TransactionVerificationStrategy> OrdersAccountingStorageRead
    for ChainstateRef<'_, S, V>
{
    type Error = storage_result::Error;

    #[log_error]
    fn get_order_data(&self, id: &OrderId) -> Result<Option<OrderData>, Self::Error> {
        self.db_tx.get_order_data(id)
    }

    #[log_error]
    fn get_ask_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.db_tx.get_ask_balance(id)
    }

    #[log_error]
    fn get_give_balance(&self, id: &OrderId) -> Result<Option<Amount>, Self::Error> {
        self.db_tx.get_give_balance(id)
    }
}

impl<S: BlockchainStorageWrite, V: TransactionVerificationStrategy> FlushableOrdersAccountingView
    for ChainstateRef<'_, S, V>
{
    type Error = orders_accounting::Error;

    fn batch_write_orders_data(
        &mut self,
        delta: orders_accounting::OrdersAccountingDeltaData,
    ) -> Result<orders_accounting::OrdersAccountingDeltaUndoData, Self::Error> {
        let mut db = OrdersAccountingDB::new(&mut self.db_tx);
        db.batch_write_orders_data(delta)
    }
}
