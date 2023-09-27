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

use std::{collections::BTreeMap, sync::Arc};

use crate::detail::{
    chainstateref::ChainstateRef,
    transaction_verifier::storage::{
        TransactionVerifierStorageError, TransactionVerifierStorageMut,
        TransactionVerifierStorageRef,
    },
    tx_verification_strategy::TransactionVerificationStrategy,
};
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite, TipStorageTag};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, ChainConfig, DelegationId, GenBlock, GenBlockId,
        OutPointSourceId, PoolId, Transaction,
    },
    primitives::{Amount, Id},
};
use pos_accounting::{
    AccountingBlockUndo, DelegationData, DeltaMergeUndo, FlushablePoSAccountingView,
    PoSAccountingDB, PoSAccountingDeltaData, PoSAccountingView, PoolData,
};
use tokens_accounting::TokensAccountingStorageRead;
use tx_verifier::transaction_verifier::TransactionSource;
use utxo::{ConsumedUtxoCache, FlushableUtxoView, UtxosBlockUndo, UtxosDB, UtxosStorageRead};

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> TransactionVerifierStorageRef
    for ChainstateRef<'a, S, V>
{
    type Error = TransactionVerifierStorageError;

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        self.db_tx.get_token_id(&tx_id).map_err(TransactionVerifierStorageError::from)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        gen_block_index_getter(&self.db_tx, self.chain_config, block_id)
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<common::chain::TxMainChainIndex>, TransactionVerifierStorageError> {
        self.db_tx
            .get_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.db_tx
            .get_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> Result<Option<AccountingBlockUndo>, TransactionVerifierStorageError> {
        self.db_tx
            .get_accounting_undo(id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, TransactionVerifierStorageError> {
        self.db_tx
            .get_account_nonce_count(account)
            .map_err(TransactionVerifierStorageError::from)
    }
}

// TODO: this function is a duplicate of one in chainstate-types; the cause for this is that BlockchainStorageRead causes a circular dependencies
// BlockchainStorageRead should probably be moved out of storage
pub fn gen_block_index_getter<S: BlockchainStorageRead>(
    db_tx: &S,
    chain_config: &ChainConfig,
    block_id: &Id<GenBlock>,
) -> Result<Option<GenBlockIndex>, storage_result::Error> {
    match block_id.classify(chain_config) {
        GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
            chain_config.genesis_block(),
        )))),
        GenBlockId::Block(id) => db_tx.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block)),
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> UtxosStorageRead
    for ChainstateRef<'a, S, V>
{
    type Error = storage_result::Error;

    fn get_utxo(
        &self,
        outpoint: &common::chain::UtxoOutPoint,
    ) -> Result<Option<utxo::Utxo>, storage_result::Error> {
        self.db_tx.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, storage_result::Error> {
        self.db_tx.get_best_block_for_utxos()
    }

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> Result<Option<UtxosBlockUndo>, storage_result::Error> {
        self.db_tx.get_undo_data(id)
    }
}

impl<'a, S: BlockchainStorageWrite, V: TransactionVerificationStrategy> FlushableUtxoView
    for ChainstateRef<'a, S, V>
{
    type Error = utxo::Error;

    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), utxo::Error> {
        let mut db = UtxosDB::new(&mut self.db_tx);
        db.batch_write(utxos)
    }
}

impl<'a, S: BlockchainStorageWrite, V: TransactionVerificationStrategy>
    TransactionVerifierStorageMut for ChainstateRef<'a, S, V>
{
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &common::chain::TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_mainchain_tx_index(tx_id, tx_index)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_token_aux_data(token_id, data)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .set_token_id(issuance_tx_id, token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), TransactionVerifierStorageError> {
        self.db_tx
            .del_token_id(issuance_tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn set_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &UtxosBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .set_undo_data(id, undo)
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

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

    fn set_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &AccountingBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .set_accounting_undo_data(id, undo)
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

    fn del_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError> {
        // TODO: check tx_source at compile-time (mintlayer/mintlayer-core#633)
        match tx_source {
            TransactionSource::Chain(id) => self
                .db_tx
                .del_accounting_undo_data(id)
                .map_err(TransactionVerifierStorageError::from),
            TransactionSource::Mempool => {
                panic!("Flushing mempool info into the storage is forbidden")
            }
        }
    }

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

    fn set_account_nonce_count(
        &mut self,
        account: AccountType,
        nonce: AccountNonce,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.db_tx
            .set_account_nonce_count(account, nonce)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn del_account_nonce_count(
        &mut self,
        account: AccountType,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error> {
        self.db_tx
            .del_account_nonce_count(account)
            .map_err(TransactionVerifierStorageError::from)
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> PoSAccountingView
    for ChainstateRef<'a, S, V>
{
    type Error = pos_accounting::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, pos_accounting::Error> {
        self.get_pool_data(pool_id).map(|v| v.is_some())
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx).get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.db_tx)
            .get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl<'a, S: BlockchainStorageWrite, V: TransactionVerificationStrategy> FlushablePoSAccountingView
    for ChainstateRef<'a, S, V>
{
    fn batch_write_delta(
        &mut self,
        data: PoSAccountingDeltaData,
    ) -> Result<DeltaMergeUndo, pos_accounting::Error> {
        let mut db = PoSAccountingDB::<_, TipStorageTag>::new(&mut self.db_tx);
        db.batch_write_delta(data)
    }
}

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> TokensAccountingStorageRead
    for ChainstateRef<'a, S, V>
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
