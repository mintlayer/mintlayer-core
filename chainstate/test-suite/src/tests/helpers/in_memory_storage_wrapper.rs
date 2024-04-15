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

use ::tx_verifier::transaction_verifier::storage::{
    TransactionVerifierStorageError, TransactionVerifierStorageRef,
};
use chainstate_storage::{inmemory::Store, BlockchainStorageRead, TipStorageTag, Transactional};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, ChainConfig, DelegationId, GenBlock, GenBlockId, PoolId,
        Transaction,
    },
    primitives::{Amount, Id},
};
use pos_accounting::{DelegationData, PoSAccountingDB, PoSAccountingView, PoolData};
use tokens_accounting::TokensAccountingStorageRead;
use tx_verifier::{
    transaction_verifier::{CachedPoSBlockUndo, CachedTokensBlockUndo, CachedUtxosBlockUndo},
    TransactionSource,
};
use utxo::UtxosStorageRead;

pub struct InMemoryStorageWrapper {
    storage: Store,
    chain_config: ChainConfig,
}

impl InMemoryStorageWrapper {
    pub fn new(storage: Store, chain_config: ChainConfig) -> Self {
        Self {
            storage,
            chain_config,
        }
    }
}

impl TransactionVerifierStorageRef for InMemoryStorageWrapper {
    type Error = TransactionVerifierStorageError;

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        self.storage
            .transaction_ro()
            .unwrap()
            .get_token_id(&tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        match block_id.classify(&self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::genesis(&self.chain_config))),
            GenBlockId::Block(id) => self
                .storage
                .transaction_ro()
                .unwrap()
                .get_block_index(&id)
                .map(|b| b.map(GenBlockIndex::Block)),
        }
    }

    fn get_undo_data(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedUtxosBlockUndo>, TransactionVerifierStorageError> {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo = self
                    .storage
                    .transaction_ro()
                    .unwrap()
                    .get_undo_data(id)?
                    .map(CachedUtxosBlockUndo::from_utxo_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => {
                panic!("Mempool should not undo stuff in chainstate")
            }
        }
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.storage
            .transaction_ro()
            .unwrap()
            .get_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_pos_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedPoSBlockUndo>, TransactionVerifierStorageError> {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo = self
                    .storage
                    .transaction_ro()
                    .unwrap()
                    .get_pos_accounting_undo(id)?
                    .map(CachedPoSBlockUndo::from_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => Ok(None),
        }
    }

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, TransactionVerifierStorageError> {
        self.storage
            .transaction_ro()
            .unwrap()
            .get_account_nonce_count(account)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_tokens_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedTokensBlockUndo>, TransactionVerifierStorageError> {
        match tx_source {
            TransactionSource::Chain(id) => {
                let undo = self
                    .storage
                    .transaction_ro()
                    .unwrap()
                    .get_tokens_accounting_undo(id)?
                    .map(CachedTokensBlockUndo::from_block_undo);
                Ok(undo)
            }
            TransactionSource::Mempool => Ok(None),
        }
    }
}

impl UtxosStorageRead for InMemoryStorageWrapper {
    type Error = storage_result::Error;

    fn get_utxo(
        &self,
        outpoint: &common::chain::UtxoOutPoint,
    ) -> Result<Option<utxo::Utxo>, storage_result::Error> {
        self.storage.transaction_ro().unwrap().get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, storage_result::Error> {
        self.storage.transaction_ro().unwrap().get_best_block_for_utxos()
    }
}

impl PoSAccountingView for InMemoryStorageWrapper {
    type Error = pos_accounting::Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, pos_accounting::Error> {
        self.get_pool_data(pool_id).map(|v| v.is_some())
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.storage).get_pool_balance(pool_id)
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.storage).get_pool_data(pool_id)
    }

    fn get_delegation_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.storage)
            .get_delegation_balance(delegation_id)
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.storage).get_delegation_data(delegation_id)
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.storage).get_pool_delegations_shares(pool_id)
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, pos_accounting::Error> {
        PoSAccountingDB::<_, TipStorageTag>::new(&self.storage)
            .get_pool_delegation_share(pool_id, delegation_id)
    }
}

impl TokensAccountingStorageRead for InMemoryStorageWrapper {
    type Error = storage_result::Error;

    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        self.storage.transaction_ro().unwrap().get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.storage.transaction_ro().unwrap().get_circulating_supply(id)
    }
}
