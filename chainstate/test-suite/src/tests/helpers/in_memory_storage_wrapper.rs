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

use ::tx_verifier::transaction_verifier::storage::{
    TransactionVerifierStorageError, TransactionVerifierStorageRef,
};
use chainstate_storage::{inmemory::Store, BlockchainStorageRead, TipStorageTag};
use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, ChainConfig, DelegationId, GenBlock, GenBlockId,
        OutPointSourceId, PoolId, Transaction, TxMainChainIndex,
    },
    primitives::{Amount, Id},
};
use pos_accounting::{DelegationData, PoSAccountingDB, PoSAccountingView, PoolData};
use tokens_accounting::TokensAccountingStorageRead;
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
        self.storage.get_token_id(&tx_id).map_err(TransactionVerifierStorageError::from)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        match block_id.classify(&self.chain_config) {
            GenBlockId::Genesis(_id) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                self.chain_config.genesis_block(),
            )))),
            GenBlockId::Block(id) => {
                self.storage.get_block_index(&id).map(|b| b.map(GenBlockIndex::Block))
            }
        }
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError> {
        self.storage
            .get_mainchain_tx_index(tx_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.storage
            .get_token_aux_data(token_id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> Result<Option<pos_accounting::AccountingBlockUndo>, TransactionVerifierStorageError> {
        self.storage
            .get_accounting_undo(id)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, TransactionVerifierStorageError> {
        self.storage
            .get_account_nonce_count(account)
            .map_err(TransactionVerifierStorageError::from)
    }

    fn get_tokens_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> Result<Option<tokens_accounting::BlockUndo>, TransactionVerifierStorageError> {
        self.storage
            .get_tokens_accounting_undo(id)
            .map_err(TransactionVerifierStorageError::from)
    }
}

impl UtxosStorageRead for InMemoryStorageWrapper {
    type Error = storage_result::Error;

    fn get_utxo(
        &self,
        outpoint: &common::chain::UtxoOutPoint,
    ) -> Result<Option<utxo::Utxo>, storage_result::Error> {
        self.storage.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, storage_result::Error> {
        self.storage.get_best_block_for_utxos()
    }

    fn get_undo_data(
        &self,
        id: Id<Block>,
    ) -> Result<Option<utxo::UtxosBlockUndo>, storage_result::Error> {
        self.storage.get_undo_data(id)
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
        self.storage.get_token_data(id)
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        self.storage.get_circulating_supply(id)
    }
}
