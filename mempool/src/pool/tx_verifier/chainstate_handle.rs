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

use std::collections::BTreeMap;

use chainstate::{
    chainstate_interface::ChainstateInterface,
    tx_verifier::{
        transaction_verifier::storage::HasTxIndexDisabledError, TransactionVerifierStorageRef,
    },
    ChainstateError,
};
use chainstate_types::storage_result;
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, DelegationId, GenBlock, OutPointSourceId, PoolId,
        Transaction, TxMainChainIndex, UtxoOutPoint,
    },
    primitives::{Amount, Id},
};
use pos_accounting::{AccountingBlockUndo, DelegationData, PoSAccountingView, PoolData};
use subsystem::blocking::BlockingHandle;
use tokens_accounting::{TokensAccountingStorageRead, TokensAccountingView};
use utils::shallow_clone::ShallowClone;
use utxo::{Utxo, UtxosBlockUndo, UtxosStorageRead, UtxosView};

/// Chainstate handle error includes errors coming from chainstate and inter-subprocess
/// communication errors.
#[derive(thiserror::Error, PartialEq, Eq, Debug)]
pub enum Error {
    #[error("Chainstate error: {0}")]
    Chainstate(#[from] ChainstateError),
    #[error("Subsystem error: {0}")]
    Subsystem(#[from] subsystem::error::CallError),
}

impl HasTxIndexDisabledError for Error {
    fn tx_index_disabled_error() -> Self {
        Self::Chainstate(ChainstateError::tx_index_disabled_error())
    }
}

impl From<pos_accounting::Error> for Error {
    fn from(e: pos_accounting::Error) -> Self {
        Error::from(ChainstateError::from(chainstate::BlockError::from(e)))
    }
}

impl From<tokens_accounting::Error> for Error {
    fn from(e: tokens_accounting::Error) -> Self {
        Error::from(ChainstateError::from(chainstate::BlockError::from(e)))
    }
}

impl From<utxo::Error> for Error {
    fn from(e: utxo::Error) -> Self {
        chainstate::tx_verifier::TransactionVerifierStorageError::from(e).into()
    }
}

impl From<chainstate::TransactionVerifierStorageError> for Error {
    fn from(e: chainstate::TransactionVerifierStorageError) -> Self {
        Error::from(ChainstateError::from(chainstate::BlockError::from(e)))
    }
}

impl From<Error> for crate::error::TxValidationError {
    fn from(e: Error) -> Self {
        match e {
            Error::Chainstate(e) => e.into(),
            Error::Subsystem(e) => e.into(),
        }
    }
}

impl From<Error> for crate::error::Error {
    fn from(e: Error) -> Self {
        crate::error::Error::Validity(e.into())
    }
}

/// A wrapper over handle to chainstate
pub struct ChainstateHandle(BlockingHandle<dyn ChainstateInterface>);

impl ChainstateHandle {
    pub fn new(inner: chainstate::ChainstateHandle) -> Self {
        Self(BlockingHandle::new(inner))
    }
}

impl ChainstateHandle {
    /// Chainstate subsystem call. We assume chainstate is alive here.
    fn call<R: 'static + Send>(
        &self,
        func: impl 'static + Send + FnOnce(&dyn ChainstateInterface) -> Result<R, ChainstateError>,
    ) -> Result<R, Error> {
        Ok(self.0.call(|c| func(c))??)
    }
}

impl Clone for ChainstateHandle {
    fn clone(&self) -> Self {
        self.shallow_clone()
    }
}

impl utils::shallow_clone::ShallowClone for ChainstateHandle {
    fn shallow_clone(&self) -> Self {
        Self(self.0.shallow_clone())
    }
}

impl UtxosStorageRead for ChainstateHandle {
    type Error = Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Error> {
        let outpoint = outpoint.clone();
        self.call(move |c| c.utxo(&outpoint))
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Error> {
        self.call(|c| c.get_best_block_id())
    }

    fn get_undo_data(&self, _id: Id<Block>) -> Result<Option<UtxosBlockUndo>, Error> {
        panic!("Mempool should not undo stuff in chainstate")
    }
}

impl PoSAccountingView for ChainstateHandle {
    type Error = Error;

    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Error> {
        self.call(move |c| c.stake_pool_exists(pool_id))
    }

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error> {
        self.call(move |c| c.get_stake_pool_balance(pool_id))
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error> {
        self.call(move |c| c.get_stake_pool_data(pool_id))
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error> {
        self.call(move |c| c.get_stake_pool_delegations_shares(pool_id))
    }

    fn get_delegation_balance(&self, delegation_id: DelegationId) -> Result<Option<Amount>, Error> {
        self.call(move |c| c.get_stake_delegation_balance(delegation_id))
    }

    fn get_delegation_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error> {
        self.call(move |c| c.get_stake_delegation_data(delegation_id))
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error> {
        self.call(move |c| c.get_stake_pool_delegation_share(pool_id, delegation_id))
    }
}

impl TransactionVerifierStorageRef for ChainstateHandle {
    type Error = Error;

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, Error> {
        self.call(move |c| c.get_token_id_from_issuance_tx(&tx_id))
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<chainstate::GenBlockIndex>, storage_result::Error> {
        let block_id = *block_id;
        self.call(move |c| c.get_gen_block_index(&block_id)).map_err(|e| match e {
            // TODO Handle this properly. For now we just panic on non-storage errors which should
            // not happen. A more principled solution is to have a more accurate error types that
            // communicate that so panics can be avoided completely.
            Error::Chainstate(e) => match e {
                ChainstateError::ProcessBlockError(chainstate::BlockError::StorageError(e)) => e,
                ChainstateError::FailedToReadProperty(
                    chainstate::PropertyQueryError::StorageError(e),
                ) => e,
                _ => panic!("unexpected non-storage error"),
            },
            // TODO Handle this properly. This is a consequence of the error being
            // `storage_result::Error` rather than `Self::Error`.
            Error::Subsystem(_) => panic!("subsystem failure"),
        })
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, Error> {
        let tx_id = tx_id.clone();
        self.call(move |c| c.get_mainchain_tx_index(&tx_id))
    }

    fn get_token_aux_data(&self, token_id: &TokenId) -> Result<Option<TokenAuxiliaryData>, Error> {
        let token_id = *token_id;
        self.call(move |c| c.get_token_aux_data(token_id))
    }

    fn get_accounting_undo(&self, _id: Id<Block>) -> Result<Option<AccountingBlockUndo>, Error> {
        panic!("Mempool should not undo stuff in chainstate")
    }

    fn get_account_nonce_count(&self, account: AccountType) -> Result<Option<AccountNonce>, Error> {
        self.call(move |c| c.get_account_nonce_count(account))
    }

    fn get_tokens_accounting_undo(
        &self,
        _id: Id<Block>,
    ) -> Result<Option<tokens_accounting::BlockUndo>, Error> {
        panic!("Mempool should not undo stuff in chainstate")
    }
}

impl UtxosView for ChainstateHandle {
    type Error = Error;

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Error> {
        let outpoint = outpoint.clone();
        self.call(move |c| c.utxo(&outpoint))
    }

    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Error> {
        self.utxo(outpoint).map(|outpt| outpt.is_some())
    }

    fn best_block_hash(&self) -> Result<Id<GenBlock>, Error> {
        self.get_best_block_for_utxos()
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

impl TokensAccountingView for ChainstateHandle {
    type Error = Error;

    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        let id = *id;
        self.call(move |c| c.get_token_data(&id))
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        let id = *id;
        self.call(move |c| c.get_token_circulating_supply(&id))
    }
}

impl TokensAccountingStorageRead for ChainstateHandle {
    type Error = Error;

    fn get_token_data(
        &self,
        id: &TokenId,
    ) -> Result<Option<tokens_accounting::TokenData>, Self::Error> {
        let id = *id;
        self.call(move |c| c.get_token_data(&id))
    }

    fn get_circulating_supply(&self, id: &TokenId) -> Result<Option<Amount>, Self::Error> {
        let id = *id;
        self.call(move |c| c.get_token_circulating_supply(&id))
    }
}
