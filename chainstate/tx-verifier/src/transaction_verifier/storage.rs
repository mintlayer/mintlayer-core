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

use std::ops::Deref;

use chainstate_types::{storage_result, GenBlockIndex};
use common::{
    chain::{
        tokens::{TokenAuxiliaryData, TokenId},
        AccountNonce, AccountType, Block, GenBlock, Transaction,
    },
    primitives::Id,
};
use pos_accounting::{
    FlushablePoSAccountingView, PoSAccountingDeltaData, PoSAccountingUndo, PoSAccountingView,
};
use thiserror::Error;
use tokens_accounting::{FlushableTokensAccountingView, TokensAccountingStorageRead};
use utxo::{FlushableUtxoView, UtxosStorageRead};

use super::{
    accounting_undo_cache::CachedBlockUndo, error::TokensError,
    tokens_accounting_undo_cache::CachedTokensBlockUndo, utxos_undo_cache::CachedUtxosBlockUndo,
    TransactionSource,
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TransactionVerifierStorageError {
    #[error("Gen block index not found")]
    GenBlockIndexRetrievalFailed(Id<GenBlock>),
    #[error("Failed to persist state: {0}")]
    StatePersistenceError(#[from] storage_result::Error),
    #[error("Failed to get ancestor: {0}")]
    GetAncestorError(#[from] chainstate_types::GetAncestorError),
    #[error("Duplicate undo info for block: {0}")]
    DuplicateBlockUndo(Id<Block>),
    #[error("Tokens error: {0}")]
    TokensError(#[from] TokensError),
    #[error("Utxo error: {0}")]
    UtxoError(#[from] utxo::Error),
    #[error("BlockUndo error: {0}")]
    UtxoBlockUndoError(#[from] utxo::UtxosBlockUndoError),
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("Accounting BlockUndo error: {0}")]
    AccountingBlockUndoError(#[from] accounting::BlockUndoError),
    #[error("Tokens accounting error: {0}")]
    TokensAccountingError(#[from] tokens_accounting::Error),
    #[error("Tokens accounting BlockUndo error: {0}")]
    TokensAccountingBlockUndoError(#[from] tokens_accounting::BlockUndoError),
}

// TODO(Gosha): PoSAccountingView should be replaced with PoSAccountingStorageRead in which the
//              return error type can handle both storage_result::Error and pos_accounting::Error
pub trait TransactionVerifierStorageRef:
    UtxosStorageRead + PoSAccountingView + TokensAccountingStorageRead
{
    type Error: std::error::Error;

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, <Self as TransactionVerifierStorageRef>::Error>;

    // TODO: Study whether moving this to a closure on tx_verifier construction is helpful.
    //       The issue here is that looking into history prevents testing the tx_verifier independently
    //       where the state of the tx index should be prepared before constructing the tx_verifier
    //       which sabotages the ability to look into the history and find the block that is being
    //       connected with the current tx.
    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error>;

    fn get_undo_data(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedUtxosBlockUndo>, <Self as TransactionVerifierStorageRef>::Error>;

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, <Self as TransactionVerifierStorageRef>::Error>;

    fn get_pos_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<
        Option<CachedBlockUndo<PoSAccountingUndo>>,
        <Self as TransactionVerifierStorageRef>::Error,
    >;

    fn get_tokens_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedTokensBlockUndo>, <Self as TransactionVerifierStorageRef>::Error>;

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, <Self as TransactionVerifierStorageRef>::Error>;
}

pub trait TransactionVerifierStorageMut:
    TransactionVerifierStorageRef
    + FlushableUtxoView
    + FlushablePoSAccountingView
    + FlushableTokensAccountingView
{
    fn set_token_aux_data(
        &mut self,
        token_id: &TokenId,
        data: &TokenAuxiliaryData,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn del_token_aux_data(
        &mut self,
        token_id: &TokenId,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn set_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
        token_id: &TokenId,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn del_token_id(
        &mut self,
        issuance_tx_id: &Id<Transaction>,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn set_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedUtxosBlockUndo,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn del_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn set_pos_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedBlockUndo<PoSAccountingUndo>,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn del_pos_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn apply_accounting_delta(
        &mut self,
        tx_source: TransactionSource,
        delta: &PoSAccountingDeltaData,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn set_account_nonce_count(
        &mut self,
        account: AccountType,
        nonce: AccountNonce,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;
    fn del_account_nonce_count(
        &mut self,
        account: AccountType,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn set_tokens_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &CachedTokensBlockUndo,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;

    fn del_tokens_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), <Self as TransactionVerifierStorageRef>::Error>;
}

impl<T: Deref> TransactionVerifierStorageRef for T
where
    T::Target: TransactionVerifierStorageRef,
{
    type Error = <T::Target as TransactionVerifierStorageRef>::Error;

    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, <Self as TransactionVerifierStorageRef>::Error> {
        self.deref().get_token_id_from_issuance_tx(tx_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        self.deref().get_gen_block_index(block_id)
    }

    fn get_undo_data(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedUtxosBlockUndo>, <Self as TransactionVerifierStorageRef>::Error> {
        self.deref().get_undo_data(tx_source)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, <Self as TransactionVerifierStorageRef>::Error> {
        self.deref().get_token_aux_data(token_id)
    }

    fn get_pos_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<
        Option<CachedBlockUndo<PoSAccountingUndo>>,
        <Self as TransactionVerifierStorageRef>::Error,
    > {
        self.deref().get_pos_accounting_undo(tx_source)
    }

    fn get_tokens_accounting_undo(
        &self,
        tx_source: TransactionSource,
    ) -> Result<Option<CachedTokensBlockUndo>, <Self as TransactionVerifierStorageRef>::Error> {
        self.deref().get_tokens_accounting_undo(tx_source)
    }

    fn get_account_nonce_count(
        &self,
        account: AccountType,
    ) -> Result<Option<AccountNonce>, <Self as TransactionVerifierStorageRef>::Error> {
        self.deref().get_account_nonce_count(account)
    }
}
