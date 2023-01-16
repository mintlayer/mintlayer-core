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
        Block, GenBlock, OutPointSourceId, Transaction, TxMainChainIndex,
    },
    primitives::Id,
};
use pos_accounting::{AccountingBlockUndo, FlushablePoSAccountingView, PoSAccountingView};
use thiserror::Error;
use utxo::{FlushableUtxoView, UtxosStorageRead};

use super::{
    error::{TokensError, TxIndexError},
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
    #[error("Tx index error: {0}")]
    TxIndexError(#[from] TxIndexError),
    #[error("BlockUndo error: {0}")]
    UtxoBlockUndoError(#[from] utxo::UtxosBlockUndoError),
    #[error("Transaction index has been disabled")]
    TransactionIndexDisabled,
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("Accounting BlockUndo error: {0}")]
    AccountingBlockUndoError(#[from] pos_accounting::AccountingBlockUndoError),
}

// TODO(Gosha): PoSAccountingView should be replaced with PoSAccountingStorageRead in which the
//              return error type can handle both storage_result::Error and pos_accounting::Error
pub trait TransactionVerifierStorageRef: UtxosStorageRead + PoSAccountingView {
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError>;

    // TODO: Study whether moving this to a closure on tx_verifier construction is helpful.
    //       The issue here is that looking into history prevents testing the tx_verifier independently
    //       where the state of the tx index should be prepared before constructing the tx_verifier
    //       which sabotages the ability to look into the history and find the block that is being
    //       connected with the current tx.
    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error>;

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError>;

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError>;

    fn get_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> Result<Option<AccountingBlockUndo>, TransactionVerifierStorageError>;
}

pub trait TransactionVerifierStorageMut:
    TransactionVerifierStorageRef + FlushableUtxoView + FlushablePoSAccountingView
{
    fn set_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
        tx_index: &TxMainChainIndex,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn del_mainchain_tx_index(
        &mut self,
        tx_id: &OutPointSourceId,
    ) -> Result<(), TransactionVerifierStorageError>;

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

    fn set_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &utxo::UtxosBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn del_utxo_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn set_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
        undo: &AccountingBlockUndo,
    ) -> Result<(), TransactionVerifierStorageError>;

    fn del_accounting_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), TransactionVerifierStorageError>;
}

impl<T: Deref> TransactionVerifierStorageRef for T
where
    T::Target: TransactionVerifierStorageRef,
{
    fn get_token_id_from_issuance_tx(
        &self,
        tx_id: Id<Transaction>,
    ) -> Result<Option<TokenId>, TransactionVerifierStorageError> {
        self.deref().get_token_id_from_issuance_tx(tx_id)
    }

    fn get_gen_block_index(
        &self,
        block_id: &Id<GenBlock>,
    ) -> Result<Option<GenBlockIndex>, storage_result::Error> {
        self.deref().get_gen_block_index(block_id)
    }

    fn get_mainchain_tx_index(
        &self,
        tx_id: &OutPointSourceId,
    ) -> Result<Option<TxMainChainIndex>, TransactionVerifierStorageError> {
        self.deref().get_mainchain_tx_index(tx_id)
    }

    fn get_token_aux_data(
        &self,
        token_id: &TokenId,
    ) -> Result<Option<TokenAuxiliaryData>, TransactionVerifierStorageError> {
        self.deref().get_token_aux_data(token_id)
    }

    fn get_accounting_undo(
        &self,
        id: Id<Block>,
    ) -> Result<Option<AccountingBlockUndo>, TransactionVerifierStorageError> {
        self.deref().get_accounting_undo(id)
    }
}
