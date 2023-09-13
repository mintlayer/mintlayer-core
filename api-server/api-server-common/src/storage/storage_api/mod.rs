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

use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};

use self::block_aux_data::BlockAuxData;
pub mod block_aux_data;

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ApiServerStorageError {
    #[error("Low level storage error: {0}")]
    LowLevelStorageError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Storage initialization failed: {0}")]
    InitializationError(String),
    #[error("Invalid initialized state")]
    InvalidInitializedState(String),
    #[error("Acquiring connection from the pool/transaction failed with error: {0}")]
    AcquiringConnectionFailed(String),
    #[error("Read-only tx begin failed: {0}")]
    RoTxBeginFailed(String),
    #[error("Read/write tx begin failed: {0}")]
    RwTxBeginFailed(String),
    #[error("Transaction commit failed: {0}")]
    TxCommitFailed(String),
    #[error("Transaction rw rollback failed: {0}")]
    TxRwRollbackFailed(String),
}

pub trait ApiServerStorageRead {
    fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError>;

    fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError>;

    fn get_best_block(&mut self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError>;

    fn get_block(&mut self, block_id: Id<Block>) -> Result<Option<Block>, ApiServerStorageError>;

    fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError>;

    fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError>;

    #[allow(clippy::type_complexity)]
    fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError>;
}

pub trait ApiServerStorageWrite: ApiServerStorageRead {
    fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError>;

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError>;

    fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError>;

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError>;

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError>;

    fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError>;

    fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;
}

pub trait ApiTransactionRw: ApiServerStorageWrite + ApiServerStorageRead {
    fn commit(self) -> Result<(), ApiServerStorageError>;
    fn rollback(self) -> Result<(), ApiServerStorageError>;
}

pub trait ApiServerTransactionRo: ApiServerStorageRead {
    fn close(self) -> Result<(), ApiServerStorageError>;
}

pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: ApiServerTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: ApiTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, ApiServerStorageError>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s mut self) -> Result<Self::TransactionRw, ApiServerStorageError>;
}

pub trait ApiServerStorage: for<'tx> Transactional<'tx> + Send + Sync {}
