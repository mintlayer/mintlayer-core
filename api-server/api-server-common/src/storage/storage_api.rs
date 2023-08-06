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
    chain::{Block, Transaction},
    primitives::{BlockHeight, Id},
};

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ApiStorageError {
    #[error("Low level storage error: {0}")]
    StorageError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

pub trait ApiStorageRead {
    fn get_storage_version(&self) -> Result<Option<u32>, ApiStorageError>;

    fn get_best_block(&self) -> Result<(BlockHeight, Id<Block>), ApiStorageError>;

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiStorageError>;

    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<Transaction>, ApiStorageError>;
}

pub trait ApiStorageWrite: ApiStorageRead {
    fn set_storage_version(&mut self, version: u32) -> Result<(), ApiStorageError>;

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiStorageError>;

    fn set_block(&mut self, block_id: Id<Block>, block: Block) -> Result<(), ApiStorageError>;

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        transaction: Transaction,
    ) -> Result<(), ApiStorageError>;
}

pub trait ApiTransactionRw: ApiStorageWrite + ApiStorageRead {
    fn commit(self) -> Result<(), ApiStorageError>;
    fn rollback(self) -> Result<(), ApiStorageError>;
}

pub trait ApiTransactionRo: ApiStorageRead {
    fn close(self) -> Result<(), ApiStorageError>;
}

pub trait Transactional<'t> {
    /// Associated read-only transaction type.
    type TransactionRo: ApiTransactionRo + 't;

    /// Associated read-write transaction type.
    type TransactionRw: ApiTransactionRw + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Result<Self::TransactionRo, ApiStorageError>;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Result<Self::TransactionRw, ApiStorageError>;
}

pub trait ApiStorage: ApiStorageWrite + for<'tx> Transactional<'tx> + Send {}
