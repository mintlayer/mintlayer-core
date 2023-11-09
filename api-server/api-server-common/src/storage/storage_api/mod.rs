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

use std::collections::BTreeSet;

use common::{
    chain::{
        Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId, SignedTransaction,
        Transaction,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::PoolData;
use serialization::{Decode, Encode};

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

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct Delegation {
    spend_destination: Destination,
    pool_id: PoolId,
    pledge_amount: Amount,
}

impl Delegation {
    pub fn new(spend_destination: Destination, pool_id: PoolId, pledge_amount: Amount) -> Self {
        Self {
            spend_destination,
            pool_id,
            pledge_amount,
        }
    }

    pub fn spend_destination(&self) -> &Destination {
        &self.spend_destination
    }

    pub fn pool_id(&self) -> &PoolId {
        &self.pool_id
    }

    pub fn pledge_amount(&self) -> Amount {
        self.pledge_amount
    }
}

#[async_trait::async_trait]
pub trait ApiServerStorageRead: Sync {
    async fn is_initialized(&self) -> Result<bool, ApiServerStorageError>;

    async fn get_storage_version(&self) -> Result<Option<u32>, ApiServerStorageError>;

    async fn get_address_balance(
        &self,
        address: &str,
    ) -> Result<Option<Amount>, ApiServerStorageError>;

    async fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<Id<Transaction>>, ApiServerStorageError>;

    async fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError>;

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiServerStorageError>;

    async fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError>;

    async fn get_delegation(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Delegation>, ApiServerStorageError>;

    async fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError>;

    async fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<PoolData>, ApiServerStorageError>;

    #[allow(clippy::type_complexity)]
    async fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerStorageWrite: ApiServerStorageRead {
    async fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_address_transactions_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_address_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_address_transactions_at_height(
        &mut self,
        address: &str,
        transaction_ids: BTreeSet<Id<Transaction>>,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_delegation_at_height(
        &mut self,
        delegation_id: DelegationId,
        delegation: &Delegation,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError>;

    async fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;

    async fn set_pool_data_at_height(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolData,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerTransactionRw: ApiServerStorageWrite + ApiServerStorageRead {
    async fn commit(self) -> Result<(), ApiServerStorageError>;
    async fn rollback(self) -> Result<(), ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait ApiServerTransactionRo: ApiServerStorageRead {
    async fn close(self) -> Result<(), ApiServerStorageError>;
}

#[async_trait::async_trait]
pub trait Transactional<'tx> {
    /// Associated read-only transaction type.
    type TransactionRo: ApiServerTransactionRo + Send + 'tx;

    /// Associated read-write transaction type.
    type TransactionRw: ApiServerTransactionRw + Send + 'tx;

    /// Start a read-only transaction.
    async fn transaction_ro<'db: 'tx>(
        &'db self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError>;

    /// Start a read-write transaction.
    async fn transaction_rw<'db: 'tx>(
        &'db mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError>;
}

pub trait ApiServerStorage: for<'tx> Transactional<'tx> + Send + Sync {}
