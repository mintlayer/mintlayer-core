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

pub mod read;
pub mod write;

use bb8_postgres::{bb8::PooledConnection, PostgresConnectionManager};
use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use tokio_postgres::NoTls;

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageError, ApiServerTransactionRo,
    ApiServerTransactionRw, Transactional,
};

use super::{queries::QueryFromConnection, TransactionalApiServerPostgresStorage};

pub struct ApiServerPostgresTransactionalRo<'a> {
    connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    finished: bool,
}

impl<'a> ApiServerPostgresTransactionalRo<'a> {
    pub(super) async fn from_connection(
        connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    ) -> Result<ApiServerPostgresTransactionalRo, ApiServerStorageError> {
        let tx = Self {
            connection,
            finished: false,
        };
        tx.connection.batch_execute("BEGIN READ ONLY").await.map_err(|e| {
            ApiServerStorageError::RoTxBeginFailed(format!("Transaction begin failed: {}", e))
        })?;
        Ok(tx)
    }

    pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.is_initialized().await?;

        Ok(res)
    }

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.get_storage_version().await?;

        Ok(res)
    }

    pub async fn get_best_block(
        &mut self,
    ) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.get_best_block().await?;

        Ok(res)
    }

    pub async fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.get_main_chain_block_id(block_height).await?;

        Ok(res)
    }

    pub async fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.get_block(block_id).await?;

        Ok(res)
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.get_transaction(transaction_id).await?;

        Ok(res)
    }

    pub async fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(&self.connection);
        let res = conn.get_block_aux_data(block_id).await?;

        Ok(res)
    }
}

pub struct ApiServerPostgresTransactionalRw<'a> {
    connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    finished: bool,
}

impl<'a> Drop for ApiServerPostgresTransactionalRw<'a> {
    fn drop(&mut self) {
        if !self.finished {
            // futures::executor::block_on(self.connection.batch_execute("ROLLBACK")).unwrap_or_else(
            //     |e| {
            //         logging::log::error!(
            //             "CRITICAL ERROR: failed to rollback failed postgres RW transaction: {e}"
            //         )
            //     },
            // );
        }
    }
}

impl<'a> ApiServerPostgresTransactionalRw<'a> {
    pub(super) async fn from_connection(
        connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    ) -> Result<ApiServerPostgresTransactionalRw<'a>, ApiServerStorageError> {
        let tx = Self {
            connection,
            finished: false,
        };
        tx.connection.batch_execute("BEGIN READ WRITE").await.map_err(|e| {
            ApiServerStorageError::RwTxBeginFailed(format!("Transaction begin failed: {}", e))
        })?;
        Ok(tx)
    }
}

#[async_trait::async_trait]
impl<'a> ApiServerTransactionRw for ApiServerPostgresTransactionalRw<'a> {
    async fn commit(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        self.connection
            .batch_execute("COMMIT")
            .await
            .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))?;
        self.finished = true;
        Ok(())
    }

    async fn rollback(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        self.connection
            .batch_execute("ROLLBACK")
            .await
            .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))?;
        self.finished = true;
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'a> ApiServerTransactionRo for ApiServerPostgresTransactionalRo<'a> {
    async fn close(self) -> Result<(), ApiServerStorageError> {
        Ok(())
    }
}

impl<'a> Drop for ApiServerPostgresTransactionalRo<'a> {
    fn drop(&mut self) {
        if !self.finished {
            // futures::executor::block_on(self.connection.batch_execute("ROLLBACK")).unwrap_or_else(
            //     |e| {
            //         logging::log::error!(
            //             "CRITICAL ERROR: failed to rollback failed postgres RO transaction: {e}"
            //         )
            //     },
            // );
        }
    }
}

#[async_trait::async_trait]
impl<'t> Transactional<'t> for TransactionalApiServerPostgresStorage {
    type TransactionRo = ApiServerPostgresTransactionalRo<'t>;

    type TransactionRw = ApiServerPostgresTransactionalRw<'t>;

    async fn transaction_ro<'s: 't>(
        &'s self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        self.begin_ro_transaction().await
    }

    async fn transaction_rw<'s: 't>(
        &'s mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        self.begin_rw_transaction().await
    }
}

impl ApiServerStorage for TransactionalApiServerPostgresStorage {}
