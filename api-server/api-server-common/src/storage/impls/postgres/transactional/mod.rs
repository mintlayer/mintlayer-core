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

use std::sync::Arc;

use bb8_postgres::{bb8::PooledConnection, PostgresConnectionManager};
use common::{
    chain::{Block, ChainConfig, PoolId, Transaction},
    primitives::{BlockHeight, Id},
};
use tokio_postgres::NoTls;

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageError, ApiServerTransactionRo,
    ApiServerTransactionRw, BlockInfo, PoolDataWithExtraInfo, TransactionInfo, Transactional,
};

use super::{queries::QueryFromConnection, TransactionalApiServerPostgresStorage};

const CONN_ERR: &str = "CRITICAL: failed to get postgres tx connection. Invariant broken.";

pub struct ApiServerPostgresTransactionalRo<'a> {
    // Note: This is an Option due to needing to pry the connection out of Self in Drop
    connection: Option<PooledConnection<'static, PostgresConnectionManager<NoTls>>>,
    finished: bool,
    db_tx_sender: tokio::sync::mpsc::UnboundedSender<
        PooledConnection<'static, PostgresConnectionManager<NoTls>>,
    >,
    chain_config: Arc<ChainConfig>,
    // Note: This exists to enforce that a transaction never outlives the database object,
    //       given that all connections have 'static lifetimes
    _marker: std::marker::PhantomData<&'a ()>,
}

impl ApiServerPostgresTransactionalRo<'_> {
    pub(super) async fn from_connection(
        connection: PooledConnection<'static, PostgresConnectionManager<NoTls>>,
        db_tx_sender: tokio::sync::mpsc::UnboundedSender<
            PooledConnection<'static, PostgresConnectionManager<NoTls>>,
        >,
        chain_config: Arc<ChainConfig>,
    ) -> Result<Self, ApiServerStorageError> {
        let tx = Self {
            connection: Some(connection),
            finished: false,
            db_tx_sender,
            chain_config,
            _marker: std::marker::PhantomData,
        };
        tx.connection
            .as_ref()
            .expect(CONN_ERR)
            .batch_execute("BEGIN READ ONLY")
            .await
            .map_err(|e| {
                ApiServerStorageError::RoTxBeginFailed(format!("Transaction begin failed: {}", e))
            })?;
        Ok(tx)
    }

    pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.is_initialized().await?;

        Ok(res)
    }

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_storage_version().await?;

        Ok(res)
    }

    pub async fn get_best_block(&mut self) -> Result<BlockAuxData, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_best_block().await?;

        Ok(res)
    }

    pub async fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_main_chain_block_id(block_height).await?;

        Ok(res)
    }

    pub async fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockInfo>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block(block_id).await?;

        Ok(res)
    }

    pub async fn get_pool_data(
        &mut self,
        pool_id: PoolId,
    ) -> Result<Option<PoolDataWithExtraInfo>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_pool_data(pool_id, &self.chain_config).await?;

        Ok(res)
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, TransactionInfo)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_transaction(transaction_id).await?;

        Ok(res)
    }

    pub async fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block_aux_data(block_id).await?;

        Ok(res)
    }
}

pub struct ApiServerPostgresTransactionalRw<'a> {
    // Note: This is an Option due to needing to pry the connection out of Self in Drop
    connection: Option<PooledConnection<'static, PostgresConnectionManager<NoTls>>>,
    finished: bool,
    db_tx_sender: tokio::sync::mpsc::UnboundedSender<
        PooledConnection<'static, PostgresConnectionManager<NoTls>>,
    >,
    chain_config: Arc<ChainConfig>,
    // Note: This exists to enforce that a transaction never outlives the database object,
    //       given that all connections have 'static lifetimes
    _marker: std::marker::PhantomData<&'a ()>,
}

impl Drop for ApiServerPostgresTransactionalRw<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.db_tx_sender
                .send(self.connection.take().expect(CONN_ERR))
                .unwrap_or_else(|e| {
                    logging::log::error!(
                        "CRITICAL: failed to send postgres RW transaction connection for closure: {e}"
                    )
                });
        }
    }
}

impl ApiServerPostgresTransactionalRw<'_> {
    pub(super) async fn from_connection(
        connection: PooledConnection<'static, PostgresConnectionManager<NoTls>>,
        db_tx_sender: tokio::sync::mpsc::UnboundedSender<
            PooledConnection<'static, PostgresConnectionManager<NoTls>>,
        >,
        chain_config: Arc<ChainConfig>,
    ) -> Result<Self, ApiServerStorageError> {
        let tx = Self {
            connection: Some(connection),
            finished: false,
            db_tx_sender,
            chain_config,
            _marker: std::marker::PhantomData,
        };
        tx.connection
            .as_ref()
            .expect(CONN_ERR)
            .batch_execute("BEGIN READ WRITE")
            .await
            .map_err(|e| {
                ApiServerStorageError::RwTxBeginFailed(format!("Transaction begin failed: {}", e))
            })?;
        Ok(tx)
    }
}

#[async_trait::async_trait]
impl ApiServerTransactionRw for ApiServerPostgresTransactionalRw<'_> {
    async fn commit(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        self.connection
            .as_ref()
            .expect(CONN_ERR)
            .batch_execute("COMMIT")
            .await
            .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))?;
        self.finished = true;
        Ok(())
    }

    async fn rollback(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        self.connection
            .as_ref()
            .expect(CONN_ERR)
            .batch_execute("ROLLBACK")
            .await
            .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))?;
        self.finished = true;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ApiServerTransactionRo for ApiServerPostgresTransactionalRo<'_> {
    async fn close(self) -> Result<(), ApiServerStorageError> {
        Ok(())
    }
}

impl Drop for ApiServerPostgresTransactionalRo<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.db_tx_sender
                .send(self.connection.take().expect(CONN_ERR))
                .unwrap_or_else(|e| {
                    logging::log::error!(
                        "CRITICAL: failed to send postgres RO transaction connection for closure: {e}"
                    )
                });
        }
    }
}

#[async_trait::async_trait]
impl<'tx> Transactional<'tx> for TransactionalApiServerPostgresStorage {
    type TransactionRo = ApiServerPostgresTransactionalRo<'tx>;

    type TransactionRw = ApiServerPostgresTransactionalRw<'tx>;

    async fn transaction_ro<'db: 'tx>(
        &'db self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        self.begin_ro_transaction().await
    }

    async fn transaction_rw<'db: 'tx>(
        &'db mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        self.begin_rw_transaction().await
    }
}

impl ApiServerStorage for TransactionalApiServerPostgresStorage {}
