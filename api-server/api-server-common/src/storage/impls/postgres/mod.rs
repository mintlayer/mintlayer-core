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

pub mod transactional;

mod queries;

use std::str::FromStr;

use bb8_postgres::bb8::Pool;
use bb8_postgres::bb8::PooledConnection;
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;

use crate::storage::storage_api::ApiServerStorageError;
use crate::storage::storage_api::ApiServerStorageRead;
use crate::storage::storage_api::ApiServerStorageWrite;
use crate::storage::storage_api::ApiServerTransactionRw;

use self::transactional::ApiServerPostgresTransactionalRo;
use self::transactional::ApiServerPostgresTransactionalRw;

pub struct TransactionalApiServerPostgresStorage {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    /// This task is responsible for rolling back failed RW/RO transactions, since closing connections are pooled
    tx_dropper_joiner: tokio::task::JoinHandle<()>,
    /// This channel is used to send transactions that are not manually rolled back to the tx_dropper task to roll them back
    db_tx_conn_sender: tokio::sync::mpsc::UnboundedSender<
        PooledConnection<'static, PostgresConnectionManager<NoTls>>,
    >,
}

impl Drop for TransactionalApiServerPostgresStorage {
    fn drop(&mut self) {
        // Since the whole connection pool will be destroyed, we can safely abort all connections
        self.tx_dropper_joiner.abort();
    }
}

impl TransactionalApiServerPostgresStorage {
    pub async fn new(
        host: &str,
        port: u16,
        user: &str,
        max_connections: u32,
        chain_config: &common::chain::ChainConfig,
    ) -> Result<Self, ApiServerStorageError> {
        let config: tokio_postgres::Config = format!("host={host} port={port} user={user}")
            .parse()
            .map_err(|e: <tokio_postgres::Config as FromStr>::Err| {
                ApiServerStorageError::InitializationError(format!(
                    "Postgres configuration parsing error: {}",
                    e
                ))
            })?;
        let manager = PostgresConnectionManager::new(config, NoTls);
        let pool = Pool::builder().max_size(max_connections).build(manager).await.map_err(|e| {
            ApiServerStorageError::InitializationError(format!(
                "Postgres connection pool creation error: {}",
                e
            ))
        })?;

        let (conn_tx, conn_rx) = tokio::sync::mpsc::unbounded_channel::<
            PooledConnection<'static, PostgresConnectionManager<NoTls>>,
        >();

        let tx_dropper_joiner = tokio::task::spawn(async move {
            let mut conn_rx = conn_rx;
            while let Some(conn) = conn_rx.recv().await {
                conn.batch_execute("ROLLBACK").await.unwrap_or_else(|e| {
                    logging::log::error!(
                        "CRITICAL ERROR: failed to rollback failed postgres RW transaction: {e}"
                    )
                });
            }
        });

        let result = Self {
            pool,
            tx_dropper_joiner,
            db_tx_conn_sender: conn_tx,
        };

        result.initialize_if_not(chain_config).await?;

        Ok(result)
    }

    async fn initialize_if_not(
        &self,
        chain_config: &common::chain::ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let mut tx = self.begin_rw_transaction().await?;
        if !tx.is_initialized().await? {
            tx.initialize_storage(chain_config).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn begin_ro_transaction(
        &self,
    ) -> Result<ApiServerPostgresTransactionalRo, ApiServerStorageError> {
        let conn = self
            .pool
            .get_owned()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRo::from_connection(conn, self.db_tx_conn_sender.clone())
            .await
    }

    pub async fn begin_rw_transaction(
        &self,
    ) -> Result<ApiServerPostgresTransactionalRw, ApiServerStorageError> {
        let conn = self
            .pool
            .get_owned()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRw::from_connection(conn, self.db_tx_conn_sender.clone())
            .await
    }
}
