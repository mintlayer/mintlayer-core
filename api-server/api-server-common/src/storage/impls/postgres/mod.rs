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

pub mod listener;
pub mod transactional;

mod queries;

use std::sync::Arc;

use bb8_postgres::PostgresConnectionManager;
use bb8_postgres::bb8::Pool;
use bb8_postgres::bb8::PooledConnection;
use common::chain::ChainConfig;
use tokio_postgres::NoTls;

use crate::storage::storage_api::ApiServerStorageError;

use self::transactional::ApiServerPostgresTransactionalRo;
use self::transactional::ApiServerPostgresTransactionalRw;

pub use self::listener::{PostgresEventListener, PostgresStreamEventSource};

pub struct TransactionalApiServerPostgresStorage {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    /// The connection configuration, used to create dedicated connections, e.g. for LISTEN/NOTIFY.
    connection_config: tokio_postgres::Config,
    /// This task is responsible for rolling back failed RW/RO transactions, since closing connections are pooled
    tx_dropper_joiner: tokio::task::JoinHandle<()>,
    /// This channel is used to send transactions that are not manually rolled back to the tx_dropper task to roll them back
    db_tx_conn_sender: tokio::sync::mpsc::UnboundedSender<
        PooledConnection<'static, PostgresConnectionManager<NoTls>>,
    >,
    chain_config: Arc<ChainConfig>,
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
        password: Option<&str>,
        database: Option<&str>,
        max_connections: u32,
        chain_config: Arc<ChainConfig>,
    ) -> Result<Self, ApiServerStorageError> {
        // The configuration is built from the discrete fields instead of a connection
        // string, so the password never exists as a string that a parse error could echo.
        let database = match database {
            Some(d) => d.to_owned(),
            None => format!("mintlayer-{}", chain_config.chain_type().name()),
        };
        logging::log::debug!(
            "Using postgres config: host={host} port={port} user={user} password={} database={database}",
            if password.is_some() {
                crate::REDACTED
            } else {
                "<unset>"
            }
        );

        let mut config = tokio_postgres::Config::new();
        config.host(host).port(port).user(user).dbname(database);
        if let Some(password) = password {
            config.password(password);
        }

        let manager = PostgresConnectionManager::new(config.clone(), NoTls);
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
                        "CRITICAL: failed to rollback failed postgres RW transaction: {e}"
                    )
                });
            }
        });

        let result = Self {
            pool,
            connection_config: config,
            tx_dropper_joiner,
            db_tx_conn_sender: conn_tx,
            chain_config,
        };

        Ok(result)
    }

    pub async fn begin_ro_transaction(
        &self,
    ) -> Result<ApiServerPostgresTransactionalRo<'_>, ApiServerStorageError> {
        let conn = self
            .pool
            .get_owned()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRo::from_connection(
            conn,
            self.db_tx_conn_sender.clone(),
            self.chain_config.clone(),
        )
        .await
    }

    pub async fn begin_rw_transaction(
        &self,
    ) -> Result<ApiServerPostgresTransactionalRw<'_>, ApiServerStorageError> {
        let conn = self
            .pool
            .get_owned()
            .await
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRw::from_connection(
            conn,
            self.db_tx_conn_sender.clone(),
            self.chain_config.clone(),
        )
        .await
    }
}
