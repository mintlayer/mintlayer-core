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

use postgres::NoTls;
use r2d2_postgres::r2d2;
use r2d2_postgres::PostgresConnectionManager;

use crate::storage::storage_api::ApiServerStorageError;

use self::transactional::ApiServerPostgresTransactionalRo;
use self::transactional::ApiServerPostgresTransactionalRw;

pub struct Postgres {
    pool: r2d2::Pool<PostgresConnectionManager<NoTls>>,
}

impl Postgres {
    pub fn new(
        host: &str,
        user: &str,
        max_connections: u32,
    ) -> Result<Self, ApiServerStorageError> {
        let config: postgres::Config = format!("host={host} user={user}").parse().map_err(
            |e: <postgres::Config as FromStr>::Err| {
                ApiServerStorageError::InitializationError(format!(
                    "Postgres configuration parsing error: {}",
                    e
                ))
            },
        )?;
        let manager = PostgresConnectionManager::new(config, NoTls);
        let pool = r2d2::Pool::builder().max_size(max_connections).build(manager).map_err(|e| {
            ApiServerStorageError::InitializationError(format!(
                "Postgres connection pool creation error: {}",
                e
            ))
        })?;
        Ok(Self { pool })
    }

    pub fn begin_ro_transaction(
        &self,
    ) -> Result<ApiServerPostgresTransactionalRo, ApiServerStorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRo::from_connection(conn)
    }

    pub fn begin_rw_transaction(
        &self,
    ) -> Result<ApiServerPostgresTransactionalRw, ApiServerStorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRw::from_connection(conn)
    }
}
