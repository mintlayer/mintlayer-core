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
                    e.to_string()
                ))
            },
        )?;
        let manager = PostgresConnectionManager::new(config, NoTls);
        let pool = r2d2::Pool::builder().max_size(max_connections).build(manager).map_err(|e| {
            ApiServerStorageError::InitializationError(format!(
                "Postgres connection pool creation error: {}",
                e.to_string()
            ))
        })?;
        Ok(Self { pool })
    }

    pub fn begin_ro_transaction<'a>(
        &'a self,
    ) -> Result<ApiServerPostgresTransactionalRo, ApiServerStorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRo::from_connection(conn)
    }

    pub fn begin_rw_transaction<'a>(
        &'a self,
    ) -> Result<ApiServerPostgresTransactionalRw, ApiServerStorageError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| ApiServerStorageError::AcquiringConnectionFailed(e.to_string()))?;
        ApiServerPostgresTransactionalRw::from_connection(conn)
    }
}
