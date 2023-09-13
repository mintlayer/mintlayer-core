pub mod read;
pub mod write;

use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use postgres::NoTls;
use r2d2_postgres::{r2d2::PooledConnection, PostgresConnectionManager};

use crate::storage::storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError};

use super::queries::QueryFromConnection;

#[ouroboros::self_referencing]
pub struct ApiServerPostgresTransactionalRo {
    connection: PooledConnection<PostgresConnectionManager<NoTls>>,
    #[borrows(mut connection)]
    #[covariant]
    // TODO(PR): Dear reviewer, is the lifetime below covariant? It does look covariant to me.
    transaction: postgres::Transaction<'this>,
}

impl ApiServerPostgresTransactionalRo {
    pub(super) fn from_connection(
        connection: PooledConnection<PostgresConnectionManager<NoTls>>,
    ) -> Result<Self, ApiServerStorageError> {
        let tx = ApiServerPostgresTransactionalRoTryBuilder {
            connection,
            transaction_builder: |conn| {
                conn.build_transaction()
                    .read_only(true)
                    .start()
                    .map_err(|e| ApiServerStorageError::RoTxBeginFailed(e.to_string()))
            },
        }
        .try_build()?;
        Ok(tx)
    }

    pub fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.is_initialized()
        })?;

        Ok(res)
    }

    pub fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_storage_version()
        })?;

        Ok(res)
    }

    pub fn get_best_block(&mut self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_best_block()
        })?;

        Ok(res)
    }

    pub fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_main_chain_block_id(block_height)
        })?;

        Ok(res)
    }

    pub fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_block(block_id)
        })?;

        Ok(res)
    }

    pub fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_transaction(transaction_id)
        })?;

        Ok(res)
    }

    pub fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_block_aux_data(block_id)
        })?;

        Ok(res)
    }
}

#[ouroboros::self_referencing]
pub struct ApiServerPostgresTransactionalRw {
    connection: PooledConnection<PostgresConnectionManager<NoTls>>,
    #[borrows(mut connection)]
    #[covariant]
    // TODO(PR): Dear reviewer, is the lifetime below covariant? It does look covariant to me.
    transaction: postgres::Transaction<'this>,
}

impl ApiServerPostgresTransactionalRw {
    pub(super) fn from_connection(
        connection: PooledConnection<PostgresConnectionManager<NoTls>>,
    ) -> Result<Self, ApiServerStorageError> {
        let tx = ApiServerPostgresTransactionalRwTryBuilder {
            connection,
            transaction_builder: |conn| {
                conn.build_transaction()
                    .read_only(true)
                    .start()
                    .map_err(|e| ApiServerStorageError::RwTxBeginFailed(e.to_string()))
            },
        }
        .try_build()?;
        Ok(tx)
    }
}
