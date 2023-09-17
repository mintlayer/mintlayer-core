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

use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use postgres::NoTls;
use r2d2_postgres::{r2d2::PooledConnection, PostgresConnectionManager};

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageError, ApiServerTransactionRo,
    ApiServerTransactionRw, Transactional,
};

use super::{queries::QueryFromConnection, TransactionalApiServerPostgresStorage};

#[ouroboros::self_referencing]
pub struct ApiServerPostgresTransactionalRo {
    connection: PooledConnection<PostgresConnectionManager<NoTls>>,
    #[borrows(mut connection)]
    // TODO(PR): Dear reviewer, is the lifetime below covariant? It does look covariant to me.
    #[covariant]
    transaction: postgres::Transaction<'this>,
}

const TX_ERR: &str = "Transaction must exist until destruction";

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

    #[allow(clippy::type_complexity)]
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
    // TODO(PR): Dear reviewer, is the lifetime below covariant? It does look covariant to me.
    #[covariant]
    // Note: This Option is required to make destruction by value possible. See commit() method.
    transaction: Option<postgres::Transaction<'this>>,
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
                    .map(Some)
                    .map_err(|e| ApiServerStorageError::RwTxBeginFailed(e.to_string()))
            },
        }
        .try_build()?;
        Ok(tx)
    }
}

impl ApiServerTransactionRw for ApiServerPostgresTransactionalRw {
    fn commit(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_taker = tx.take();
            tx_taker.expect(TX_ERR).commit()
        })
        .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))
    }

    fn rollback(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }
}

impl ApiServerTransactionRo for ApiServerPostgresTransactionalRo {
    fn close(self) -> Result<(), ApiServerStorageError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'t> Transactional<'t> for TransactionalApiServerPostgresStorage {
    type TransactionRo = ApiServerPostgresTransactionalRo;

    type TransactionRw = ApiServerPostgresTransactionalRw;

    async fn transaction_ro<'s: 't>(
        &'s self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        self.begin_ro_transaction()
    }

    async fn transaction_rw<'s: 't>(
        &'s mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        self.begin_rw_transaction()
    }
}

impl ApiServerStorage for TransactionalApiServerPostgresStorage {}
