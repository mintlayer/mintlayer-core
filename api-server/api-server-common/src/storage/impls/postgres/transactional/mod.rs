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

#[ouroboros::self_referencing]
pub struct ApiServerPostgresTransactionalRo<'a> {
    connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    #[borrows(mut connection)]
    // TODO(PR): Dear reviewer, is the lifetime below covariant? It does look covariant to me.
    #[covariant]
    transaction: tokio_postgres::Transaction<'this>,
}

const TX_ERR: &str = "Transaction must exist until destruction";

impl<'a> ApiServerPostgresTransactionalRo<'a> {
    pub(super) async fn from_connection(
        connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    ) -> Result<ApiServerPostgresTransactionalRo, ApiServerStorageError> {
        let tx = ApiServerPostgresTransactionalRoAsyncTryBuilder {
            connection,
            transaction_builder: |conn| {
                Box::pin(async {
                    conn.build_transaction()
                        .read_only(true)
                        .start()
                        .await
                        .map_err(|e| ApiServerStorageError::RoTxBeginFailed(e.to_string()))
                })
            },
        }
        .try_build()
        .await?;
        Ok(tx)
    }

    pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.is_initialized().await?;

        Ok(res)
    }

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.get_storage_version().await?;

        Ok(res)
    }

    pub async fn get_best_block(
        &mut self,
    ) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.get_best_block().await?;

        Ok(res)
    }

    pub async fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.get_main_chain_block_id(block_height).await?;

        Ok(res)
    }

    pub async fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.get_block(block_id).await?;

        Ok(res)
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.get_transaction(transaction_id).await?;

        Ok(res)
    }

    pub async fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let tx = self.borrow_transaction();
        let mut conn = QueryFromConnection::new(tx);
        let res = conn.get_block_aux_data(block_id).await?;

        Ok(res)
    }
}

#[ouroboros::self_referencing]
pub struct ApiServerPostgresTransactionalRw<'a> {
    connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    #[borrows(mut connection)]
    // TODO(PR): Dear reviewer, is the lifetime below covariant? It does look covariant to me.
    #[covariant]
    // Note: This Option is required to make destruction by value possible. See commit() method.
    transaction: Option<tokio_postgres::Transaction<'this>>,
}

impl<'a> ApiServerPostgresTransactionalRw<'a> {
    pub(super) async fn from_connection(
        connection: PooledConnection<'a, PostgresConnectionManager<NoTls>>,
    ) -> Result<ApiServerPostgresTransactionalRw<'a>, ApiServerStorageError> {
        let tx = ApiServerPostgresTransactionalRwAsyncTryBuilder {
            connection,
            transaction_builder: |conn| {
                Box::pin(async {
                    conn.build_transaction()
                        .read_only(true)
                        .start()
                        .await
                        .map(Some)
                        .map_err(|e| ApiServerStorageError::RwTxBeginFailed(e.to_string()))
                })
            },
        }
        .try_build()
        .await?;
        Ok(tx)
    }
}

#[async_trait::async_trait]
impl<'a> ApiServerTransactionRw for ApiServerPostgresTransactionalRw<'a> {
    async fn commit(mut self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_taker = tx.take();
            tx_taker.expect(TX_ERR).commit()
        })
        .await
        .map_err(|e| ApiServerStorageError::TxCommitFailed(e.to_string()))
    }

    async fn rollback(self) -> Result<(), crate::storage::storage_api::ApiServerStorageError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'a> ApiServerTransactionRo for ApiServerPostgresTransactionalRo<'a> {
    async fn close(self) -> Result<(), ApiServerStorageError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl<'t> Transactional<'t> for TransactionalApiServerPostgresStorage {
    type TransactionRo = ApiServerPostgresTransactionalRo<'t>;

    type TransactionRw = ApiServerPostgresTransactionalRw<'t>;

    async fn transaction_ro<'s: 't>(
        &'s self,
    ) -> Result<Self::TransactionRo, ApiServerStorageError> {
        // TODO(PR): finish this
        // let t = self.begin_ro_transaction().await?;
        // Ok(t)
        todo!()
    }

    async fn transaction_rw<'s: 't>(
        &'s mut self,
    ) -> Result<Self::TransactionRw, ApiServerStorageError> {
        // TODO(PR): finish this
        // self.begin_rw_transaction().await
        todo!()
    }
}

impl ApiServerStorage for TransactionalApiServerPostgresStorage {}
