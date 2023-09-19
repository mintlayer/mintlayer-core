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

use crate::storage::{
    impls::postgres::queries::QueryFromConnection, storage_api::ApiServerStorageRead,
};

use super::{ApiServerPostgresTransactionalRo, CONN_ERR};

#[async_trait::async_trait]
impl<'a> ApiServerStorageRead for ApiServerPostgresTransactionalRo<'a> {
    async fn is_initialized(
        &mut self,
    ) -> Result<bool, crate::storage::storage_api::ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.is_initialized().await?;

        Ok(res)
    }

    async fn get_storage_version(
        &mut self,
    ) -> Result<Option<u32>, crate::storage::storage_api::ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_storage_version().await?;

        Ok(res)
    }

    async fn get_best_block(
        &mut self,
    ) -> Result<
        (
            common::primitives::BlockHeight,
            common::primitives::Id<common::chain::GenBlock>,
        ),
        crate::storage::storage_api::ApiServerStorageError,
    > {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_best_block().await?;

        Ok(res)
    }

    async fn get_block(
        &mut self,
        block_id: common::primitives::Id<common::chain::Block>,
    ) -> Result<Option<common::chain::Block>, crate::storage::storage_api::ApiServerStorageError>
    {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block(block_id).await?;

        Ok(res)
    }

    async fn get_block_aux_data(
        &mut self,
        block_id: common::primitives::Id<common::chain::Block>,
    ) -> Result<
        Option<crate::storage::storage_api::block_aux_data::BlockAuxData>,
        crate::storage::storage_api::ApiServerStorageError,
    > {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block_aux_data(block_id).await?;

        Ok(res)
    }

    async fn get_main_chain_block_id(
        &mut self,
        block_height: common::primitives::BlockHeight,
    ) -> Result<
        Option<common::primitives::Id<common::chain::Block>>,
        crate::storage::storage_api::ApiServerStorageError,
    > {
        self.get_main_chain_block_id(block_height).await
    }

    async fn get_transaction(
        &mut self,
        transaction_id: common::primitives::Id<common::chain::Transaction>,
    ) -> Result<
        Option<(
            Option<common::primitives::Id<common::chain::Block>>,
            common::chain::SignedTransaction,
        )>,
        crate::storage::storage_api::ApiServerStorageError,
    > {
        self.get_transaction(transaction_id).await
    }
}
