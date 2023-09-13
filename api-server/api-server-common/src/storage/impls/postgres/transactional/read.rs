use crate::storage::{
    impls::postgres::queries::QueryFromConnection, storage_api::ApiServerStorageRead,
};

use super::ApiServerPostgresTransactionalRo;

impl ApiServerStorageRead for ApiServerPostgresTransactionalRo {
    fn is_initialized(
        &mut self,
    ) -> Result<bool, crate::storage::storage_api::ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.is_initialized()
        })?;

        Ok(res)
    }

    fn get_storage_version(
        &mut self,
    ) -> Result<Option<u32>, crate::storage::storage_api::ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_storage_version()
        })?;

        Ok(res)
    }

    fn get_best_block(
        &mut self,
    ) -> Result<
        (
            common::primitives::BlockHeight,
            common::primitives::Id<common::chain::GenBlock>,
        ),
        crate::storage::storage_api::ApiServerStorageError,
    > {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_best_block()
        })?;

        Ok(res)
    }

    fn get_block(
        &mut self,
        block_id: common::primitives::Id<common::chain::Block>,
    ) -> Result<Option<common::chain::Block>, crate::storage::storage_api::ApiServerStorageError>
    {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_block(block_id)
        })?;

        Ok(res)
    }

    fn get_block_aux_data(
        &mut self,
        block_id: common::primitives::Id<common::chain::Block>,
    ) -> Result<
        Option<crate::storage::storage_api::block_aux_data::BlockAuxData>,
        crate::storage::storage_api::ApiServerStorageError,
    > {
        let res = self.with_transaction_mut(|tx| {
            let mut conn = QueryFromConnection::new(tx);
            conn.get_block_aux_data(block_id)
        })?;

        Ok(res)
    }

    fn get_main_chain_block_id(
        &mut self,
        block_height: common::primitives::BlockHeight,
    ) -> Result<
        Option<common::primitives::Id<common::chain::Block>>,
        crate::storage::storage_api::ApiServerStorageError,
    > {
        self.get_main_chain_block_id(block_height)
    }

    fn get_transaction(
        &mut self,
        transaction_id: common::primitives::Id<common::chain::Transaction>,
    ) -> Result<
        Option<(
            Option<common::primitives::Id<common::chain::Block>>,
            common::chain::SignedTransaction,
        )>,
        crate::storage::storage_api::ApiServerStorageError,
    > {
        self.get_transaction(transaction_id)
    }
}
