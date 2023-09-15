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

use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};

use crate::storage::{
    impls::postgres::queries::QueryFromConnection,
    storage_api::{
        block_aux_data::BlockAuxData, ApiServerStorageError, ApiServerStorageRead,
        ApiServerStorageWrite,
    },
};

use super::{ApiServerPostgresTransactionalRw, TX_ERR};

impl ApiServerStorageWrite for ApiServerPostgresTransactionalRw {
    fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.initialize_database(chain_config)
        })?;

        Ok(())
    }

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.set_best_block(block_height, block_id)
        })?;

        Ok(())
    }

    fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.set_block(block_id, block)
        })?;

        Ok(())
    }

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.set_transaction(transaction_id, owning_block, transaction)
        })?;

        Ok(())
    }

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.set_block_aux_data(block_id, block_aux_data)
        })?;

        Ok(())
    }

    fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.set_main_chain_block_id(block_height, block_id)
        })?;

        Ok(())
    }

    fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.del_main_chain_block_id(block_height)
        })?;

        Ok(())
    }
}

impl ApiServerStorageRead for ApiServerPostgresTransactionalRw {
    fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.is_initialized()
        })?;

        Ok(res)
    }

    fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.get_storage_version()
        })?;

        Ok(res)
    }

    fn get_best_block(&mut self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.get_best_block()
        })?;

        Ok(res)
    }

    fn get_block(&mut self, block_id: Id<Block>) -> Result<Option<Block>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.get_block(block_id)
        })?;

        Ok(res)
    }

    fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.get_block_aux_data(block_id)
        })?;

        Ok(res)
    }

    fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.get_main_chain_block_id(block_height)
        })?;

        Ok(res)
    }

    fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
        let res = self.with_transaction_mut(|tx| {
            let tx_ref = tx.as_mut().expect(TX_ERR);
            let mut conn = QueryFromConnection::new(tx_ref);
            conn.get_transaction(transaction_id)
        })?;

        Ok(res)
    }
}
