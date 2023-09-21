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

use bb8_postgres::{bb8::PooledConnection, PostgresConnectionManager};
use serialization::{DecodeAll, Encode};

use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use tokio_postgres::NoTls;

use crate::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError},
};

pub struct QueryFromConnection<'a, 'b> {
    tx: &'a PooledConnection<'b, PostgresConnectionManager<NoTls>>,
}

impl<'a, 'b> QueryFromConnection<'a, 'b> {
    fn get_table_exists_query(table_name: &str) -> String {
        format!(
            "SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = '{}'
        ) THEN 1 ELSE 0 END AS count;",
            table_name
        )
    }
}

impl<'a, 'b> QueryFromConnection<'a, 'b> {
    pub fn new(tx: &'a PooledConnection<'b, PostgresConnectionManager<NoTls>>) -> Self {
        Self { tx }
    }

    fn block_height_to_postgres_friendly(block_height: BlockHeight) -> i64 {
        // Postgres doesn't like u64, so we have to convert it to i64, and given BlockDistance limitations, it's OK.
        block_height
            .into_int()
            .try_into()
            .unwrap_or_else(|e| panic!("Invalid block height: {e}"))
    }

    pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let query_str = Self::get_table_exists_query("ml_misc_data");
        let row_count = self
            .tx
            .query_one(&query_str, &[])
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row_count: i64 = row_count.get(0);

        if row_count == 0 {
            return Ok(false);
        }

        let version = self.get_storage_version().await?;

        let version = match version {
            Some(v) => v,
            None => return Ok(false),
        };

        logging::log::info!("Found database version: {version}");

        Ok(true)
    }

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError> {
        let query_result = self
            .tx
            .query_opt(
                "SELECT value FROM ml_misc_data WHERE name = 'version';",
                &[],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match query_result {
            Some(d) => d,
            None => return Ok(None),
        };

        let data: Vec<u8> = row.get(0);

        let version = u32::decode_all(&mut data.as_slice()).map_err(|e| {
            ApiServerStorageError::InvalidInitializedState(format!(
                "Version deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(version))
    }

    pub async fn get_best_block(
        &mut self,
    ) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        let query_result = self
            .tx
            .query_one(
                "SELECT value FROM ml_misc_data WHERE name = 'best_block';",
                &[],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data: Vec<u8> = query_result.get(0);

        let best =
            <(BlockHeight, Id<GenBlock>)>::decode_all(&mut data.as_slice()).map_err(|e| {
                ApiServerStorageError::InvalidInitializedState(format!(
                    "Version deserialization failed: {}",
                    e
                ))
            })?;

        Ok(best)
    }

    pub async fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting best block with block_id {}", block_id);

        self.tx
            .execute(
                "INSERT INTO ml_misc_data (name, value) VALUES (?, ?)
                    ON CONFLICT (name) DO UPDATE
                    SET value = $2;",
                &[&(block_height, block_id).encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    async fn just_execute(&mut self, query: &str) -> Result<(), ApiServerStorageError> {
        self.tx
            .execute(query, &[])
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn create_tables(&mut self) -> Result<(), ApiServerStorageError> {
        logging::log::info!("Creating database tables");

        self.just_execute(
            "CREATE TABLE ml_misc_data (
            name TEXT PRIMARY KEY,
            value BLOB NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_main_chain_blocks (
            block_height bigint PRIMARY KEY,
            block_id BLOB NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_blocks (
                block_id BLOB PRIMARY KEY,
                block_data BLOB NOT NULL
            );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_transactions (
                    transaction_id BLOB PRIMARY KEY,
                    owning_block_id BLOB,
                    transaction_data BLOB NOT NULL
                );", // block_id can be null if the transaction is not in the main chain
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_block_aux_data (
                    block_id BLOB PRIMARY KEY,
                    aux_data BLOB NOT NULL
                );",
        )
        .await?;

        logging::log::info!("Done creating database tables");

        Ok(())
    }

    pub async fn initialize_database(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.create_tables().await?;

        // Insert row to the table
        self.tx
            .execute(
                "INSERT INTO ml_misc_data (name, value) VALUES (?, ?)",
                &[&"version", &CURRENT_STORAGE_VERSION.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        self.set_best_block(0.into(), chain_config.genesis_block_id()).await?;

        Ok(())
    }

    pub async fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        let row = self
            .tx
            .query_opt(
                "SELECT block_id FROM ml_main_chain_blocks WHERE block_height = ?;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let data: Vec<u8> = data.get(0);

        let block_id = Id::<Block>::decode_all(&mut data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Block id deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(block_id))
    }

    pub async fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        logging::log::debug!("Inserting block id: {:?} for height: {}", block_id, height);

        self.tx
            .execute(
                "INSERT INTO ml_main_chain_blocks (block_height, block_id) VALUES ($1, $2)
                    ON CONFLICT (block_height) DO UPDATE
                    SET block_id = $2;",
                &[&height, &block_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_main_chain_blocks
                WHERE block_height = $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT block_data FROM ml_blocks WHERE block_id = ?;",
                &[&block_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let data: Vec<u8> = data.get(0);

        let block = Block::decode_all(&mut data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Block {} deserialization failed: {}",
                block_id, e
            ))
        })?;

        Ok(Some(block))
    }

    pub async fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting block with id: {:?}", block_id);

        self.tx
            .execute(
                "INSERT INTO ml_blocks (block_id, block_data) VALUES ($1, $2)
                    ON CONFLICT (block_id) DO UPDATE
                    SET block_data = $2;",
                &[&block_id.encode(), &block.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
        let row = self.tx.query_opt(
                "SELECT owning_block_id, transaction_data FROM ml_transactions WHERE transaction_id = ?;",&[&transaction_id.encode()]
            ).await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let block_id_data: Option<Vec<u8>> = data.get(0);
        let transaction_data: Vec<u8> = data.get(1);

        let block_id = {
            let deserialized_block_id =
                block_id_data.map(|d| Id::<Block>::decode_all(&mut d.as_slice())).transpose();
            deserialized_block_id.map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Block deserialization failed: {}",
                    e
                ))
            })?
        };

        let transaction =
            SignedTransaction::decode_all(&mut transaction_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Transaction {} deserialization failed: {}",
                    transaction_id, e
                ))
            })?;

        Ok(Some((block_id, transaction)))
    }

    pub async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!(
            "Inserting transaction with id {}, owned by block {:?}",
            transaction_id,
            owning_block
        );

        self.tx.execute(
                "INSERT INTO ml_transactions (transaction_id, owning_block_id, transaction_data) VALUES ($1, $2, $3)
                    ON CONFLICT (transaction_id) DO UPDATE
                    SET owning_block_id = $2, transaction_data = $3;", &[&transaction_id.encode(), &owning_block.map(|v|v.encode()), &transaction.encode()]
            ).await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT aux_data FROM ml_block_aux_data WHERE block_id = ?;",
                &[&block_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let serialized_data: Vec<u8> = row.get(0);

        let block_aux_data =
            BlockAuxData::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Block aux data of block id {} deserialization failed: {}",
                    block_id, e
                ))
            })?;

        Ok(Some(block_aux_data))
    }

    pub async fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting block aux data with block_id {}", block_id);

        self.tx
            .execute(
                "INSERT INTO ml_block_aux_data (block_id, aux_data) VALUES ($1, $2)
                    ON CONFLICT (block_id) DO UPDATE
                    SET aux_data = $2;",
                &[&block_id.encode(), &block_aux_data.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }
}
