use serialization::{DecodeAll, Encode};

use common::{
    chain::{Block, GenBlock, SignedTransaction, Transaction},
    primitives::{BlockHeight, Id},
};
use sqlx::{database::HasArguments, ColumnIndex, Database, Executor, IntoArguments, Pool};

use crate::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError},
};

pub struct QueryFromConnection<'a, D: Database> {
    conn: &'a mut <D as Database>::Connection,
}

impl<'a, D: Database> QueryFromConnection<'a, D> {
    pub fn new(conn: &'a mut <D as sqlx::Database>::Connection) -> Self {
        Self { conn }
    }

    fn block_height_to_sqlx_friendly(block_height: BlockHeight) -> i64 {
        // sqlx doesn't like u64, so we have to convert it to i64, and given BlockDistance limitations, it's OK.
        block_height
            .into_int()
            .try_into()
            .unwrap_or_else(|e| panic!("Invalid block height: {e}"))
    }

    pub async fn get_storage_version(&mut self) -> Result<Option<u32>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as sqlx::Database>::Connection: Executor<'e>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        let data: Option<(Vec<u8>,)> =
            sqlx::query_as::<_, _>("SELECT value FROM ml_misc_data WHERE name = 'version';")
                .fetch_optional(&mut *self.conn)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let data = match data {
            Some(d) => d,
            None => return Ok(None),
        };

        let version = u32::decode_all(&mut data.0.as_slice()).map_err(|e| {
            ApiServerStorageError::InvalidInitializedState(format!(
                "Version deserialization failed: {}",
                e
            ))
        })?;

        Ok(Some(version))
    }

    pub async fn get_best_block(
        &mut self,
    ) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError>
    where
        D: Database,
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        for<'e> &'e Pool<D>: Executor<'e, Database = D>,
        usize: ColumnIndex<D::Row>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
    {
        let data: (Vec<u8>,) =
            sqlx::query_as("SELECT value FROM ml_misc_data WHERE name = 'best_block';")
                .fetch_one(&mut *self.conn)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let best =
            <(BlockHeight, Id<GenBlock>)>::decode_all(&mut data.0.as_slice()).map_err(|e| {
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
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> &'e str: sqlx::Encode<'e, D>,
        for<'e> &'e str: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting best block with block_id {}", block_id);

        sqlx::query(
            "INSERT INTO ml_misc_data (name, value) VALUES (?, ?)
                ON CONFLICT (name) DO UPDATE
                SET value = $2;",
        )
        .bind("best_block")
        .bind((block_height, block_id).encode())
        .execute(&mut *self.conn)
        .await
        .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        Ok(())
    }

    pub async fn create_tables(&mut self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut <D as Database>::Connection: Executor<'e>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
    {
        sqlx::query(
            "CREATE TABLE ml_misc_data (
                name TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );",
        )
        .execute(&mut *self.conn)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE ml_main_chain_blocks (
                block_height bigint PRIMARY KEY,
                block_id BLOB NOT NULL
            );",
        )
        .execute(&mut *self.conn)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE ml_blocks (
                block_id BLOB PRIMARY KEY,
                block_data BLOB NOT NULL
            );",
        )
        .execute(&mut *self.conn)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE ml_transactions (
                transaction_id BLOB PRIMARY KEY,
                owning_block_id BLOB,
                transaction_data BLOB NOT NULL
            );", // block_id can be null if the transaction is not in the main chain
        )
        .execute(&mut *self.conn)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        sqlx::query(
            "CREATE TABLE ml_block_aux_data (
                block_id BLOB PRIMARY KEY,
                aux_data BLOB NOT NULL
            );",
        )
        .execute(&mut *self.conn)
        .await
        .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn initialize_database(&mut self) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> &'e str: sqlx::Encode<'e, D>,
        for<'e> &'e str: sqlx::Type<D>,
    {
        self.create_tables().await?;

        // Insert row to the table
        sqlx::query("INSERT INTO ml_misc_data (name, value) VALUES (?, ?)")
            .bind("version")
            .bind(CURRENT_STORAGE_VERSION.encode())
            .execute(&mut *self.conn)
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let height = Self::block_height_to_sqlx_friendly(block_height);

        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT block_id FROM ml_main_chain_blocks WHERE block_height = ?;")
                .bind(height)
                .fetch_optional(&mut *self.conn)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let data = match row {
            Some(d) => d.0,
            None => return Ok(None),
        };

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
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let height = Self::block_height_to_sqlx_friendly(block_height);

        logging::log::debug!("Inserting block id: {:?} for height: {}", block_id, height);

        sqlx::query(
            "INSERT INTO ml_main_chain_blocks (block_height, block_id) VALUES ($1, $2)
                ON CONFLICT (block_height) DO UPDATE
                SET block_id = $2;",
        )
        .bind(height)
        .bind(block_id.encode())
        .execute(&mut *self.conn)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> i64: sqlx::Encode<'e, D>,
        i64: sqlx::Type<D>,
    {
        let height = Self::block_height_to_sqlx_friendly(block_height);

        sqlx::query(
            "DELETE FROM ml_main_chain_blocks
            WHERE block_height = $1;",
        )
        .bind(height)
        .execute(&mut *self.conn)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<Block>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
    {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT block_data FROM ml_blocks WHERE block_id = ?;")
                .bind(block_id.encode())
                .fetch_optional(&mut *self.conn)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let data = match row {
            Some(d) => d.0,
            None => return Ok(None),
        };

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
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting block with id: {:?}", block_id);

        sqlx::query(
            "INSERT INTO ml_blocks (block_id, block_data) VALUES ($1, $2)
                ON CONFLICT (block_id) DO UPDATE
                SET block_data = $2;",
        )
        .bind(block_id.encode())
        .bind(block.encode())
        .execute(&mut *self.conn)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
    {
        let row: Option<(Option<Vec<u8>>, Vec<u8>)> = sqlx::query_as(
            "SELECT owning_block_id, transaction_data FROM ml_transactions WHERE transaction_id = ?;",
        )
        .bind(transaction_id.encode())
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let (block_id_data, transaction_data) = match row {
            Some(d) => d,
            None => return Ok(None),
        };

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
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Option<Vec<u8>>: sqlx::Encode<'e, D>,
    {
        logging::log::debug!(
            "Inserting transaction with id {}, owned by block {:?}",
            transaction_id,
            owning_block
        );

        sqlx::query(
            "INSERT INTO ml_transactions (transaction_id, owning_block_id, transaction_data) VALUES ($1, $2, $3)
                ON CONFLICT (transaction_id) DO UPDATE
                SET owning_block_id = $2, transaction_data = $3;",
        )
        .bind(transaction_id.encode())
        .bind(owning_block.map(|v|v.encode()))
        .bind(transaction.encode())
        .execute(&mut *self.conn)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_block_aux_data(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
        for<'e> Vec<u8>: sqlx::Decode<'e, D>,
    {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT aux_data FROM ml_block_aux_data WHERE block_id = ?;")
                .bind(block_id.encode())
                .fetch_optional(&mut *self.conn)
                .await
                .map_err(|e: sqlx::Error| {
                    ApiServerStorageError::LowLevelStorageError(e.to_string())
                })?;

        let serialized_data = match row {
            Some(d) => d.0,
            None => return Ok(None),
        };

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
    ) -> Result<(), ApiServerStorageError>
    where
        for<'e> <D as HasArguments<'e>>::Arguments: IntoArguments<'e, D>,
        for<'e> &'e mut D::Connection: Executor<'e, Database = D>,
        usize: ColumnIndex<<D as sqlx::Database>::Row>,
        for<'e> Vec<u8>: sqlx::Encode<'e, D>,
        Vec<u8>: sqlx::Type<D>,
    {
        logging::log::debug!("Inserting block aux data with block_id {}", block_id);

        sqlx::query(
            "INSERT INTO ml_block_aux_data (block_id, aux_data) VALUES ($1, $2)
                ON CONFLICT (block_id) DO UPDATE
                SET aux_data = $2;",
        )
        .bind(block_id.encode())
        .bind(block_aux_data.encode())
        .execute(&mut *self.conn)
        .await
        .map_err(|e: sqlx::Error| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }
}
