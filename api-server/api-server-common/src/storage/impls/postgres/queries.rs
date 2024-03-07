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

use std::collections::{BTreeMap, BTreeSet};

use bb8_postgres::{bb8::PooledConnection, PostgresConnectionManager};
use pos_accounting::PoolData;
use serialization::{DecodeAll, Encode};

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        tokens::{NftIssuance, TokenId},
        AccountNonce, Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};
use tokio_postgres::NoTls;

use crate::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{
        block_aux_data::{BlockAuxData, BlockWithExtraData},
        ApiServerStorageError, BlockInfo, Delegation, FungibleTokenData, LockedUtxo,
        PoolBlockStats, TransactionInfo, Utxo, UtxoWithExtraInfo,
    },
};

const VERSION_STR: &str = "version";

pub struct QueryFromConnection<'a, 'b> {
    tx: &'a PooledConnection<'b, PostgresConnectionManager<NoTls>>,
}

impl<'a, 'b> QueryFromConnection<'a, 'b> {
    fn get_table_exists_query(table_name: &str) -> String {
        format!(
            "SELECT COALESCE( (
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = '{}'
        ), 0) AS count;",
            table_name
        )
    }

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

    fn block_time_to_postgres_friendly(
        block_timestamp: BlockTimestamp,
    ) -> Result<i64, ApiServerStorageError> {
        // Postgres doesn't like u64, so we have to convert it to i64, and given BlockDistance limitations, it's OK.
        block_timestamp
            .as_int_seconds()
            .try_into()
            .map_err(|_| ApiServerStorageError::TimestampToHigh(block_timestamp))
    }

    pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let query_str = Self::get_table_exists_query("ml_misc_data");
        let row_count = self
            .tx
            .query_one(&query_str, &[])
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row_count: i32 = row_count.get(0);

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

    pub async fn get_address_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.tx
            .query_opt(
                r#"
                    SELECT amount
                    FROM ml_address_balance
                    WHERE address = $1 AND coin_or_token_id = $2
                    ORDER BY block_height DESC
                    LIMIT 1;
                "#,
                &[&address, &coin_or_token_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .map_or_else(
                || Ok(None),
                |row| {
                    let amount: Vec<u8> = row.get(0);
                    let amount = Amount::decode_all(&mut amount.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Amount deserialization failed: {}",
                            e
                        ))
                    })?;

                    Ok(Some(amount))
                },
            )
    }

    pub async fn get_address_locked_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.tx
            .query_opt(
                r#"
                    SELECT amount
                    FROM ml_address_locked_balance
                    WHERE address = $1 AND coin_or_token_id = $2
                    ORDER BY block_height DESC
                    LIMIT 1;
                "#,
                &[&address, &coin_or_token_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .map_or_else(
                || Ok(None),
                |row| {
                    let amount: Vec<u8> = row.get(0);
                    let amount = Amount::decode_all(&mut amount.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Amount deserialization failed: {}",
                            e
                        ))
                    })?;

                    Ok(Some(amount))
                },
            )
    }

    pub async fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_address_balance WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_address_locked_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_address_locked_balance WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_address_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_address_balance (address, block_height, coin_or_token_id, amount)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (address, block_height, coin_or_token_id)
                    DO UPDATE SET amount = $4;
                "#,
                &[&address.to_string(), &height, &coin_or_token_id.encode(), &amount.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_address_locked_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_address_locked_balance (address, block_height, coin_or_token_id, amount)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (address, block_height, coin_or_token_id)
                    DO UPDATE SET amount = $4;
                "#,
                &[&address.to_string(), &height, &coin_or_token_id.encode(), &amount.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<Id<Transaction>>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"
                    SELECT transaction_id
                    FROM ml_address_transactions
                    WHERE address = $1
                    ORDER BY block_height DESC;
                "#,
                &[&address],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let mut transaction_ids = vec![];

        for row in &rows {
            let transaction_id: Vec<u8> = row.get(0);
            let transaction_id = Id::<Transaction>::decode_all(&mut transaction_id.as_slice())
                .map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Transaction id deserialization failed: {}",
                        e
                    ))
                })?;

            transaction_ids.push(transaction_id);
        }

        Ok(transaction_ids)
    }

    pub async fn del_address_transactions_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_address_transactions WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_address_transactions_at_height(
        &mut self,
        address: &str,
        transaction_ids: BTreeSet<Id<Transaction>>,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        for transaction_id in transaction_ids {
            self.tx
                .execute(
                    r#"
                        INSERT INTO ml_address_transactions (address, block_height, transaction_id)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (address, block_height, transaction_id)
                        DO NOTHING;
                    "#,
                    &[&address.to_string(), &height, &transaction_id.encode()],
                )
                .await
                .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn get_latest_blocktimestamps(
        &self,
    ) -> Result<Vec<BlockTimestamp>, ApiServerStorageError> {
        const MEDIAN_TIME_SPAN: i64 = chainstate::MEDIAN_TIME_SPAN as i64;
        let rows = self
            .tx
            .query(
                r#"
                SELECT block_timestamp
                FROM
                (
                (
                    SELECT block_height, block_timestamp
                    FROM ml_blocks
                    WHERE block_height IS NOT NULL
                    ORDER BY block_height DESC
                    LIMIT $1
                )
                UNION ALL
                (
                    SELECT block_height, block_timestamp
                    FROM ml_genesis
                    LIMIT 1
                )
                ORDER BY block_height DESC
                LIMIT $1
                ) as blocks
                "#,
                &[&MEDIAN_TIME_SPAN],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let timestamps = rows
            .into_iter()
            .map(|row| {
                let block_timestamp: i64 = row.get(0);
                BlockTimestamp::from_int_seconds(block_timestamp as u64)
            })
            .collect();

        Ok(timestamps)
    }

    pub async fn get_best_block(&mut self) -> Result<BlockAuxData, ApiServerStorageError> {
        let row = self
            .tx
            .query_one(
                r#"
                (
                    SELECT block_height, block_id, block_timestamp
                    FROM ml_blocks
                    WHERE block_height IS NOT NULL
                    ORDER BY block_height DESC
                    LIMIT 1
                )
                UNION ALL
                (
                    SELECT block_height, block_id, block_timestamp
                    FROM ml_genesis
                    LIMIT 1
                )
                ORDER BY block_height DESC
                LIMIT 1
                "#,
                &[],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let block_height: i64 = row.get(0);
        let block_id: Vec<u8> = row.get(1);
        let block_timestamp: i64 = row.get(2);

        let block_height = BlockHeight::new(block_height as u64);
        let block_timestamp = BlockTimestamp::from_int_seconds(block_timestamp as u64);
        let block_id = Id::<GenBlock>::decode_all(&mut block_id.as_slice()).map_err(|e| {
            ApiServerStorageError::InvalidInitializedState(format!(
                "BlockId deserialization failed: {}",
                e
            ))
        })?;

        Ok(BlockAuxData::new(block_id, block_height, block_timestamp))
    }

    async fn just_execute(&mut self, query: &str) -> Result<(), ApiServerStorageError> {
        self.tx
            .execute(query, &[])
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    async fn create_tables(&mut self) -> Result<(), ApiServerStorageError> {
        logging::log::info!("Creating database tables");

        self.just_execute(
            "CREATE TABLE ml_misc_data (
            name TEXT PRIMARY KEY,
            value bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_genesis (
            block_height bigint PRIMARY KEY,
            block_id bytea NOT NULL,
            block_timestamp bigint NOT NULL,
            block_data bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_blocks (
                block_id bytea PRIMARY KEY,
                block_height bigint,
                block_timestamp bigint NOT NULL,
                block_data bytea NOT NULL
            );",
        )
        .await?;

        // Add ml_blocks indexes on height and timestamp
        self.just_execute("CREATE INDEX ml_blocks_block_height_index ON ml_blocks (block_height);")
            .await?;
        self.just_execute(
            "CREATE INDEX ml_blocks_block_timestamp_index ON ml_blocks (block_timestamp);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_transactions (
                    transaction_id bytea PRIMARY KEY,
                    owning_block_id bytea REFERENCES ml_blocks(block_id),
                    transaction_data bytea NOT NULL
                );", // block_id can be null if the transaction is not in the main chain
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_address_balance (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    coin_or_token_id bytea NOT NULL,
                    amount bytea NOT NULL,
                    PRIMARY KEY (address, block_height, coin_or_token_id)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_address_locked_balance (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    coin_or_token_id bytea NOT NULL,
                    amount bytea NOT NULL,
                    PRIMARY KEY (address, block_height, coin_or_token_id)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_address_transactions (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    transaction_id bytea NOT NULL,
                    PRIMARY KEY (address, block_height, transaction_id)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_utxo (
                    outpoint bytea NOT NULL,
                    block_height bigint,
                    spent BOOLEAN NOT NULL,
                    address TEXT NOT NULL,
                    utxo bytea NOT NULL,
                    PRIMARY KEY (outpoint, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_locked_utxo (
                    outpoint bytea NOT NULL,
                    block_height bigint,
                    address TEXT NOT NULL,
                    utxo bytea NOT NULL,
                    lock_until_block bigint,
                    lock_until_timestamp bigint,
                    PRIMARY KEY (outpoint)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_block_aux_data (
                    block_id bytea PRIMARY KEY REFERENCES ml_blocks(block_id),
                    aux_data bytea NOT NULL
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_pool_data (
                    pool_id TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    staker_balance TEXT NOT NULL,
                    data bytea NOT NULL,
                    PRIMARY KEY (pool_id, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_delegations (
                    delegation_id TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    pool_id TEXT NOT NULL,
                    balance TEXT NOT NULL,
                    next_nonce bytea NOT NULL,
                    spend_destination bytea NOT NULL,
                    PRIMARY KEY (delegation_id, block_height)
                );",
        )
        .await?;

        // index when searching for delegations by address
        self.just_execute(
            "CREATE INDEX ml_delegations_spend_destination_index ON ml_delegations (spend_destination);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_fungible_token (
                    token_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    issuance bytea NOT NULL,
                    PRIMARY KEY (token_id, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_nft_issuance (
                    nft_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    issuance bytea NOT NULL,
                    PRIMARY KEY (nft_id)
                );",
        )
        .await?;

        logging::log::info!("Done creating database tables");

        Ok(())
    }

    async fn drop_tables(&mut self) -> Result<(), ApiServerStorageError> {
        logging::log::info!("Dropping database tables");

        self.just_execute("DROP TABLE ml_misc_data;").await?;
        self.just_execute("DROP TABLE ml_genesis;").await?;
        self.just_execute("DROP TABLE ml_blocks;").await?;
        self.just_execute("DROP TABLE ml_transactions;").await?;
        self.just_execute("DROP TABLE ml_address_balance;").await?;
        self.just_execute("DROP TABLE ml_address_transactions;").await?;
        self.just_execute("DROP TABLE ml_utxo;").await?;
        self.just_execute("DROP TABLE ml_block_aux_data;").await?;
        self.just_execute("DROP TABLE ml_pool_data;").await?;
        self.just_execute("DROP TABLE ml_delegations;").await?;
        self.just_execute("DROP TABLE ml_fungible_token;").await?;
        self.just_execute("DROP TABLE ml_nft_issuance;").await?;

        logging::log::info!("Done dropping database tables");

        Ok(())
    }

    pub async fn initialize_database(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.create_tables().await?;

        let timestamp =
            Self::block_time_to_postgres_friendly(chain_config.genesis_block().timestamp())?;
        // Insert row to the table
        self.tx
            .execute(
                "INSERT INTO ml_misc_data (name, value) VALUES ($1, $2)",
                &[&VERSION_STR, &CURRENT_STORAGE_VERSION.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        self.tx
            .execute(
                "INSERT INTO ml_genesis (block_height, block_id, block_timestamp, block_data) VALUES ($1, $2, $3, $4)",
                &[
                    &(0i64),
                    &chain_config.genesis_block_id().encode(),
                    &timestamp,
                    &chain_config.genesis_block().encode(),
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        Ok(())
    }

    pub async fn reinitialize_database(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.drop_tables().await?;

        self.initialize_database(chain_config).await?;

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
                "SELECT block_id FROM ml_blocks WHERE block_height = $1;",
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

    pub async fn del_main_chain_blocks_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "UPDATE ml_blocks
                SET block_height = NULL
                WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_block(
        &mut self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockInfo>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT block_data, block_height FROM ml_blocks WHERE block_id = $1;",
                &[&block_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let data: Vec<u8> = row.get(0);
        let height: Option<i64> = row.get(1);
        let height = height.map(|h| BlockHeight::new(h as u64));

        let block = BlockWithExtraData::decode_all(&mut data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Block {} deserialization failed: {}",
                block_id, e
            ))
        })?;

        Ok(Some(BlockInfo { block, height }))
    }

    pub async fn get_block_range_from_time_range(
        &mut self,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<(BlockHeight, BlockHeight), ApiServerStorageError> {
        let from = Self::block_time_to_postgres_friendly(time_range.0)?;
        let to = Self::block_time_to_postgres_friendly(time_range.1)?;
        let row = self
            .tx
            .query_one(
                r"
                SELECT COALESCE(MIN(block_height), 0), COALESCE(MAX(block_height), 0)
                FROM ml_blocks
                WHERE block_timestamp BETWEEN $1 AND $2 AND block_height IS NOT NULL
                ;",
                &[&from, &to],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let from_height: i64 = row.get(0);
        let to_height: i64 = row.get(1);

        Ok((
            BlockHeight::new(from_height as u64),
            BlockHeight::new(to_height as u64),
        ))
    }

    pub async fn set_mainchain_block(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
        block: &BlockWithExtraData,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting block with id: {:?}", block_id);
        let height = Self::block_height_to_postgres_friendly(block_height);
        let timestamp = Self::block_time_to_postgres_friendly(block.block.timestamp())?;

        self.tx
            .execute(
                "INSERT INTO ml_blocks (block_id, block_height, block_timestamp, block_data) VALUES ($1, $2, $3, $4)
                    ON CONFLICT (block_id) DO UPDATE
                    SET block_data = $4, block_height = $2;",
                &[&block_id.encode(), &height, &timestamp, &block.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_delegation(
        &mut self,
        delegation_id: DelegationId,
        chain_config: &ChainConfig,
    ) -> Result<Option<Delegation>, ApiServerStorageError> {
        let delegation_id = Address::new(chain_config, &delegation_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let row = self
            .tx
            .query_opt(
                r#"SELECT pool_id, balance, spend_destination, next_nonce
                FROM ml_delegations
                WHERE delegation_id = $1
                AND block_height = (SELECT MAX(block_height) FROM ml_delegations WHERE delegation_id = $1);
                "#,
                &[&delegation_id.get()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let pool_id: String = data.get(0);
        let pool_id = Address::<PoolId>::from_str(chain_config, &pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?
            .decode_object(chain_config)
            .expect("already checked");
        let balance: String = data.get(1);
        let spend_destination: Vec<u8> = data.get(2);
        let next_nonce: Vec<u8> = data.get(3);

        let balance = Amount::from_fixedpoint_str(&balance, 0).ok_or_else(|| {
            ApiServerStorageError::DeserializationError(format!(
                "Delegation {delegation_id} Deserialization failed invalid balance {balance}"
            ))
        })?;

        let spend_destination = Destination::decode_all(&mut spend_destination.as_slice())
            .map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Delegation {} deserialization failed: {}",
                    delegation_id, e
                ))
            })?;

        let next_nonce = AccountNonce::decode_all(&mut next_nonce.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Delegation {} deserialization failed: {}",
                delegation_id, e
            ))
        })?;

        let delegation = Delegation::new(spend_destination, pool_id, balance, next_nonce);
        Ok(Some(delegation))
    }

    pub async fn get_delegations_from_address(
        &mut self,
        address: &Destination,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(DelegationId, Delegation)>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"SELECT delegation_id, pool_id, balance, spend_destination, next_nonce
                FROM (
                    SELECT delegation_id, pool_id, balance, spend_destination, next_nonce, ROW_NUMBER() OVER(PARTITION BY delegation_id ORDER BY block_height DESC) as newest
                    FROM ml_delegations
                    WHERE spend_destination = $1
                ) AS sub
                WHERE newest = 1;
                "#,
                &[&address.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let delegation_id: String = row.get(0);
                let delegation_id = Address::<DelegationId>::from_str(chain_config, &delegation_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .decode_object(chain_config)
                    .expect("already checked");
                let pool_id: String = row.get(1);
                let pool_id = Address::<PoolId>::from_str(chain_config, &pool_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .decode_object(chain_config)
                    .expect("already checked");
                let balance: String = row.get(2);
                let spend_destination: Vec<u8> = row.get(3);
                let next_nonce: Vec<u8> = row.get(4);

                let balance = Amount::from_fixedpoint_str(&balance, 0).ok_or_else(|| {
                    ApiServerStorageError::DeserializationError(format!(
                "Delegation {delegation_id} Deserialization failed invalid balance {balance}"
                    ))
                })?;

                let spend_destination = Destination::decode_all(&mut spend_destination.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Delegation deserialization failed: {e}",
                        ))
                    })?;

                let next_nonce =
                    AccountNonce::decode_all(&mut next_nonce.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Delegation deserialization failed: {e}",
                        ))
                    })?;

                let delegation = Delegation::new(spend_destination, pool_id, balance, next_nonce);
                Ok((delegation_id, delegation))
            })
            .collect()
    }

    pub async fn set_delegation_at_height(
        &mut self,
        delegation_id: DelegationId,
        delegation: &Delegation,
        block_height: BlockHeight,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);
        let pool_id = Address::new(chain_config, delegation.pool_id())
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let delegation_id = Address::new(chain_config, &delegation_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_delegations (delegation_id, block_height, pool_id, balance, spend_destination, next_nonce)
                    VALUES($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (delegation_id, block_height) DO UPDATE
                    SET pool_id = $3, balance = $4, spend_destination = $5, next_nonce = $6;
                "#,
                &[
                    &delegation_id.get(),
                    &height,
                    &pool_id.get(),
                    &amount_to_str(*delegation.balance()),
                    &delegation.spend_destination().encode(),
                    &delegation.next_nonce().encode(),
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_delegations_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_delegations WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_pools_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_pool_data WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_pool_block_stats(
        &self,
        pool_id: PoolId,
        block_range: (BlockHeight, BlockHeight),
        chain_config: &ChainConfig,
    ) -> Result<Option<PoolBlockStats>, ApiServerStorageError> {
        let from_height = Self::block_height_to_postgres_friendly(block_range.0);
        let to_height = Self::block_height_to_postgres_friendly(block_range.1);
        let pool_id_str = Address::new(chain_config, &pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let row = self
            .tx
            .query_one(
                r#"SELECT COUNT(*)
                    FROM ml_pool_data
                    WHERE pool_id = $1 AND block_height BETWEEN $2 AND $3
                    AND block_height != (SELECT COALESCE(MIN(block_height), 0) FROM ml_pool_data WHERE pool_id = $1)
                    AND staker_balance::NUMERIC != 0
                "#,
                &[&pool_id_str.get(), &from_height, &to_height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;
        let count: i64 = row.get(0);

        Ok(Some(PoolBlockStats {
            block_count: count as u64,
        }))
    }

    pub async fn get_pool_delegation_shares(
        &mut self,
        pool_id: PoolId,
        chain_config: &ChainConfig,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError> {
        let pool_id_str = Address::new(chain_config, &pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        self.tx
            .query(
                r#"SELECT delegation_id, balance, spend_destination, next_nonce
                    FROM ml_delegations
                    WHERE pool_id = $1
                    AND (delegation_id, block_height) in (SELECT delegation_id, MAX(block_height)
                                                            FROM ml_delegations
                                                            WHERE pool_id = $1
                                                            GROUP BY delegation_id)
                "#,
                &[&pool_id_str.get()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| {
                let delegation_id_str: String = row.get(0);
                let delegation_id =
                    Address::<DelegationId>::from_str(chain_config, &delegation_id_str)
                        .map_err(|_| ApiServerStorageError::AddressableError)?
                        .decode_object(chain_config)
                        .expect("already checked");
                let balance: String = row.get(1);
                let spend_destination: Vec<u8> = row.get(2);
                let next_nonce: Vec<u8> = row.get(3);

                let balance = Amount::from_fixedpoint_str(&balance, 0).ok_or_else(|| {
                    ApiServerStorageError::DeserializationError(format!(
                "Delegation {delegation_id_str} Deserialization failed invalid balance {balance}"
                    ))
                })?;
                let spend_destination = Destination::decode_all(&mut spend_destination.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Amount for PoolId {} deserialization failed: {}",
                            pool_id_str, e
                        ))
                    })?;
                let next_nonce =
                    AccountNonce::decode_all(&mut next_nonce.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Delegation {} deserialization failed: {}",
                            delegation_id_str, e
                        ))
                    })?;

                Ok((
                    delegation_id,
                    Delegation::new(spend_destination, pool_id, balance, next_nonce),
                ))
            })
            .collect()
    }

    pub async fn get_pool_data(
        &mut self,
        pool_id: PoolId,
        chain_config: &ChainConfig,
    ) -> Result<Option<PoolData>, ApiServerStorageError> {
        let pool_id = Address::new(chain_config, &pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        self.tx
            .query_opt(
                r#"
                SELECT data
                FROM ml_pool_data
                WHERE pool_id = $1
                ORDER BY block_height DESC
                LIMIT 1;
            "#,
                &[&pool_id.get()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .map_or_else(
                || Ok(None),
                |row| {
                    let pool_data: Vec<u8> = row.get(0);
                    let pool_data =
                        PoolData::decode_all(&mut pool_data.as_slice()).map_err(|e| {
                            ApiServerStorageError::DeserializationError(format!(
                                "Pool data deserialization failed: {}",
                                e
                            ))
                        })?;

                    Ok(Some(pool_data))
                },
            )
    }

    pub async fn get_latest_pool_data(
        &self,
        len: u32,
        offset: u32,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                SELECT sub.pool_id, data
                FROM (
                    SELECT pool_id, data, staker_balance, block_height, ROW_NUMBER() OVER(PARTITION BY pool_id ORDER BY block_height DESC) as newest
                    FROM ml_pool_data
                ) AS sub INNER JOIN (SELECT pool_id, MIN(block_height) AS created_height FROM ml_pool_data GROUP BY pool_id) as created ON sub.pool_id = created.pool_id
                WHERE newest = 1 AND staker_balance::NUMERIC != 0
                ORDER BY created_height DESC
                OFFSET $1
                LIMIT $2;
            "#,
                &[&offset, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| -> Result<(PoolId, PoolData), ApiServerStorageError> {
                let pool_id: String = row.get(0);
                let pool_id = Address::<PoolId>::from_str(chain_config, &pool_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .decode_object(chain_config)
                    .expect("already checked");
                let pool_data: Vec<u8> = row.get(1);
                let pool_data = PoolData::decode_all(&mut pool_data.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Pool data deserialization failed: {}",
                        e
                    ))
                })?;

                Ok((pool_id, pool_data))
            })
            .collect()
    }

    pub async fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                SELECT pool_id, data
                FROM (
                    SELECT pool_id, data, staker_balance, ROW_NUMBER() OVER(PARTITION BY pool_id ORDER BY block_height DESC) as newest
                    FROM ml_pool_data
                ) AS sub
                WHERE newest = 1 AND staker_balance::NUMERIC != 0
                ORDER BY staker_balance DESC
                OFFSET $1
                LIMIT $2;
            "#,
                &[&offset, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| -> Result<(PoolId, PoolData), ApiServerStorageError> {
                let pool_id: String = row.get(0);
                let pool_id = Address::<PoolId>::from_str(chain_config, &pool_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .decode_object(chain_config)
                    .expect("already checked");
                let pool_data: Vec<u8> = row.get(1);
                let pool_data = PoolData::decode_all(&mut pool_data.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Pool data deserialization failed: {}",
                        e
                    ))
                })?;

                Ok((pool_id, pool_data))
            })
            .collect()
    }

    pub async fn set_pool_data_at_height(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolData,
        block_height: BlockHeight,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);
        let amount_str = amount_to_str(pool_data.staker_balance().expect("no overflow"));
        let pool_id = Address::new(chain_config, &pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_pool_data (pool_id, block_height, staker_balance, data)
                    VALUES ($1, $2, $3, $4)
                "#,
                &[&pool_id.get(), &height, &amount_str, &pool_data.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, TransactionInfo)>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                r#"SELECT owning_block_id, transaction_data
                 FROM ml_transactions
                 WHERE transaction_id = $1;
            "#,
                &[&transaction_id.encode()],
            )
            .await
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
            TransactionInfo::decode_all(&mut transaction_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Transaction {} deserialization failed: {}",
                    transaction_id, e
                ))
            })?;

        Ok(Some((block_id, transaction)))
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction_with_block(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, TransactionInfo)>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                r#"
                SELECT
                    t.transaction_data,
                    b.aux_data
                FROM
                    ml_transactions t
                LEFT JOIN
                    ml_block_aux_data b ON t.owning_block_id = b.block_id
                WHERE
                    t.transaction_id = $1;
                "#,
                &[&transaction_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let transaction_data: Vec<u8> = data.get(0);
        let block_data: Option<Vec<u8>> = data.get(1);

        let block_data = {
            let deserialized_block_id =
                block_data.map(|d| BlockAuxData::decode_all(&mut d.as_slice())).transpose();
            deserialized_block_id.map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Block deserialization failed: {}",
                    e
                ))
            })?
        };

        let transaction =
            TransactionInfo::decode_all(&mut transaction_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Transaction {} deserialization failed: {}",
                    transaction_id, e
                ))
            })?;

        Ok(Some((block_data, transaction)))
    }

    pub async fn get_transactions_with_block(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(BlockAuxData, TransactionInfo)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        let rows = self
            .tx
            .query(
                r#"
                SELECT
                    t.transaction_data,
                    b.aux_data
                FROM
                    ml_blocks mb
                INNER JOIN
                    ml_transactions t ON t.owning_block_id = mb.block_id
                INNER JOIN
                    ml_block_aux_data b ON t.owning_block_id = b.block_id
                WHERE mb.block_height IS NOT NULL
                ORDER BY mb.block_height DESC
                OFFSET $1
                LIMIT $2;
                "#,
                &[&offset, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|data| {
                let transaction_data: Vec<u8> = data.get(0);
                let block_data: Vec<u8> = data.get(1);

                let block_data =
                    BlockAuxData::decode_all(&mut block_data.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Block deserialization failed: {}",
                            e
                        ))
                    })?;

                let transaction = TransactionInfo::decode_all(&mut transaction_data.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Transaction deserialization failed: {e}"
                        ))
                    })?;

                Ok((block_data, transaction))
            })
            .collect()
    }

    pub async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &TransactionInfo,
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

    pub async fn get_utxo(
        &mut self,
        outpoint: UtxoOutPoint,
    ) -> Result<Option<Utxo>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT utxo, spent FROM ml_utxo WHERE outpoint = $1 ORDER BY block_height DESC LIMIT 1;",
                &[&outpoint.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let serialized_data: Vec<u8> = row.get(0);
        let spent: bool = row.get(1);

        let output =
            UtxoWithExtraInfo::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Utxo for outpoint {:?} deserialization failed: {}",
                    outpoint, e
                ))
            })?;

        Ok(Some(Utxo::new_with_info(output, spent)))
    }

    pub async fn get_address_available_utxos(
        &mut self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"SELECT outpoint, utxo
                FROM (
                    SELECT outpoint, utxo, spent, ROW_NUMBER() OVER(PARTITION BY outpoint ORDER BY block_height DESC) as newest
                    FROM ml_utxo
                    WHERE address = $1
                ) AS sub
                WHERE newest = 1 AND spent = false;"#,
                &[&address],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let outpoint: Vec<u8> = row.get(0);
                let utxo: Vec<u8> = row.get(1);

                let outpoint = UtxoOutPoint::decode_all(&mut outpoint.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Outpoint for address {:?} deserialization failed: {}",
                        address, e
                    ))
                })?;

                let output = UtxoWithExtraInfo::decode_all(&mut utxo.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Utxo for address {:?} deserialization failed: {}",
                        address, e
                    ))
                })?;
                Ok((outpoint, output))
            })
            .collect()
    }

    pub async fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"
                SELECT outpoint, utxo
                FROM ml_utxo
                WHERE address = $1
                UNION
                SELECT outpoint, utxo
                FROM ml_locked_utxo
                WHERE address = $1
                ;"#,
                &[&address],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let outpoint: Vec<u8> = row.get(0);
                let utxo: Vec<u8> = row.get(1);

                let outpoint = UtxoOutPoint::decode_all(&mut outpoint.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Outpoint for address {:?} deserialization failed: {}",
                        address, e
                    ))
                })?;

                let output = UtxoWithExtraInfo::decode_all(&mut utxo.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Utxo for address {:?} deserialization failed: {}",
                        address, e
                    ))
                })?;
                Ok((outpoint, output))
            })
            .collect()
    }

    pub async fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let block_height = Self::block_height_to_postgres_friendly(block_height);
        let from_time = Self::block_time_to_postgres_friendly(time_range.0)?;
        let to_time = Self::block_time_to_postgres_friendly(time_range.1)?;

        let rows = self
            .tx
            .query(
                r#"SELECT outpoint, utxo
                FROM ml_locked_utxo
                WHERE lock_until_block = $1 OR lock_until_timestamp BETWEEN $2 AND $3
                ;"#,
                &[&block_height, &from_time, &to_time],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let outpoint: Vec<u8> = row.get(0);
                let utxo: Vec<u8> = row.get(1);

                let outpoint = UtxoOutPoint::decode_all(&mut outpoint.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Outpoint deserialization failed: {e}",
                    ))
                })?;
                let output = UtxoWithExtraInfo::decode_all(&mut utxo.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Utxo deserialization failed: {e}",
                    ))
                })?;
                Ok((outpoint, output))
            })
            .collect()
    }

    pub async fn set_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: Utxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting utxo {:?} for outpoint {:?}", utxo, outpoint);
        let height = Self::block_height_to_postgres_friendly(block_height);
        let spent = utxo.spent();

        self.tx
            .execute(
                "INSERT INTO ml_utxo (outpoint, utxo, spent, address, block_height) VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (outpoint, block_height) DO UPDATE
                    SET utxo = $2, spent = $3;",
                &[&outpoint.encode(), &utxo.utxo_with_extra_info().encode(), &spent, &address, &height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_locked_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: LockedUtxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting utxo {:?} for outpoint {:?}", utxo, outpoint);
        let height = Self::block_height_to_postgres_friendly(block_height);
        let (lock_time, lock_height) = utxo.lock().into_time_and_height();
        let lock_time = lock_time.map(Self::block_time_to_postgres_friendly).transpose()?;
        let lock_height = lock_height.map(Self::block_height_to_postgres_friendly);

        self.tx
            .execute(
                "INSERT INTO ml_locked_utxo (outpoint, utxo, lock_until_timestamp, lock_until_block, address, block_height)
                    VALUES ($1, $2, $3, $4, $5, $6);",
                &[&outpoint.encode(), &utxo.utxo_with_extra_info().encode(), &lock_time, &lock_height, &address, &height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute("DELETE FROM ml_utxo WHERE block_height > $1;", &[&height])
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_locked_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_locked_utxo WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_fungible_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: FungibleTokenData,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "INSERT INTO ml_fungible_token (token_id, block_height, issuance) VALUES ($1, $2, $3)
                    ON CONFLICT (token_id, block_height) DO UPDATE
                    SET issuance = $3;",
                &[&token_id.encode(), &height, &issuance.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT issuance FROM ml_fungible_token WHERE token_id = $1
                    ORDER BY block_height DESC
                    LIMIT 1;",
                &[&token_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let serialized_data: Vec<u8> = row.get(0);

        let issuance =
            FungibleTokenData::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Token data for token id {} deserialization failed: {}",
                    token_id, e
                ))
            })?;

        Ok(Some(issuance))
    }

    pub async fn get_token_num_decimals(
        &self,
        token_id: TokenId,
    ) -> Result<Option<u8>, ApiServerStorageError> {
        if let Some(data) = self.get_fungible_token_issuance(token_id).await? {
            return Ok(Some(data.number_of_decimals));
        }

        Ok(self.get_nft_token_issuance(token_id).await?.map(|_| 0))
    }

    pub async fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftIssuance>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT issuance FROM ml_nft_issuance WHERE nft_id = $1
                    ORDER BY block_height DESC
                    LIMIT 1;",
                &[&token_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let serialized_data: Vec<u8> = row.get(0);

        let issuance = NftIssuance::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Nft issuance data for nft id {} deserialization failed: {}",
                token_id, e
            ))
        })?;

        Ok(Some(issuance))
    }

    pub async fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "INSERT INTO ml_nft_issuance (nft_id, block_height, issuance) VALUES ($1, $2, $3);",
                &[&token_id.encode(), &height, &issuance.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_token_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_fungible_token WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_nft_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml_nft_issuance WHERE block_height > $1;",
                &[&height],
            )
            .await
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
                "SELECT aux_data FROM ml_block_aux_data WHERE block_id = $1;",
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

fn amount_to_str(amount: Amount) -> String {
    let mut amount_str = amount.into_fixedpoint_str(0);
    let max_len = u128::MAX.to_string().len();
    if amount_str.len() < max_len {
        let zeros = "0".repeat(max_len - amount_str.len());
        amount_str = zeros + &amount_str;
    }
    amount_str
}
