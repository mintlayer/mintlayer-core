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

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use bb8_postgres::{bb8::PooledConnection, PostgresConnectionManager};
use serialization::{DecodeAll, Encode};

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        tokens::{NftIssuance, TokenId},
        AccountNonce, Block, ChainConfig, DelegationId, Destination, GenBlock, OrderId, PoolId,
        Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};
use tokio_postgres::NoTls;

use crate::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{
        block_aux_data::{BlockAuxData, BlockWithExtraData},
        AmountWithDecimals, ApiServerStorageError, BlockInfo, CoinOrTokenStatistic, Delegation,
        FungibleTokenData, LockedUtxo, NftWithOwner, Order, PoolBlockStats, PoolDataWithExtraInfo,
        TransactionInfo, TransactionWithBlockInfo, Utxo, UtxoWithExtraInfo,
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
            WHERE table_name = '{}' AND table_schema = 'ml'
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
            .map_err(|_| ApiServerStorageError::TimestampTooHigh(block_timestamp))
    }

    fn tx_global_index_to_postgres_friendly(tx_global_index: u64) -> i64 {
        // Postgres doesn't like u64, so we have to convert it to i64
        tx_global_index
            .try_into()
            .unwrap_or_else(|e| panic!("Invalid tx global index: {e}"))
    }

    pub async fn is_initialized(&mut self) -> Result<bool, ApiServerStorageError> {
        let query_str = Self::get_table_exists_query("misc_data");
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
                "SELECT value FROM ml.misc_data WHERE name = 'version';",
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
                    FROM ml.latest_address_balance_cache
                    WHERE address = $1 AND coin_or_token_id = $2
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

    pub async fn get_address_balances(
        &self,
        address: &str,
    ) -> Result<BTreeMap<CoinOrTokenId, AmountWithDecimals>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"
                    SELECT coin_or_token_id, amount, number_of_decimals
                    FROM ml.latest_address_balance_cache
                    WHERE address = $1;
                "#,
                &[&address],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let coin_or_token_id: Vec<u8> = row.get(0);
                let amount: Vec<u8> = row.get(1);
                let number_of_decimals: i16 = row.get(2);

                let amount = Amount::decode_all(&mut amount.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Amount deserialization failed: {}",
                        e
                    ))
                })?;

                let coin_or_token_id = CoinOrTokenId::decode_all(&mut coin_or_token_id.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "CoinOrTokenId deserialization failed: {}",
                            e
                        ))
                    })?;

                Ok((
                    coin_or_token_id,
                    AmountWithDecimals {
                        amount,
                        decimals: number_of_decimals as u8,
                    },
                ))
            })
            .collect()
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
                    FROM ml.address_locked_balance
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
                "DELETE FROM ml.address_balance WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        // delete and update the address balance from the cache table
        self.tx
            .execute(
                r#"
                WITH deleted_cache_rows AS (
                    DELETE FROM ml.latest_address_balance_cache
                    WHERE block_height > $1
                    RETURNING address, coin_or_token_id
                ),
                latest_address_balances_for_deleted AS (
                    SELECT
                        dcr.address,
                        dcr.coin_or_token_id,
                        ld.block_height,
                        ld.amount,
                        dec.number_of_decimals
                    FROM deleted_cache_rows dcr, ml.coin_or_token_decimals dec
                    CROSS JOIN LATERAL (
                        SELECT block_height, amount, dec.number_of_decimals
                        FROM ml.address_balance d_inner
                        WHERE d_inner.address = dcr.address AND d_inner.coin_or_token_id = dcr.coin_or_token_id AND d_inner.coin_or_token_id = dec.coin_or_token_id
                        ORDER BY block_height DESC
                        LIMIT 1
                    ) AS ld
                )
                INSERT INTO ml.latest_address_balance_cache (address, block_height, coin_or_token_id, amount, number_of_decimals)
                SELECT
                    ld.address,
                    ld.block_height,
                    ld.coin_or_token_id,
                    ld.amount,
                    ld.number_of_decimals
                FROM latest_address_balances_for_deleted ld;
                "#,
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
                "DELETE FROM ml.address_locked_balance WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_address_balance_at_height(
        &mut self,
        address: &Address<Destination>,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.latest_address_balance_cache (address, block_height, coin_or_token_id, amount, number_of_decimals)
                    VALUES($1, $2, $3, $4,
                        (SELECT number_of_decimals
                         FROM ml.coin_or_token_decimals
                         WHERE coin_or_token_id = $3
                         LIMIT 1)
                     )
                    ON CONFLICT (address, coin_or_token_id) DO UPDATE
                    SET block_height = EXCLUDED.block_height, amount = EXCLUDED.amount
                    WHERE ml.latest_address_balance_cache.block_height <= EXCLUDED.block_height;
                "#,
                &[&address.to_string(), &height, &coin_or_token_id.encode(), &amount.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.address_balance (address, block_height, coin_or_token_id, amount)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (address, block_height, coin_or_token_id)
                    DO UPDATE SET amount = EXCLUDED.amount;
                "#,
                &[&address.to_string(), &height, &coin_or_token_id.encode(), &amount.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let CoinOrTokenId::TokenId(token_id) = coin_or_token_id else {
            return Ok(());
        };

        self.update_nft_owner(token_id, height, (amount > Amount::ZERO).then_some(address))
            .await?;

        Ok(())
    }

    async fn update_nft_owner(
        &mut self,
        token_id: TokenId,
        height: i64,
        owner: Option<&Address<Destination>>,
    ) -> Result<(), ApiServerStorageError> {
        self.tx
            .execute(
                r#"
                    WITH LastRow AS (
                        SELECT
                            nft_id,
                            block_height,
                            ticker,
                            issuance
                        FROM
                            ml.nft_issuance
                        WHERE
                            nft_id = $1
                        ORDER BY
                            block_height DESC
                        LIMIT 1
                    )
                    INSERT INTO ml.nft_issuance (nft_id, block_height, ticker, issuance, owner)
                    SELECT
                        lr.nft_id,
                        $2,
                        lr.ticker,
                        lr.issuance,
                        $3
                    FROM
                        LastRow lr
                    ON CONFLICT (nft_id, block_height) DO UPDATE
                    SET
                        ticker = EXCLUDED.ticker,
                        owner = EXCLUDED.owner;
                "#,
                &[&token_id.encode(), &height, &owner.map(|o| o.as_object().encode())],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;
        Ok(())
    }

    pub async fn set_address_locked_balance_at_height(
        &mut self,
        address: &Address<Destination>,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.address_locked_balance (address, block_height, coin_or_token_id, amount)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (address, block_height, coin_or_token_id)
                    DO UPDATE SET amount = $4;
                "#,
                &[&address.to_string(), &height, &coin_or_token_id.encode(), &amount.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let CoinOrTokenId::TokenId(token_id) = coin_or_token_id else {
            return Ok(());
        };

        self.update_nft_owner(token_id, height, (amount > Amount::ZERO).then_some(address))
            .await?;

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
                    FROM ml.address_transactions
                    WHERE address = $1
                    ORDER BY block_height DESC;
                "#,
                &[&address],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let mut transaction_ids = Vec::with_capacity(rows.len());

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
                "DELETE FROM ml.address_transactions WHERE block_height > $1;",
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
                        INSERT INTO ml.address_transactions (address, block_height, transaction_id)
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
                    FROM ml.blocks
                    WHERE block_height IS NOT NULL
                    ORDER BY block_height DESC
                    LIMIT $1
                )
                UNION ALL
                (
                    SELECT block_height, block_timestamp
                    FROM ml.genesis
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
                    FROM ml.blocks
                    WHERE block_height IS NOT NULL
                    ORDER BY block_height DESC
                    LIMIT 1
                )
                UNION ALL
                (
                    SELECT block_height, block_id, block_timestamp
                    FROM ml.genesis
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

        self.just_execute("CREATE SCHEMA ml;").await?;

        self.just_execute(
            "CREATE TABLE ml.misc_data (
            name TEXT PRIMARY KEY,
            value bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.genesis (
            block_height bigint PRIMARY KEY,
            block_id bytea NOT NULL,
            block_timestamp bigint NOT NULL,
            block_data bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.blocks (
                block_id bytea PRIMARY KEY,
                block_height bigint,
                block_timestamp bigint NOT NULL,
                block_data bytea NOT NULL
            );",
        )
        .await?;

        // Add ml.blocks indexes on height and timestamp
        self.just_execute("CREATE INDEX blocks_block_height_index ON ml.blocks (block_height) WHERE block_height IS NOT NULL;")
            .await?;
        self.just_execute(
            "CREATE INDEX blocks_block_timestamp_index ON ml.blocks (block_timestamp) WHERE block_height IS NOT NULL;",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.transactions (
                    transaction_id bytea PRIMARY KEY,
                    global_tx_index bigint NOT NULL,
                    owning_block_id bytea NOT NULL REFERENCES ml.blocks(block_id),
                    transaction_data bytea NOT NULL
                );", // block_id can be null if the transaction is not in the main chain
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.address_balance (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    coin_or_token_id bytea NOT NULL,
                    amount bytea NOT NULL,
                    PRIMARY KEY (address, coin_or_token_id, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.latest_address_balance_cache (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    coin_or_token_id bytea NOT NULL,
                    amount bytea NOT NULL,
                    number_of_decimals smallint NOT NULL,
                    PRIMARY KEY (address, coin_or_token_id)
                );",
        )
        .await?;

        // index for reorgs
        self.just_execute("CREATE INDEX latest_address_balance_cache_block_height ON ml.latest_address_balance_cache (block_height DESC);")
            .await?;

        self.just_execute(
            "CREATE TABLE ml.address_locked_balance (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    coin_or_token_id bytea NOT NULL,
                    amount bytea NOT NULL,
                    PRIMARY KEY (address, coin_or_token_id, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.address_transactions (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    transaction_id bytea NOT NULL,
                    PRIMARY KEY (address, block_height, transaction_id)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.utxo (
                    outpoint bytea NOT NULL,
                    block_height bigint,
                    spent BOOLEAN NOT NULL,
                    address TEXT NOT NULL,
                    utxo bytea NOT NULL,
                    PRIMARY KEY (outpoint, block_height)
                );",
        )
        .await?;

        // index for reorgs
        self.just_execute("CREATE INDEX utxo_block_height ON ml.utxo (block_height DESC);")
            .await?;

        self.just_execute(
            "CREATE TABLE ml.locked_utxo (
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
            "CREATE TABLE ml.block_aux_data (
                    block_id bytea PRIMARY KEY REFERENCES ml.blocks(block_id),
                    aux_data bytea NOT NULL
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.pool_data (
                    pool_id TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    staker_balance TEXT NOT NULL,
                    data bytea NOT NULL,
                    PRIMARY KEY (pool_id, block_height)
                );",
        )
        .await?;

        // index when searching for number of minted blocks
        self.just_execute(
            "CREATE INDEX pool_data_block_height ON ml.pool_data (pool_id, block_height DESC) WHERE (staker_balance::NUMERIC != 0);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.delegations (
                    delegation_id TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    creation_block_height bigint NOT NULL,
                    pool_id TEXT NOT NULL,
                    balance TEXT NOT NULL,
                    next_nonce bytea NOT NULL,
                    spend_destination bytea NOT NULL,
                    PRIMARY KEY (delegation_id, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.latest_delegations_cache (
                    delegation_id TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    creation_block_height bigint NOT NULL,
                    pool_id TEXT NOT NULL,
                    balance TEXT NOT NULL,
                    next_nonce bytea NOT NULL,
                    spend_destination bytea NOT NULL,
                    PRIMARY KEY (pool_id, delegation_id)
                );",
        )
        .await?;

        // index when searching for delegations by address
        self.just_execute(
            "CREATE INDEX latest_delegations_spend_destination_index ON ml.latest_delegations_cache (spend_destination);",
        )
        .await?;

        // index for reorgs for latest_delegations_cache
        self.just_execute(
            "CREATE INDEX latest_delegations_by_block_height_index ON ml.latest_delegations_cache (block_height);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.fungible_token (
                    token_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    ticker bytea NOT NULL,
                    authority TEXT NOT NULL,
                    issuance bytea NOT NULL,
                    PRIMARY KEY (token_id, block_height)
                );",
        )
        .await?;

        // index when searching for token tickers
        self.just_execute(
            "CREATE INDEX fungible_token_ticker_index ON ml.fungible_token USING HASH (ticker);",
        )
        .await?;

        // index for searching token_ids by authority
        self.just_execute(
            "CREATE INDEX fungible_token_authority_index ON ml.fungible_token (authority, token_id, block_height DESC);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.nft_issuance (
                    nft_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    ticker bytea NOT NULL,
                    issuance bytea NOT NULL,
                    owner bytea,
                    PRIMARY KEY (nft_id, block_height)
                );",
        )
        .await?;

        // index when searching for token tickers
        self.just_execute(
            "CREATE INDEX nft_token_ticker_index ON ml.nft_issuance USING HASH (ticker);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.coin_or_token_decimals (
                    coin_or_token_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    number_of_decimals smallint NOT NULL,
                    PRIMARY KEY (coin_or_token_id)
                );",
        )
        .await?;

        // index for reorgs
        self.just_execute(
            "CREATE INDEX coin_or_token_decimals_block_height ON ml.coin_or_token_decimals (block_height DESC);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.statistics (
            statistic TEXT NOT NULL,
            coin_or_token_id bytea NOT NULL,
            block_height bigint NOT NULL,
            amount bytea NOT NULL,
            PRIMARY KEY (statistic, coin_or_token_id, block_height)
        );",
        )
        .await?;

        // index for reorgs
        self.just_execute(
            "CREATE INDEX statistics_block_height ON ml.statistics (block_height DESC);",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml.orders (
                    order_id TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    creation_block_height bigint NOT NULL,
                    initially_asked TEXT NOT NULL,
                    ask_balance TEXT NOT NULL,
                    ask_currency bytea NOT NULL,
                    initially_given TEXT NOT NULL,
                    give_balance TEXT NOT NULL,
                    give_currency bytea NOT NULL,
                    next_nonce bytea NOT NULL,
                    conclude_destination bytea NOT NULL,
                    frozen BOOLEAN NOT NULL,
                    PRIMARY KEY (order_id, block_height)
                );",
        )
        .await?;

        // Index for searching for trading pairs
        self.just_execute(
            "CREATE INDEX orders_currencies_index ON ml.orders (ask_currency, give_currency);",
        )
        .await?;

        logging::log::info!("Done creating database tables");

        Ok(())
    }

    async fn drop_tables(&mut self) -> Result<(), ApiServerStorageError> {
        logging::log::info!("Dropping database tables");

        // drop any legacy tables from before version 8
        self.just_execute("DROP TABLE IF EXISTS ml_misc_data CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_transactions CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_address_balance CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_address_locked_balance CASCADE;")
            .await?;
        self.just_execute("DROP TABLE IF EXISTS ml_address_transactions CASCADE;")
            .await?;
        self.just_execute("DROP TABLE IF EXISTS ml_utxo CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_locked_utxo CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_block_aux_data CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_pool_data CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_delegations CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_fungible_token CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_nft_issuance CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_genesis CASCADE;").await?;
        self.just_execute("DROP TABLE IF EXISTS ml_blocks CASCADE;").await?;

        // drop the new ml schema since version 8
        self.just_execute("DROP SCHEMA IF EXISTS ml CASCADE;").await?;

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
                "INSERT INTO ml.misc_data (name, value) VALUES ($1, $2)",
                &[&VERSION_STR, &CURRENT_STORAGE_VERSION.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        self.tx
            .execute(
                "INSERT INTO ml.genesis (block_height, block_id, block_timestamp, block_data) VALUES ($1, $2, $3, $4)",
                &[
                    &(0i64),
                    &chain_config.genesis_block_id().encode(),
                    &timestamp,
                    &chain_config.genesis_block().encode(),
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        let coin_or_token_id = CoinOrTokenId::Coin;
        self.tx
            .execute(
                "INSERT INTO ml.coin_or_token_decimals (coin_or_token_id, block_height, number_of_decimals) VALUES ($1, $2, $3);",
                &[&coin_or_token_id.encode(), &0_i64, &(chain_config.coin_decimals() as i16)],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

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
                "SELECT block_id FROM ml.blocks WHERE block_height = $1;",
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
                "UPDATE ml.blocks
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
                "SELECT block_data, block_height FROM ml.blocks WHERE block_id = $1;",
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
                FROM ml.blocks
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

        // Note: we need to update the block height on conflict, because the block may have been
        // added as a stale one in the past, in which case its block_height hasn't been set.
        // Regarding the rest of the columns, updating them on conflict makes no sense from the
        // consensus point of view, because the data, if calculated correctly, can never change,
        // provided that the block id stays the same. However, this is a low-level db call,
        // so it'd be better if the caller decides what data can change and what can't.
        // Also, this way it's consistent with the in-memory implementation.
        self.tx
            .execute(
                "INSERT INTO ml.blocks (block_id, block_height, block_timestamp, block_data)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (block_id) DO UPDATE
                    SET block_height = $2, block_timestamp = $3, block_data = $4;",
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
        let delegation_id = Address::new(chain_config, delegation_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let row = self
            .tx
            .query_opt(
                r#"
                SELECT pool_id, balance, spend_destination, next_nonce, creation_block_height
                FROM ml.latest_delegations_cache
                WHERE delegation_id = $1
                LIMIT 1;
                "#,
                &[&delegation_id.as_str()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let pool_id: String = data.get(0);
        let pool_id = Address::<PoolId>::from_string(chain_config, pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?
            .into_object();
        let balance: String = data.get(1);
        let spend_destination: Vec<u8> = data.get(2);
        let next_nonce: Vec<u8> = data.get(3);
        let creation_block_height: i64 = data.get(4);

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

        let delegation = Delegation::new(
            BlockHeight::new(creation_block_height as u64),
            spend_destination,
            pool_id,
            balance,
            next_nonce,
        );
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
                r#"
                SELECT delegation_id, pool_id, balance, spend_destination, next_nonce, creation_block_height
                FROM ml.latest_delegations_cache
                WHERE spend_destination = $1
                "#,
                &[&address.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let delegation_id: String = row.get(0);
                let delegation_id =
                    Address::<DelegationId>::from_string(chain_config, delegation_id)
                        .map_err(|_| ApiServerStorageError::AddressableError)?
                        .into_object();
                let pool_id: String = row.get(1);
                let pool_id = Address::<PoolId>::from_string(chain_config, pool_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .into_object();
                let balance: String = row.get(2);
                let spend_destination: Vec<u8> = row.get(3);
                let next_nonce: Vec<u8> = row.get(4);
                let creation_block_height: i64 = row.get(5);

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

                let delegation = Delegation::new(
                    BlockHeight::new(creation_block_height as u64),
                    spend_destination,
                    pool_id,
                    balance,
                    next_nonce,
                );
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
        let creation_block_height =
            Self::block_height_to_postgres_friendly(delegation.creation_block_height());
        let pool_id = Address::new(chain_config, *delegation.pool_id())
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let delegation_id = Address::new(chain_config, delegation_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.latest_delegations_cache (delegation_id, block_height, pool_id, balance, spend_destination, next_nonce, creation_block_height)
                    VALUES($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (pool_id, delegation_id) DO UPDATE
                    SET block_height = EXCLUDED.block_height,
                    balance = EXCLUDED.balance,
                    spend_destination = EXCLUDED.spend_destination,
                    next_nonce = EXCLUDED.next_nonce,
                    creation_block_height = EXCLUDED.creation_block_height
                    WHERE ml.latest_delegations_cache.block_height <= EXCLUDED.block_height;
                "#,
                &[
                    &delegation_id.as_str(),
                    &height,
                    &pool_id.as_str(),
                    &amount_to_str(*delegation.balance()),
                    &delegation.spend_destination().encode(),
                    &delegation.next_nonce().encode(),
                    &creation_block_height,
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.delegations (delegation_id, block_height, pool_id, balance, spend_destination, next_nonce, creation_block_height)
                    VALUES($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (delegation_id, block_height) DO UPDATE
                    SET pool_id = EXCLUDED.pool_id,
                    balance = EXCLUDED.balance,
                    spend_destination = EXCLUDED.spend_destination,
                    next_nonce = EXCLUDED.next_nonce,
                    creation_block_height = EXCLUDED.creation_block_height;
                "#,
                &[
                    &delegation_id.as_str(),
                    &height,
                    &pool_id.as_str(),
                    &amount_to_str(*delegation.balance()),
                    &delegation.spend_destination().encode(),
                    &delegation.next_nonce().encode(),
                    &creation_block_height,
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

        // delete the delegations from the main table
        self.tx
            .execute(
                "DELETE FROM ml.delegations WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        // delete and update the delegations from the cache table
        self.tx
            .execute(
                r#"
                WITH deleted_cache_rows AS (
                    DELETE FROM ml.latest_delegations_cache
                    WHERE block_height > $1
                    RETURNING delegation_id
                ),
                latest_delegations_for_deleted AS (
                    SELECT
                        dcr.delegation_id,
                        ld.block_height,
                        ld.creation_block_height,
                        ld.pool_id,
                        ld.balance,
                        ld.next_nonce,
                        ld.spend_destination
                    FROM deleted_cache_rows dcr
                    CROSS JOIN LATERAL (
                        SELECT
                            delegation_id,
                            block_height,
                            creation_block_height,
                            pool_id,
                            balance,
                            next_nonce,
                            spend_destination
                        FROM ml.delegations d_inner
                        WHERE d_inner.delegation_id = dcr.delegation_id
                        ORDER BY block_height DESC
                        LIMIT 1
                    ) AS ld
                )
                INSERT INTO ml.latest_delegations_cache (delegation_id, block_height, creation_block_height, pool_id, balance, next_nonce, spend_destination)
                SELECT
                    ld.delegation_id,
                    ld.block_height,
                    ld.creation_block_height,
                    ld.pool_id,
                    ld.balance,
                    ld.next_nonce,
                    ld.spend_destination
                FROM latest_delegations_for_deleted ld;
                "#,
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
                "DELETE FROM ml.pool_data WHERE block_height > $1;",
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
        let pool_id_str = Address::new(chain_config, pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let row = self
            .tx
            .query_one(
                r#"
                SELECT COUNT(*)
                    FROM ml.pool_data
                    WHERE pool_id = $1 AND block_height BETWEEN $2 AND $3
                    AND block_height != (SELECT COALESCE(MIN(block_height), 0) FROM ml.pool_data WHERE pool_id = $1)
                    AND staker_balance::NUMERIC != 0
                "#,
                &[&pool_id_str.as_str(), &from_height, &to_height],
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
        let pool_id_str = Address::new(chain_config, pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        self.tx
            .query(
                r#"
                SELECT delegation_id, balance, spend_destination, next_nonce, creation_block_height
                FROM ml.latest_delegations_cache
                WHERE pool_id = $1;
                "#,
                &[&pool_id_str.as_str()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| {
                let delegation_id_str: String = row.get(0);
                let delegation_id =
                    Address::<DelegationId>::from_string(chain_config, &delegation_id_str)
                        .map_err(|_| ApiServerStorageError::AddressableError)?
                        .into_object();
                let balance: String = row.get(1);
                let spend_destination: Vec<u8> = row.get(2);
                let next_nonce: Vec<u8> = row.get(3);
                let creation_block_height: i64 = row.get(4);

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
                    Delegation::new(
                        BlockHeight::new(creation_block_height as u64),
                        spend_destination,
                        pool_id,
                        balance,
                        next_nonce,
                    ),
                ))
            })
            .collect()
    }

    pub async fn get_pool_data(
        &mut self,
        pool_id: PoolId,
        chain_config: &ChainConfig,
    ) -> Result<Option<PoolDataWithExtraInfo>, ApiServerStorageError> {
        let pool_id = Address::new(chain_config, pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        self.tx
            .query_opt(
                r#"
                SELECT data
                FROM ml.pool_data
                WHERE pool_id = $1
                ORDER BY block_height DESC
                LIMIT 1;
            "#,
                &[&pool_id.as_str()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .map_or_else(
                || Ok(None),
                |row| {
                    let pool_data: Vec<u8> = row.get(0);
                    let pool_data = PoolDataWithExtraInfo::decode_all(&mut pool_data.as_slice())
                        .map_err(|e| {
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
        offset: u64,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                SELECT sub.pool_id, data
                FROM (
                    SELECT pool_id, data, staker_balance, block_height, ROW_NUMBER() OVER(PARTITION BY pool_id ORDER BY block_height DESC) as newest
                    FROM ml.pool_data
                ) AS sub INNER JOIN (SELECT pool_id, MIN(block_height) AS created_height FROM ml.pool_data GROUP BY pool_id) as created ON sub.pool_id = created.pool_id
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
            .map(|row| -> Result<(PoolId, PoolDataWithExtraInfo), ApiServerStorageError> {
                let pool_id: String = row.get(0);
                let pool_id = Address::<PoolId>::from_string(chain_config, pool_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .into_object();
                let pool_data: Vec<u8> = row.get(1);
                let pool_data = PoolDataWithExtraInfo::decode_all(&mut pool_data.as_slice()).map_err(|e| {
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
        offset: u64,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                SELECT pool_id, data
                FROM (
                    SELECT pool_id, data, staker_balance, ROW_NUMBER() OVER(PARTITION BY pool_id ORDER BY block_height DESC) as newest
                    FROM ml.pool_data
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
            .map(|row| -> Result<(PoolId, PoolDataWithExtraInfo), ApiServerStorageError> {
                let pool_id: String = row.get(0);
                let pool_id = Address::<PoolId>::from_string(chain_config, pool_id)
                    .map_err(|_| ApiServerStorageError::AddressableError)?
                    .into_object();
                let pool_data: Vec<u8> = row.get(1);
                let pool_data = PoolDataWithExtraInfo::decode_all(&mut pool_data.as_slice()).map_err(|e| {
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
        pool_data: &PoolDataWithExtraInfo,
        block_height: BlockHeight,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);
        let amount_str = amount_to_str(pool_data.staker_balance().expect("no overflow"));
        let pool_id = Address::new(chain_config, pool_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.pool_data (pool_id, block_height, staker_balance, data)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (pool_id, block_height) DO UPDATE
                    SET staker_balance = $3, data = $4;
                "#,
                &[&pool_id.as_str(), &height, &amount_str, &pool_data.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub async fn get_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, TransactionInfo)>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                r#"SELECT owning_block_id, transaction_data
                 FROM ml.transactions
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

        let block_id_data: Vec<u8> = data.get(0);
        let transaction_data: Vec<u8> = data.get(1);

        let block_id = {
            let deserialized_block_id = Id::<Block>::decode_all(&mut block_id_data.as_slice());
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
                    ml.transactions t
                LEFT JOIN
                    ml.block_aux_data b ON t.owning_block_id = b.block_id
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
        offset: u64,
    ) -> Result<Vec<TransactionWithBlockInfo>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        let rows = self
            .tx
            .query(
                r#"
                SELECT
                    t.transaction_data,
                    b.aux_data,
                    t.global_tx_index
                FROM
                    ml.transactions t
                INNER JOIN
                    ml.block_aux_data b ON t.owning_block_id = b.block_id
                ORDER BY t.global_tx_index DESC
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
                let global_tx_index: i64 = data.get(2);

                let block_aux =
                    BlockAuxData::decode_all(&mut block_data.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Block deserialization failed: {}",
                            e
                        ))
                    })?;

                let tx_info = TransactionInfo::decode_all(&mut transaction_data.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Transaction deserialization failed: {e}"
                        ))
                    })?;

                Ok(TransactionWithBlockInfo {
                    tx_info,
                    block_aux,
                    global_tx_index: global_tx_index as u64,
                })
            })
            .collect()
    }

    pub async fn get_transactions_with_block_before_tx_global_index(
        &self,
        len: u32,
        global_tx_index: u64,
    ) -> Result<Vec<TransactionWithBlockInfo>, ApiServerStorageError> {
        let len = len as i64;
        let tx_global_index = Self::tx_global_index_to_postgres_friendly(global_tx_index);
        let rows = self
            .tx
            .query(
                r#"
                SELECT
                    t.transaction_data,
                    b.aux_data,
                    t.global_tx_index
                FROM
                    ml.transactions t
                INNER JOIN
                    ml.block_aux_data b ON t.owning_block_id = b.block_id
                WHERE t.global_tx_index < $1
                ORDER BY t.global_tx_index DESC
                LIMIT $2;
                "#,
                &[&tx_global_index, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|data| {
                let transaction_data: Vec<u8> = data.get(0);
                let block_data: Vec<u8> = data.get(1);
                let global_tx_index: i64 = data.get(2);

                let block_aux =
                    BlockAuxData::decode_all(&mut block_data.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Block deserialization failed: {}",
                            e
                        ))
                    })?;

                let tx_info = TransactionInfo::decode_all(&mut transaction_data.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Transaction deserialization failed: {e}"
                        ))
                    })?;

                Ok(TransactionWithBlockInfo {
                    tx_info,
                    block_aux,
                    global_tx_index: global_tx_index as u64,
                })
            })
            .collect()
    }

    pub async fn get_last_transaction_global_index(
        &self,
    ) -> Result<Option<u64>, ApiServerStorageError> {
        let row = self
            .tx
            .query_one(
                r#"
                SELECT
                    MAX(t.global_tx_index)
                FROM
                    ml.transactions t;
                "#,
                &[],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let last_tx_global_index: Option<i64> = row.get(0);

        Ok(last_tx_global_index.map(|last_tx_global_index| last_tx_global_index as u64))
    }

    pub async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        global_tx_index: u64,
        owning_block: Id<Block>,
        transaction: &TransactionInfo,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!(
            "Inserting transaction with id {}, owned by block {:?}",
            transaction_id,
            owning_block
        );
        let global_tx_index = Self::tx_global_index_to_postgres_friendly(global_tx_index);

        self.tx.execute(
                "INSERT INTO ml.transactions (transaction_id, owning_block_id, transaction_data, global_tx_index) VALUES ($1, $2, $3, $4)
                    ON CONFLICT (transaction_id) DO UPDATE
                    SET owning_block_id = $2, transaction_data = $3, global_tx_index = $4;",
                &[&transaction_id.encode(), &owning_block.encode(), &transaction.encode(), &global_tx_index]
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
                "SELECT utxo, spent, block_height FROM ml.utxo WHERE outpoint = $1 ORDER BY block_height DESC LIMIT 1;",
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
        let block_height: i64 = row.get(2);
        let spent_at_block_height = spent.then_some(BlockHeight::new(block_height as u64));

        let output =
            UtxoWithExtraInfo::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Utxo for outpoint {:?} deserialization failed: {}",
                    outpoint, e
                ))
            })?;

        Ok(Some(Utxo::new_with_info(output, spent_at_block_height)))
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
                    FROM ml.utxo
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
                r#"SELECT outpoint, utxo
                FROM (
                    SELECT outpoint, utxo, spent, ROW_NUMBER() OVER(PARTITION BY outpoint ORDER BY block_height DESC) as newest
                    FROM ml.utxo
                    WHERE address = $1
                ) AS sub
                WHERE newest = 1 AND spent = false
                UNION ALL
                SELECT outpoint, utxo
                FROM ml.locked_utxo AS locked
                WHERE locked.address = $1 AND NOT EXISTS (SELECT 1 FROM ml.utxo WHERE outpoint = locked.outpoint)
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
                FROM ml.locked_utxo
                WHERE lock_until_block = $1 OR lock_until_timestamp > $2 AND lock_until_timestamp <= $3
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
                "INSERT INTO ml.utxo (outpoint, utxo, spent, address, block_height) VALUES ($1, $2, $3, $4, $5)
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
                "INSERT INTO ml.locked_utxo (outpoint, utxo, lock_until_timestamp, lock_until_block, address, block_height)
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
            .execute("DELETE FROM ml.utxo WHERE block_height > $1;", &[&height])
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
                "DELETE FROM ml.locked_utxo WHERE block_height > $1;",
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
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        let authority = Address::new(chain_config, issuance.authority.clone())
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                "INSERT INTO ml.fungible_token (token_id, block_height, issuance, ticker, authority) VALUES ($1, $2, $3, $4, $5);",
                &[
                    &token_id.encode(),
                    &height,
                    &issuance.encode(),
                    &issuance.token_ticker,
                    &authority.into_string(),
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let coin_or_token_id = CoinOrTokenId::TokenId(token_id);
        self.tx
            .execute(
                "INSERT INTO ml.coin_or_token_decimals (coin_or_token_id, block_height, number_of_decimals) VALUES ($1, $2, $3);",
                &[&coin_or_token_id.encode(), &height, &(issuance.number_of_decimals as i16)],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn set_fungible_token_data(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: FungibleTokenData,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);
        let authority = Address::new(chain_config, issuance.authority.clone())
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                "INSERT INTO ml.fungible_token (token_id, block_height, issuance, ticker, authority) VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (token_id, block_height) DO UPDATE
                    SET issuance = $3, ticker = $4;",
                &[
                    &token_id.encode(),
                    &height,
                    &issuance.encode(),
                    &issuance.token_ticker,
                    &authority.into_string(),
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;
        Ok(())
    }

    pub async fn get_fungible_tokens_by_authority(
        &self,
        authority: Destination,
        chain_config: &ChainConfig,
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        let authority = Address::new(chain_config, authority)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let rows = self
            .tx
            .query(
                r#"WITH candidate AS (
                        SELECT token_id, MAX(block_height) AS block_height
                        FROM ml.fungible_token
                        WHERE authority = $1
                        GROUP BY token_id
                    )
                    SELECT c.token_id
                    FROM candidate c
                    WHERE c.block_height = (
                            SELECT MAX(block_height)
                            FROM ml.fungible_token
                            WHERE token_id = c.token_id);
                "#,
                &[&authority.into_string()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let token_id: Vec<u8> = row.get(0);

                let token_id = TokenId::decode_all(&mut token_id.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "TokenId deserialization failed: {}",
                        e
                    ))
                })?;

                Ok(token_id)
            })
            .collect()
    }

    pub async fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT issuance FROM ml.fungible_token WHERE token_id = $1
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

    pub async fn get_token_ids(
        &self,
        len: u32,
        offset: u64,
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                WITH count_tokens AS (
                    SELECT count(token_id) FROM ml.fungible_token
                )
                (SELECT token_id
                 FROM ml.fungible_token
                 ORDER BY token_id
                 OFFSET $1
                 LIMIT $2)
                UNION ALL
                (SELECT nft_id
                 FROM ml.nft_issuance
                 ORDER BY nft_id
                 OFFSET GREATEST($1 - (SELECT * FROM count_tokens), 0)
                 LIMIT CASE
                       WHEN ($1 - (SELECT * FROM count_tokens) >= -$2)
                           THEN ($2 + $1 - (SELECT * FROM count_tokens))
                       ELSE 0 END);
            "#,
                &[&offset, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| -> Result<TokenId, ApiServerStorageError> {
                let token_id: Vec<u8> = row.get(0);
                let token_id = TokenId::decode_all(&mut token_id.as_slice())
                    .map_err(|_| ApiServerStorageError::AddressableError)?;
                Ok(token_id)
            })
            .collect()
    }

    pub async fn get_token_ids_by_ticker(
        &self,
        len: u32,
        offset: u64,
        ticker: &[u8],
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                WITH count_tokens AS (
                    SELECT count(token_id) FROM ml.fungible_token WHERE ticker = $3
                )
                (SELECT token_id
                 FROM ml.fungible_token
                 WHERE ticker = $3
                 ORDER BY token_id
                 OFFSET $1
                 LIMIT $2)
                UNION ALL
                (SELECT nft_id
                 FROM ml.nft_issuance
                 WHERE ticker = $3
                 ORDER BY nft_id
                 OFFSET GREATEST($1 - (SELECT * FROM count_tokens), 0)
                 LIMIT CASE
                       WHEN ($1 - (SELECT * FROM count_tokens) >= -$2)
                           THEN ($2 + $1 - (SELECT * FROM count_tokens))
                       ELSE 0 END);
            "#,
                &[&offset, &len, &ticker],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| -> Result<TokenId, ApiServerStorageError> {
                let token_id: Vec<u8> = row.get(0);
                let token_id = TokenId::decode_all(&mut token_id.as_slice())
                    .map_err(|_| ApiServerStorageError::AddressableError)?;
                Ok(token_id)
            })
            .collect()
    }

    pub async fn get_statistic(
        &self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT amount FROM ml.statistics WHERE statistic = $1 AND coin_or_token_id = $2
                    ORDER BY block_height DESC
                    LIMIT 1;",
                &[&statistic.to_string(), &coin_or_token_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let serialized_data: Vec<u8> = row.get(0);

        let amount = Amount::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Amount for statistic {} and coin or token id {:?} deserialization failed: {}",
                statistic, coin_or_token_id, e
            ))
        })?;

        Ok(Some(amount))
    }

    pub async fn get_all_statistic(
        &self,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<BTreeMap<CoinOrTokenStatistic, Amount>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"
                SELECT sub.statistic, sub.amount
                FROM (
                    SELECT statistic, amount, ROW_NUMBER() OVER(PARTITION BY statistic ORDER BY block_height DESC) as newest
                    FROM ml.statistics
                    WHERE coin_or_token_id = $1
                ) AS sub
                WHERE newest = 1;
                "#,
                &[&coin_or_token_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                let statistic: String = row.get(0);
                let serialized_amount: Vec<u8> = row.get(1);

                let amount =
                    Amount::decode_all(&mut serialized_amount.as_slice()).map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Amount for statistic {} and coin or token id {:?} deserialization failed: {}",
                            statistic, coin_or_token_id, e
                        ))
                    })?;

                Ok((CoinOrTokenStatistic::from_str(&statistic)?, amount))
            })
            .collect()
    }

    pub async fn set_statistic(
        &mut self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
        amount: Amount,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "INSERT INTO ml.statistics (statistic, coin_or_token_id, block_height, amount)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (statistic, coin_or_token_id, block_height) DO UPDATE
                    SET amount = $4;",
                &[&statistic.to_string(), &coin_or_token_id.encode(), &height, &amount.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_statistics_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml.statistics WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_coin_or_token_decimals_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "DELETE FROM ml.coin_or_token_decimals WHERE block_height > $1;",
                &[&height],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftWithOwner>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT issuance, owner FROM ml.nft_issuance WHERE nft_id = $1
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
        let owner: Option<Vec<u8>> = row.get(1);

        let nft = NftIssuance::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Nft issuance data for nft id {} deserialization failed: {}",
                token_id, e
            ))
        })?;

        let owner = owner
            .map(|owner| {
                Destination::decode_all(&mut owner.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Deserialization failed for nft owner {token_id}: {e}"
                    ))
                })
            })
            .transpose()?;

        Ok(Some(NftWithOwner { nft, owner }))
    }

    pub async fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
        owner: &Destination,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        let ticker = match &issuance {
            NftIssuance::V0(data) => data.metadata.ticker(),
        };

        self.tx
            .execute(
                "INSERT INTO ml.nft_issuance (nft_id, block_height, issuance, ticker, owner) VALUES ($1, $2, $3, $4, $5);",
                &[&token_id.encode(), &height, &issuance.encode(), ticker, &owner.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let coin_or_token_id = CoinOrTokenId::TokenId(token_id);
        self.tx
            .execute(
                "INSERT INTO ml.coin_or_token_decimals (coin_or_token_id, block_height, number_of_decimals) VALUES ($1, $2, $3);",
                &[&coin_or_token_id.encode(), &height, &0_i16],
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
                "DELETE FROM ml.fungible_token WHERE block_height > $1;",
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
                "DELETE FROM ml.nft_issuance WHERE block_height > $1;",
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
                "SELECT aux_data FROM ml.block_aux_data WHERE block_id = $1;",
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

        // Note: we update the data on block id conflict, the reasons are the same as in set_mainchain_block.
        self.tx
            .execute(
                "INSERT INTO ml.block_aux_data (block_id, aux_data) VALUES ($1, $2)
                    ON CONFLICT (block_id) DO UPDATE
                    SET aux_data = $2;",
                &[&block_id.encode(), &block_aux_data.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_order(
        &self,
        order_id: OrderId,
        chain_config: &ChainConfig,
    ) -> Result<Option<Order>, ApiServerStorageError> {
        let order_id_addr = Address::new(chain_config, order_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;
        let row = self
            .tx
            .query_opt(
                r#"
                SELECT order_id, initially_asked, ask_balance, ask_currency, initially_given, give_balance, give_currency, conclude_destination, next_nonce, creation_block_height, frozen
                FROM ml.orders
                WHERE order_id = $1
                ORDER BY block_height DESC
                LIMIT 1;
                "#,
                &[&order_id_addr.as_str()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let (decoded_order_id, order) = decode_order_from_row(&data, chain_config)?;
        assert_eq!(order_id, decoded_order_id);

        Ok(Some(order))
    }

    pub async fn set_order_at_height(
        &mut self,
        order_id: OrderId,
        order: &Order,
        block_height: BlockHeight,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);
        let creation_block_height =
            Self::block_height_to_postgres_friendly(order.creation_block_height);
        let order_id = Address::new(chain_config, order_id)
            .map_err(|_| ApiServerStorageError::AddressableError)?;

        self.tx
            .execute(
                r#"
                    INSERT INTO ml.orders (order_id, block_height, initially_asked, ask_balance, ask_currency, initially_given, give_balance, give_currency, conclude_destination, next_nonce, creation_block_height, frozen)
                    VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (order_id, block_height) DO UPDATE
                    SET initially_asked = $3, ask_balance = $4, ask_currency = $5, initially_given = $6, give_balance = $7, give_currency = $8, conclude_destination = $9, next_nonce = $10, creation_block_height = $11, frozen = $12;
                "#,
                &[
                    &order_id.as_str(),
                    &height,
                    &amount_to_str(order.initially_asked),
                    &amount_to_str(order.ask_balance),
                    &order.ask_currency.encode(),
                    &amount_to_str(order.initially_given),
                    &amount_to_str(order.give_balance),
                    &order.give_currency.encode(),
                    &order.conclude_destination.encode(),
                    &order.next_nonce.encode(),
                    &creation_block_height,
                    &order.is_frozen
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn del_orders_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute("DELETE FROM ml.orders WHERE block_height > $1;", &[&height])
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_orders_by_height(
        &self,
        len: u32,
        offset: u64,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                SELECT order_id, initially_asked, ask_balance, ask_currency, initially_given, give_balance, give_currency, conclude_destination, next_nonce, creation_block_height, frozen
                FROM (
                    SELECT order_id, initially_asked, ask_balance, ask_currency, initially_given, give_balance, give_currency, conclude_destination, next_nonce, creation_block_height, frozen, block_height, ROW_NUMBER() OVER(PARTITION BY order_id ORDER BY block_height DESC) as newest
                    FROM ml.orders
                ) AS sub
                WHERE newest = 1
                ORDER BY creation_block_height DESC
                OFFSET $1
                LIMIT $2;
            "#,
                &[&offset, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| -> Result<(OrderId, Order), ApiServerStorageError> {
                 decode_order_from_row(&row, chain_config)
            })
            .collect()
    }

    pub async fn get_orders_for_trading_pair(
        &self,
        pair: (CoinOrTokenId, CoinOrTokenId),
        len: u32,
        offset: u64,
        chain_config: &ChainConfig,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError> {
        let len = len as i64;
        let offset = offset as i64;
        self.tx
            .query(
                r#"
                SELECT order_id, initially_asked, ask_balance, ask_currency, initially_given, give_balance, give_currency, conclude_destination, next_nonce, creation_block_height, frozen
                FROM (
                    SELECT order_id, initially_asked, ask_balance, ask_currency, initially_given, give_balance, give_currency, conclude_destination, next_nonce, creation_block_height, frozen, block_height, ROW_NUMBER() OVER(PARTITION BY order_id ORDER BY block_height DESC) as newest
                    FROM ml.orders
                ) AS sub
                WHERE newest = 1 AND ((ask_currency = $1 AND give_currency = $2) OR (ask_currency = $2 AND give_currency = $1))
                ORDER BY creation_block_height DESC
                OFFSET $3
                LIMIT $4;
            "#,
                &[&pair.0.encode(), &pair.1.encode(), &offset, &len],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| -> Result<(OrderId, Order), ApiServerStorageError> {
                 decode_order_from_row(&row, chain_config)
            })
            .collect()
    }
}

fn decode_order_from_row(
    data: &tokio_postgres::Row,
    chain_config: &ChainConfig,
) -> Result<(OrderId, Order), ApiServerStorageError> {
    let order_id: String = data.get("order_id");
    let initially_asked: String = data.get("initially_asked");
    let ask_balance: String = data.get("ask_balance");
    let ask_currency: Vec<u8> = data.get("ask_currency");
    let initially_given: String = data.get("initially_given");
    let give_balance: String = data.get("give_balance");
    let give_currency: Vec<u8> = data.get("give_currency");
    let conclude_destination: Vec<u8> = data.get("conclude_destination");
    let next_nonce: Vec<u8> = data.get("next_nonce");
    let creation_block_height: i64 = data.get("creation_block_height");
    let is_frozen: bool = data.get("frozen");

    let order_id = Address::<OrderId>::from_string(chain_config, order_id)
        .map_err(|_| ApiServerStorageError::AddressableError)?
        .into_object();

    let initially_asked = Amount::from_fixedpoint_str(&initially_asked, 0).ok_or_else(|| {
            ApiServerStorageError::DeserializationError(format!(
                "Deserialization failed for order {order_id}: invalid initial ask balance {initially_asked}"
            ))
        })?;

    let ask_balance = Amount::from_fixedpoint_str(&ask_balance, 0).ok_or_else(|| {
        ApiServerStorageError::DeserializationError(format!(
            "Deserialization failed for order {order_id}: invalid ask balance {ask_balance}"
        ))
    })?;

    let ask_currency = CoinOrTokenId::decode_all(&mut ask_currency.as_slice()).map_err(|e| {
        ApiServerStorageError::DeserializationError(format!(
            "Deserialization failed for order {order_id}: {e}"
        ))
    })?;

    let initially_given = Amount::from_fixedpoint_str(&initially_given, 0).ok_or_else(|| {
            ApiServerStorageError::DeserializationError(format!(
                "Deserialization failed for order {order_id}: invalid initial give balance {initially_given}"
            ))
        })?;

    let give_balance = Amount::from_fixedpoint_str(&give_balance, 0).ok_or_else(|| {
        ApiServerStorageError::DeserializationError(format!(
            "Deserialization failed for order {order_id}: invalid give balance {give_balance}"
        ))
    })?;

    let give_currency = CoinOrTokenId::decode_all(&mut give_currency.as_slice()).map_err(|e| {
        ApiServerStorageError::DeserializationError(format!(
            "Deserialization failed for order {order_id}: {e}"
        ))
    })?;

    let conclude_destination = Destination::decode_all(&mut conclude_destination.as_slice())
        .map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Deserialization failed for order {order_id}: {e}"
            ))
        })?;

    let next_nonce = AccountNonce::decode_all(&mut next_nonce.as_slice()).map_err(|e| {
        ApiServerStorageError::DeserializationError(format!(
            "Deserialization failed for order {order_id}: {e}"
        ))
    })?;

    let order = Order {
        creation_block_height: BlockHeight::new(creation_block_height as u64),
        conclude_destination,
        ask_balance,
        initially_asked,
        ask_currency,
        give_balance,
        give_currency,
        initially_given,
        is_frozen,
        next_nonce,
    };
    Ok((order_id, order))
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
