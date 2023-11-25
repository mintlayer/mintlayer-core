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
    chain::{
        Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId, SignedTransaction,
        Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use tokio_postgres::NoTls;

use crate::storage::{
    impls::CURRENT_STORAGE_VERSION,
    storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError, Delegation, Utxo},
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
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.tx
            .query_opt(
                r#"
                    SELECT amount
                    FROM ml_address_balance
                    WHERE address = $1
                    ORDER BY block_height DESC
                    LIMIT 1;
                "#,
                &[&address],
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

    pub async fn set_address_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_address_balance (address, block_height, amount)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (address, block_height)
                    DO UPDATE SET amount = $3;
                "#,
                &[&address.to_string(), &height, &amount.encode()],
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

    pub async fn get_best_block(
        &mut self,
    ) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        let row = self
            .tx
            .query_one(
                r#"
                (
                    SELECT block_height, block_id
                    FROM ml_blocks
                    WHERE block_height IS NOT NULL
                    ORDER BY block_height DESC
                    LIMIT 1
                )
                UNION ALL
                (
                    SELECT block_height, block_id
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

        let block_height = BlockHeight::new(block_height as u64);
        let block_id = Id::<GenBlock>::decode_all(&mut block_id.as_slice()).map_err(|e| {
            ApiServerStorageError::InvalidInitializedState(format!(
                "BlockId deserialization failed: {}",
                e
            ))
        })?;

        Ok((block_height, block_id))
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
            value bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_genesis (
            block_height bigint PRIMARY KEY,
            block_id bytea NOT NULL,
            block_data bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_main_chain_blocks (
            block_height bigint PRIMARY KEY,
            block_id bytea NOT NULL
        );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_blocks (
                block_id bytea PRIMARY KEY,
                block_height bigint,
                block_data bytea NOT NULL
            );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_transactions (
                    transaction_id bytea PRIMARY KEY,
                    owning_block_id bytea,
                    transaction_data bytea NOT NULL
                );", // block_id can be null if the transaction is not in the main chain
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_address_balance (
                    address TEXT NOT NULL,
                    block_height bigint NOT NULL,
                    amount bytea NOT NULL,
                    PRIMARY KEY (address, block_height)
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
            "CREATE TABLE ml_block_aux_data (
                    block_id bytea PRIMARY KEY,
                    aux_data bytea NOT NULL
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_pool_data (
                    pool_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    data bytea NOT NULL,
                    PRIMARY KEY (pool_id, block_height)
                );",
        )
        .await?;

        self.just_execute(
            "CREATE TABLE ml_delegations (
                    delegation_id bytea NOT NULL,
                    block_height bigint NOT NULL,
                    pool_id bytea NOT NULL,
                    balance bytea NOT NULL,
                    spend_destination bytea NOT NULL,
                    PRIMARY KEY (delegation_id, block_height)
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
                "INSERT INTO ml_misc_data (name, value) VALUES ($1, $2)",
                &[&VERSION_STR, &CURRENT_STORAGE_VERSION.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

        self.tx
            .execute(
                "INSERT INTO ml_genesis (block_height, block_id, block_data) VALUES ($1, $2, $3)",
                &[
                    &(0i64),
                    &chain_config.genesis_block_id().encode(),
                    &chain_config.genesis_block().encode(),
                ],
            )
            .await
            .map_err(|e| ApiServerStorageError::InitializationError(e.to_string()))?;

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
    ) -> Result<Option<Block>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT block_data FROM ml_blocks WHERE block_id = $1;",
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

    pub async fn set_mainchain_block(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
        block: &Block,
    ) -> Result<(), ApiServerStorageError> {
        logging::log::debug!("Inserting block with id: {:?}", block_id);
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                "INSERT INTO ml_blocks (block_id, block_height, block_data) VALUES ($1, $2, $3)
                    ON CONFLICT (block_id) DO UPDATE
                    SET block_data = $3, block_height = $2;",
                &[&block_id.encode(), &height, &block.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_delegation(
        &mut self,
        delegation_id: DelegationId,
    ) -> Result<Option<Delegation>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                r#"SELECT pool_id, balance, spend_destination
                FROM ml_delegations
                WHERE delegation_id = $1
                AND block_height = (SELECT MAX(block_height) FROM ml_delegations WHERE delegation_id = $1);
                "#,
                &[&delegation_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let data = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let pool_id: Vec<u8> = data.get(0);
        let balance: Vec<u8> = data.get(1);
        let spend_destination: Vec<u8> = data.get(2);

        let pool_id = PoolId::decode_all(&mut pool_id.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Delegation {} deserialization failed: {}",
                delegation_id, e
            ))
        })?;

        let balance = Amount::decode_all(&mut balance.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Delegation {} deserialization failed: {}",
                delegation_id, e
            ))
        })?;

        let spend_destination = Destination::decode_all(&mut spend_destination.as_slice())
            .map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Delegation {} deserialization failed: {}",
                    delegation_id, e
                ))
            })?;

        let delegation = Delegation::new(spend_destination, pool_id, balance);
        Ok(Some(delegation))
    }

    pub async fn set_delegation_at_height(
        &mut self,
        delegation_id: DelegationId,
        delegation: &Delegation,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_delegations (delegation_id, block_height, pool_id, balance, spend_destination)
                    VALUES($1, $2, $3, $4, $5)
                "#,
                &[
                    &delegation_id.encode(),
                    &height,
                    &delegation.pool_id().encode(),
                    &delegation.balance().encode(),
                    &delegation.spend_destination().encode(),
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

    pub async fn get_pool_delegation_shares(
        &mut self,
        pool_id: PoolId,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError> {
        self.tx
            .query(
                r#"SELECT delegation_id, balance, spend_destination
                    FROM ml_delegations
                    WHERE pool_id = $1
                    AND (delegation_id, block_height) in (SELECT delegation_id, MAX(block_height)
                                                            FROM ml_delegations
                                                            WHERE pool_id = $1
                                                            GROUP BY delegation_id)
                "#,
                &[&pool_id.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?
            .into_iter()
            .map(|row| {
                let delegation_id: Vec<u8> = row.get(0);
                let balance: Vec<u8> = row.get(1);
                let spend_destination: Vec<u8> = row.get(2);

                let delegation_id = DelegationId::decode_all(&mut delegation_id.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "DelegationId for PoolId {} deserialization failed: {}",
                            pool_id, e
                        ))
                    })?;
                let balance = Amount::decode_all(&mut balance.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Amount for PoolId {} deserialization failed: {}",
                        pool_id, e
                    ))
                })?;
                let spend_destination = Destination::decode_all(&mut spend_destination.as_slice())
                    .map_err(|e| {
                        ApiServerStorageError::DeserializationError(format!(
                            "Amount for PoolId {} deserialization failed: {}",
                            pool_id, e
                        ))
                    })?;

                Ok((
                    delegation_id,
                    Delegation::new(spend_destination, pool_id, balance),
                ))
            })
            .collect()
    }

    pub async fn get_pool_data(
        &mut self,
        pool_id: PoolId,
    ) -> Result<Option<PoolData>, ApiServerStorageError> {
        self.tx
            .query_opt(
                r#"
                SELECT data
                FROM ml_pool_data
                WHERE pool_id = $1
                ORDER BY block_height DESC
                LIMIT 1;
            "#,
                &[&pool_id.encode()],
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

    pub async fn set_pool_data_at_height(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolData,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let height = Self::block_height_to_postgres_friendly(block_height);

        self.tx
            .execute(
                r#"
                    INSERT INTO ml_pool_data (pool_id, block_height, data)
                    VALUES ($1, $2, $3)
                "#,
                &[&pool_id.encode(), &height, &pool_data.encode()],
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
            SignedTransaction::decode_all(&mut transaction_data.as_slice()).map_err(|e| {
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
    ) -> Result<Option<(Option<BlockAuxData>, SignedTransaction)>, ApiServerStorageError> {
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
            SignedTransaction::decode_all(&mut transaction_data.as_slice()).map_err(|e| {
                ApiServerStorageError::DeserializationError(format!(
                    "Transaction {} deserialization failed: {}",
                    transaction_id, e
                ))
            })?;

        Ok(Some((block_data, transaction)))
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

    pub async fn get_utxo(
        &mut self,
        outpoint: UtxoOutPoint,
    ) -> Result<Option<Utxo>, ApiServerStorageError> {
        let row = self
            .tx
            .query_opt(
                "SELECT utxo FROM ml_utxo WHERE outpoint = $1;",
                &[&outpoint.encode()],
            )
            .await
            .map_err(|e| ApiServerStorageError::LowLevelStorageError(e.to_string()))?;

        let row = match row {
            Some(d) => d,
            None => return Ok(None),
        };

        let serialized_data: Vec<u8> = row.get(0);

        let utxo = Utxo::decode_all(&mut serialized_data.as_slice()).map_err(|e| {
            ApiServerStorageError::DeserializationError(format!(
                "Utxo for outpoint {:?} deserialization failed: {}",
                outpoint, e
            ))
        })?;

        Ok(Some(utxo))
    }

    pub async fn get_address_available_utxos(
        &mut self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError> {
        let rows = self
            .tx
            .query(
                r#"SELECT outpoint, utxo
                FROM (
                    SELECT outpoint, utxo, spent, ROW_NUMBER() OVER(PARTITION BY outpoint ORDER BY block_height DESC) as newest
                    FROM ml_utxo
                    WHERE address = $1 
                )
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

                let utxo = Utxo::decode_all(&mut utxo.as_slice()).map_err(|e| {
                    ApiServerStorageError::DeserializationError(format!(
                        "Utxo for address {:?} deserialization failed: {}",
                        address, e
                    ))
                })?;
                Ok((outpoint, utxo.into_output()))
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
                    SET utxo = $2;",
                &[&outpoint.encode(), &utxo.encode(), &spent, &address, &height],
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
