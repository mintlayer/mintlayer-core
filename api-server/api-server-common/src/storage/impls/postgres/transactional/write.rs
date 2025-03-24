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

use common::{
    address::Address,
    chain::{
        block::timestamp::BlockTimestamp,
        tokens::{NftIssuance, TokenId},
        Block, ChainConfig, DelegationId, Destination, OrderId, PoolId, Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};

use crate::storage::{
    impls::postgres::queries::QueryFromConnection,
    storage_api::{
        block_aux_data::{BlockAuxData, BlockWithExtraData},
        AmountWithDecimals, ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite,
        BlockInfo, CoinOrTokenStatistic, Delegation, FungibleTokenData, LockedUtxo, NftWithOwner,
        Order, PoolBlockStats, PoolDataWithExtraInfo, TransactionInfo, Utxo, UtxoWithExtraInfo,
    },
};

use super::{ApiServerPostgresTransactionalRw, CONN_ERR};

#[async_trait::async_trait]
impl ApiServerStorageWrite for ApiServerPostgresTransactionalRw<'_> {
    async fn reinitialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.reinitialize_database(chain_config).await?;

        Ok(())
    }

    async fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_address_balance_above_height(block_height).await?;

        Ok(())
    }

    async fn del_address_locked_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_address_locked_balance_above_height(block_height).await?;

        Ok(())
    }

    async fn del_address_transactions_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_address_transactions_above_height(block_height).await?;

        Ok(())
    }

    async fn set_address_balance_at_height(
        &mut self,
        address: &Address<Destination>,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_address_balance_at_height(address, amount, coin_or_token_id, block_height)
            .await?;

        Ok(())
    }

    async fn set_address_locked_balance_at_height(
        &mut self,
        address: &Address<Destination>,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_address_locked_balance_at_height(address, amount, coin_or_token_id, block_height)
            .await?;

        Ok(())
    }

    async fn set_address_transactions_at_height(
        &mut self,
        address: &str,
        transaction_ids: BTreeSet<Id<Transaction>>,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_address_transactions_at_height(address, transaction_ids, block_height)
            .await?;

        Ok(())
    }

    async fn set_mainchain_block(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
        block: &BlockWithExtraData,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_mainchain_block(block_id, block_height, block).await?;

        Ok(())
    }

    async fn set_delegation_at_height(
        &mut self,
        delegation_id: DelegationId,
        delegation: &Delegation,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_delegation_at_height(delegation_id, delegation, block_height, &self.chain_config)
            .await?;

        Ok(())
    }

    async fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Id<Block>,
        transaction: &TransactionInfo,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_transaction(transaction_id, owning_block, transaction).await?;

        Ok(())
    }

    async fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_block_aux_data(block_id, block_aux_data).await?;

        Ok(())
    }

    async fn del_main_chain_blocks_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_main_chain_blocks_above_height(block_height).await?;

        Ok(())
    }

    async fn set_pool_data_at_height(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolDataWithExtraInfo,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_pool_data_at_height(pool_id, pool_data, block_height, &self.chain_config)
            .await?;

        Ok(())
    }

    async fn del_delegations_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_delegations_above_height(block_height).await?;

        Ok(())
    }

    async fn del_pools_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_pools_above_height(block_height).await?;

        Ok(())
    }

    async fn set_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: Utxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_utxo_at_height(outpoint, utxo, address, block_height).await?;

        Ok(())
    }

    async fn set_locked_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: LockedUtxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_locked_utxo_at_height(outpoint, utxo, address, block_height).await?;

        Ok(())
    }

    async fn del_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_utxo_above_height(block_height).await?;

        Ok(())
    }

    async fn del_locked_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_locked_utxo_above_height(block_height).await?;

        Ok(())
    }

    async fn set_fungible_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: FungibleTokenData,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_fungible_token_issuance(token_id, block_height, issuance).await?;

        Ok(())
    }

    async fn set_fungible_token_data(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        data: FungibleTokenData,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_fungible_token_data(token_id, block_height, data).await?;

        Ok(())
    }

    async fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
        owner: &Destination,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_nft_token_issuance(token_id, block_height, issuance, owner).await?;

        Ok(())
    }

    async fn del_token_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_token_issuance_above_height(block_height).await?;

        Ok(())
    }

    async fn del_nft_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_nft_issuance_above_height(block_height).await?;

        Ok(())
    }

    async fn del_coin_or_token_decimals_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_coin_or_token_decimals_above_height(block_height).await?;

        Ok(())
    }

    async fn set_statistic(
        &mut self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
        amount: Amount,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_statistic(statistic, coin_or_token_id, block_height, amount).await?;

        Ok(())
    }

    async fn del_statistics_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_statistics_above_height(block_height).await?;

        Ok(())
    }

    async fn set_order_at_height(
        &mut self,
        order_id: OrderId,
        order: &Order,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_order_at_height(order_id, order, block_height, &self.chain_config)
            .await?;

        Ok(())
    }

    async fn del_orders_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.del_orders_above_height(block_height).await?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl ApiServerStorageRead for ApiServerPostgresTransactionalRw<'_> {
    async fn is_initialized(&self) -> Result<bool, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.is_initialized().await?;

        Ok(res)
    }

    async fn get_storage_version(&self) -> Result<Option<u32>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_storage_version().await?;

        Ok(res)
    }

    async fn get_address_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_balance(address, coin_or_token_id).await?;

        Ok(res)
    }

    async fn get_address_balances(
        &self,
        address: &str,
    ) -> Result<BTreeMap<CoinOrTokenId, AmountWithDecimals>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_balances(address).await?;

        Ok(res)
    }

    async fn get_address_locked_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_locked_balance(address, coin_or_token_id).await?;

        Ok(res)
    }

    async fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<Id<Transaction>>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_transactions(address).await?;

        Ok(res)
    }

    async fn get_latest_blocktimestamps(
        &self,
    ) -> Result<Vec<BlockTimestamp>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_latest_blocktimestamps().await?;

        Ok(res)
    }

    async fn get_best_block(&self) -> Result<BlockAuxData, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_best_block().await?;

        Ok(res)
    }

    async fn get_block(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockInfo>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block(block_id).await?;

        Ok(res)
    }

    async fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block_aux_data(block_id).await?;

        Ok(res)
    }

    async fn get_block_range_from_time_range(
        &self,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<(BlockHeight, BlockHeight), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_block_range_from_time_range(time_range).await?;

        Ok(res)
    }

    async fn get_delegation(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Delegation>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_delegation(delegation_id, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_main_chain_block_id(block_height).await?;

        Ok(res)
    }

    async fn get_transaction_with_block(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, TransactionInfo)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_transaction_with_block(transaction_id).await?;

        Ok(res)
    }

    async fn get_transactions_with_block(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(BlockAuxData, TransactionInfo)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_transactions_with_block(len, offset).await?;

        Ok(res)
    }

    async fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<PoolDataWithExtraInfo>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_pool_data(pool_id, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_latest_pool_data(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_latest_pool_data(len, offset, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn
            .get_pool_data_with_largest_staker_balance(len, offset, &self.chain_config)
            .await?;

        Ok(res)
    }

    async fn get_pool_block_stats(
        &self,
        pool_id: PoolId,
        block_range: (BlockHeight, BlockHeight),
    ) -> Result<Option<PoolBlockStats>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_pool_block_stats(pool_id, block_range, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_pool_delegations(
        &self,
        pool_id: PoolId,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_pool_delegation_shares(pool_id, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, TransactionInfo)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_transaction(transaction_id).await?;

        Ok(res)
    }

    async fn get_utxo(
        &self,
        outpoint: UtxoOutPoint,
    ) -> Result<Option<Utxo>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_utxo(outpoint).await?;

        Ok(res)
    }

    async fn get_address_available_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_available_utxos(address).await?;

        Ok(res)
    }

    async fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_all_utxos(address).await?;

        Ok(res)
    }

    async fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_locked_utxos_until_now(block_height, time_range).await?;

        Ok(res)
    }

    async fn get_delegations_from_address(
        &self,
        address: &Destination,
    ) -> Result<Vec<(DelegationId, Delegation)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_delegations_from_address(address, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_fungible_token_issuance(token_id).await?;

        Ok(res)
    }

    async fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftWithOwner>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_nft_token_issuance(token_id).await?;

        Ok(res)
    }

    async fn get_token_num_decimals(
        &self,
        token_id: TokenId,
    ) -> Result<Option<u8>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_token_num_decimals(token_id).await?;

        Ok(res)
    }

    async fn get_token_ids(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_token_ids(len, offset).await?;

        Ok(res)
    }

    async fn get_token_ids_by_ticker(
        &self,
        len: u32,
        offset: u32,
        ticker: &[u8],
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_token_ids_by_ticker(len, offset, ticker).await?;

        Ok(res)
    }

    async fn get_statistic(
        &self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_statistic(statistic, coin_or_token_id).await?;

        Ok(res)
    }

    async fn get_all_statistic(
        &self,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<BTreeMap<CoinOrTokenStatistic, Amount>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_all_statistic(coin_or_token_id).await?;

        Ok(res)
    }

    async fn get_order(&self, order_id: OrderId) -> Result<Option<Order>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_order(order_id, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_all_orders(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_orders_by_height(len, offset, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_orders_for_trading_pair(
        &self,
        pair: (CoinOrTokenId, CoinOrTokenId),
        len: u32,
        offset: u32,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_orders_for_trading_pair(pair, len, offset, &self.chain_config).await?;

        Ok(res)
    }
}
