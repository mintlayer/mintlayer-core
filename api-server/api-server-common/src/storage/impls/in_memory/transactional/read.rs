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

use std::collections::BTreeMap;

use common::{
    chain::{
        block::timestamp::BlockTimestamp, tokens::TokenId, Block, DelegationId, Destination,
        OrderId, PoolId, Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};

use crate::storage::storage_api::{
    block_aux_data::BlockAuxData, AmountWithDecimals, ApiServerStorageError, ApiServerStorageRead,
    BlockInfo, CoinOrTokenStatistic, Delegation, FungibleTokenData, NftWithOwner, Order,
    PoolBlockStats, PoolDataWithExtraInfo, TransactionInfo, Utxo, UtxoWithExtraInfo,
};

use super::ApiServerInMemoryStorageTransactionalRo;

#[async_trait::async_trait]
impl ApiServerStorageRead for ApiServerInMemoryStorageTransactionalRo<'_> {
    async fn is_initialized(&self) -> Result<bool, ApiServerStorageError> {
        self.transaction.is_initialized()
    }

    async fn get_address_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.transaction.get_address_balance(address, coin_or_token_id)
    }

    async fn get_address_balances(
        &self,
        address: &str,
    ) -> Result<BTreeMap<CoinOrTokenId, AmountWithDecimals>, ApiServerStorageError> {
        self.transaction.get_address_balances(address)
    }

    async fn get_address_locked_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.transaction.get_address_locked_balance(address, coin_or_token_id)
    }

    async fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<Id<Transaction>>, ApiServerStorageError> {
        self.transaction.get_address_transactions(address)
    }

    async fn get_block(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockInfo>, ApiServerStorageError> {
        self.transaction.get_block(block_id)
    }

    async fn get_block_range_from_time_range(
        &self,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<(BlockHeight, BlockHeight), ApiServerStorageError> {
        self.transaction.get_block_range_from_time_range(time_range)
    }

    async fn get_transaction_with_block(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, TransactionInfo)>, ApiServerStorageError> {
        self.transaction.get_transaction_with_block(transaction_id)
    }

    async fn get_transactions_with_block(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(BlockAuxData, TransactionInfo)>, ApiServerStorageError> {
        self.transaction.get_transactions_with_block(len, offset)
    }

    async fn get_delegation(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Delegation>, ApiServerStorageError> {
        self.transaction.get_delegation(delegation_id)
    }

    async fn get_pool_block_stats(
        &self,
        pool_id: PoolId,
        block_range: (BlockHeight, BlockHeight),
    ) -> Result<Option<PoolBlockStats>, ApiServerStorageError> {
        self.transaction.get_pool_block_stats(pool_id, block_range)
    }

    async fn get_pool_delegations(
        &self,
        pool_id: PoolId,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError> {
        self.transaction.get_pool_delegations(pool_id)
    }

    async fn get_latest_pool_data(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError> {
        self.transaction.get_latest_pool_ids(len, offset)
    }

    async fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolDataWithExtraInfo)>, ApiServerStorageError> {
        self.transaction.get_pool_data_with_largest_staker_balance(len, offset)
    }

    async fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, TransactionInfo)>, ApiServerStorageError> {
        self.transaction.get_transaction(transaction_id)
    }

    async fn get_storage_version(&self) -> Result<Option<u32>, ApiServerStorageError> {
        Ok(Some(self.transaction.get_storage_version()?))
    }

    async fn get_latest_blocktimestamps(
        &self,
    ) -> Result<Vec<BlockTimestamp>, ApiServerStorageError> {
        self.transaction.get_latest_blocktimestamps()
    }

    async fn get_best_block(&self) -> Result<BlockAuxData, ApiServerStorageError> {
        self.transaction.get_best_block()
    }

    async fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        self.transaction.get_block_aux_data(block_id)
    }

    async fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        self.transaction.get_main_chain_block_id(block_height)
    }

    async fn get_pool_data(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<PoolDataWithExtraInfo>, ApiServerStorageError> {
        self.transaction.get_pool_data(pool_id)
    }

    async fn get_utxo(
        &self,
        outpoint: UtxoOutPoint,
    ) -> Result<Option<Utxo>, ApiServerStorageError> {
        self.transaction.get_utxo(outpoint)
    }

    async fn get_address_available_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        self.transaction.get_address_available_utxos(address)
    }

    async fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        self.transaction.get_address_all_utxos(address)
    }

    async fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        self.transaction.get_locked_utxos_until_now(block_height, time_range)
    }

    async fn get_delegations_from_address(
        &self,
        address: &Destination,
    ) -> Result<Vec<(DelegationId, Delegation)>, ApiServerStorageError> {
        self.transaction.get_delegations_from_address(address)
    }

    async fn get_fungible_tokens_by_authority(
        &self,
        authority: Destination,
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        self.transaction.get_fungible_tokens_by_authority(authority)
    }

    async fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError> {
        self.transaction.get_fungible_token_issuance(token_id)
    }

    async fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftWithOwner>, ApiServerStorageError> {
        self.transaction.get_nft_token_issuance(token_id)
    }

    async fn get_token_num_decimals(
        &self,
        token_id: TokenId,
    ) -> Result<Option<u8>, ApiServerStorageError> {
        self.transaction.get_token_num_decimals(token_id)
    }

    async fn get_token_ids(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        self.transaction.get_token_ids(len, offset)
    }

    async fn get_token_ids_by_ticker(
        &self,
        len: u32,
        offset: u32,
        ticker: &[u8],
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        self.transaction.get_token_ids_by_ticker(len, offset, ticker)
    }

    async fn get_statistic(
        &self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.transaction.get_statistic(statistic, coin_or_token_id)
    }

    async fn get_all_statistic(
        &self,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<BTreeMap<CoinOrTokenStatistic, Amount>, ApiServerStorageError> {
        self.transaction.get_all_statistic(coin_or_token_id)
    }

    async fn get_order(&self, order_id: OrderId) -> Result<Option<Order>, ApiServerStorageError> {
        self.transaction.get_order(order_id)
    }

    async fn get_all_orders(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError> {
        self.transaction.get_orders_by_height(len, offset)
    }

    async fn get_orders_for_trading_pair(
        &self,
        pair: (CoinOrTokenId, CoinOrTokenId),
        len: u32,
        offset: u32,
    ) -> Result<Vec<(OrderId, Order)>, ApiServerStorageError> {
        self.transaction.get_orders_for_trading_pair(pair, len, offset)
    }
}
