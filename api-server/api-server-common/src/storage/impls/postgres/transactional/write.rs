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
    chain::{
        block::timestamp::BlockTimestamp,
        tokens::{NftIssuance, TokenId},
        Block, ChainConfig, DelegationId, Destination, PoolId, Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};
use pos_accounting::PoolData;

use crate::storage::{
    impls::postgres::queries::QueryFromConnection,
    storage_api::{
        block_aux_data::{BlockAuxData, BlockWithExtraData},
        ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite, BlockInfo, Delegation,
        FungibleTokenData, LockedUtxo, PoolBlockStats, TransactionInfo, Utxo,
    },
};

use super::{ApiServerPostgresTransactionalRw, CONN_ERR};

#[async_trait::async_trait]
impl<'a> ApiServerStorageWrite for ApiServerPostgresTransactionalRw<'a> {
    async fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.initialize_database(chain_config).await?;

        Ok(())
    }

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
        address: &str,
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
        address: &str,
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
        owning_block: Option<Id<Block>>,
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
        pool_data: &PoolData,
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

    async fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
    ) -> Result<(), ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        conn.set_nft_token_issuance(token_id, block_height, issuance).await?;

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
}

#[async_trait::async_trait]
impl<'a> ApiServerStorageRead for ApiServerPostgresTransactionalRw<'a> {
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
    ) -> Result<Option<PoolData>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_pool_data(pool_id, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_latest_pool_data(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_latest_pool_data(len, offset, &self.chain_config).await?;

        Ok(res)
    }

    async fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError> {
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
    ) -> Result<Option<(Option<Id<Block>>, TransactionInfo)>, ApiServerStorageError> {
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
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError> {
        let mut conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_available_utxos(address).await?;

        Ok(res)
    }

    async fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_address_all_utxos(address).await?;

        Ok(res)
    }

    async fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError> {
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
    ) -> Result<Option<NftIssuance>, ApiServerStorageError> {
        let conn = QueryFromConnection::new(self.connection.as_ref().expect(CONN_ERR));
        let res = conn.get_nft_token_issuance(token_id).await?;

        Ok(res)
    }
}
