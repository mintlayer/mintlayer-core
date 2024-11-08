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

pub mod transactional;

use crate::storage::storage_api::{
    block_aux_data::{BlockAuxData, BlockWithExtraData},
    ApiServerStorageError, BlockInfo, CoinOrTokenStatistic, Delegation, FungibleTokenData,
    LockedUtxo, Order, PoolBlockStats, TransactionInfo, Utxo, UtxoLock, UtxoWithExtraInfo,
};
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        tokens::{NftIssuance, TokenId},
        Block, ChainConfig, DelegationId, Destination, Genesis, OrderId, PoolId, Transaction,
        UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, CoinOrTokenId, Id},
};
use pos_accounting::PoolData;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    ops::Bound::{Excluded, Unbounded},
    sync::Arc,
};

use super::CURRENT_STORAGE_VERSION;

#[derive(Debug, Clone)]
struct ApiServerInMemoryStorage {
    block_table: BTreeMap<Id<Block>, BlockWithExtraData>,
    block_aux_data_table: BTreeMap<Id<Block>, BlockAuxData>,
    address_balance_table: BTreeMap<String, BTreeMap<(CoinOrTokenId, BlockHeight), Amount>>,
    address_locked_balance_table: BTreeMap<String, BTreeMap<(CoinOrTokenId, BlockHeight), Amount>>,
    address_transactions_table: BTreeMap<String, BTreeMap<BlockHeight, Vec<Id<Transaction>>>>,
    delegation_table: BTreeMap<DelegationId, BTreeMap<BlockHeight, Delegation>>,
    main_chain_blocks_table: BTreeMap<BlockHeight, Id<Block>>,
    pool_data_table: BTreeMap<PoolId, BTreeMap<BlockHeight, PoolData>>,
    transaction_table: BTreeMap<Id<Transaction>, (Id<Block>, TransactionInfo)>,
    utxo_table: BTreeMap<UtxoOutPoint, BTreeMap<BlockHeight, Utxo>>,
    address_utxos: BTreeMap<String, BTreeSet<UtxoOutPoint>>,
    locked_utxo_table: BTreeMap<UtxoOutPoint, BTreeMap<BlockHeight, LockedUtxo>>,
    address_locked_utxos: BTreeMap<String, BTreeSet<UtxoOutPoint>>,
    fungible_token_issuances: BTreeMap<TokenId, BTreeMap<BlockHeight, FungibleTokenData>>,
    nft_token_issuances: BTreeMap<TokenId, BTreeMap<BlockHeight, NftIssuance>>,
    statistics:
        BTreeMap<CoinOrTokenStatistic, BTreeMap<CoinOrTokenId, BTreeMap<BlockHeight, Amount>>>,
    orders_table: BTreeMap<OrderId, BTreeMap<BlockHeight, Order>>,
    best_block: BlockAuxData,
    genesis_block: Arc<WithId<Genesis>>,
    storage_version: u32,
}

impl ApiServerInMemoryStorage {
    pub fn new(chain_config: &ChainConfig) -> Self {
        let mut result = Self {
            block_table: BTreeMap::new(),
            block_aux_data_table: BTreeMap::new(),
            address_balance_table: BTreeMap::new(),
            address_locked_balance_table: BTreeMap::new(),
            address_transactions_table: BTreeMap::new(),
            delegation_table: BTreeMap::new(),
            main_chain_blocks_table: BTreeMap::new(),
            pool_data_table: BTreeMap::new(),
            transaction_table: BTreeMap::new(),
            utxo_table: BTreeMap::new(),
            address_utxos: BTreeMap::new(),
            locked_utxo_table: BTreeMap::new(),
            address_locked_utxos: BTreeMap::new(),
            fungible_token_issuances: BTreeMap::new(),
            nft_token_issuances: BTreeMap::new(),
            statistics: BTreeMap::new(),
            orders_table: BTreeMap::new(),
            genesis_block: chain_config.genesis_block().clone(),
            best_block: BlockAuxData::new(
                chain_config.genesis_block_id(),
                0.into(),
                chain_config.genesis_block().timestamp(),
            ),
            storage_version: super::CURRENT_STORAGE_VERSION,
        };
        result
            .initialize_storage(chain_config)
            .expect("In-memory initialization must succeed");
        result
    }

    fn is_initialized(&self) -> Result<bool, ApiServerStorageError> {
        Ok(true)
    }

    fn get_address_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.address_balance_table.get(address).map_or_else(
            || Ok(None),
            |balance| {
                let range_begin = (coin_or_token_id, BlockHeight::zero());
                let range_end = (coin_or_token_id, BlockHeight::max());
                let range = balance.range(range_begin..=range_end);
                Ok(range.last().map(|(_, v)| *v))
            },
        )
    }

    fn get_address_locked_balance(
        &self,
        address: &str,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        self.address_locked_balance_table.get(address).map_or_else(
            || Ok(None),
            |balance| {
                let range_begin = (coin_or_token_id, BlockHeight::zero());
                let range_end = (coin_or_token_id, BlockHeight::max());
                let range = balance.range(range_begin..=range_end);
                Ok(range.last().map(|(_, v)| *v))
            },
        )
    }

    fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<Id<Transaction>>, ApiServerStorageError> {
        Ok(self
            .address_transactions_table
            .get(address)
            .map_or_else(Vec::new, |transactions| {
                transactions.iter().flat_map(|(_, txs)| txs.iter()).cloned().collect()
            }))
    }

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<BlockInfo>, ApiServerStorageError> {
        let block_result = self.block_table.get(&block_id);
        let block = match block_result {
            Some(blk) => blk,
            None => return Ok(None),
        };
        let height = self.block_aux_data_table.get(&block_id).map(|data| data.block_height());

        Ok(Some(BlockInfo {
            block: block.clone(),
            height,
        }))
    }

    fn get_transactions_with_block(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(BlockAuxData, TransactionInfo)>, ApiServerStorageError> {
        Ok(self
            .main_chain_blocks_table
            .values()
            .rev()
            .flat_map(|block_id| {
                let block_aux = self.block_aux_data_table.get(block_id).expect("must exist");
                let block = self.block_table.get(block_id).expect("must exist");
                block.block.transactions().iter().zip(block.tx_additional_infos.iter()).map(
                    |(tx, additinal_data)| {
                        (
                            *block_aux,
                            TransactionInfo {
                                tx: tx.clone(),
                                additional_info: additinal_data.clone(),
                            },
                        )
                    },
                )
            })
            .skip(offset as usize)
            .take(len as usize)
            .collect())
    }

    #[allow(clippy::type_complexity)]
    fn get_transaction_with_block(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, TransactionInfo)>, ApiServerStorageError> {
        let transaction_result = self.transaction_table.get(&transaction_id);
        let (block_id, tx) = match transaction_result {
            Some(tx) => tx,
            None => return Ok(None),
        };

        Ok(Some((
            self.block_aux_data_table.get(block_id).cloned(),
            tx.clone(),
        )))
    }

    #[allow(clippy::type_complexity)]
    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Id<Block>, TransactionInfo)>, ApiServerStorageError> {
        let transaction_result = self.transaction_table.get(&transaction_id);
        let tx = match transaction_result {
            Some(tx) => tx,
            None => return Ok(None),
        };
        Ok(Some(tx.clone()))
    }

    fn get_storage_version(&self) -> Result<u32, ApiServerStorageError> {
        let version_table_handle = self.storage_version;
        Ok(version_table_handle)
    }

    fn get_best_block(&self) -> Result<BlockAuxData, ApiServerStorageError> {
        Ok(self.best_block)
    }

    fn get_latest_blocktimestamps(&self) -> Result<Vec<BlockTimestamp>, ApiServerStorageError> {
        Ok(self
            .main_chain_blocks_table
            .iter()
            .rev()
            .map(|(_, id)| {
                self.block_table
                    .get(id)
                    .expect("Block id must be present in block_table")
                    .block
                    .timestamp()
            })
            .chain(std::iter::once(self.genesis_block.timestamp()))
            .take(chainstate::MEDIAN_TIME_SPAN)
            .collect())
    }

    fn get_block_aux_data(
        &self,
        block_id: Id<Block>,
    ) -> Result<Option<BlockAuxData>, ApiServerStorageError> {
        let block_aux_data_result = self.block_aux_data_table.get(&block_id);
        let block_aux_data = match block_aux_data_result {
            Some(data) => data,
            None => return Ok(None),
        };
        Ok(Some(*block_aux_data))
    }

    fn get_block_range_from_time_range(
        &self,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<(BlockHeight, BlockHeight), ApiServerStorageError> {
        let from_height = self
            .main_chain_blocks_table
            .iter()
            .find_map(|(k, v)| {
                (self.block_aux_data_table.get(v).expect("must exist").block_timestamp()
                    >= time_range.0)
                    .then_some(*k)
            })
            .unwrap_or(BlockHeight::new(0));

        let to_height = self
            .main_chain_blocks_table
            .iter()
            .rev()
            .find_map(|(k, v)| {
                (self.block_aux_data_table.get(v).expect("must exist").block_timestamp()
                    <= time_range.1)
                    .then_some(*k)
            })
            .unwrap_or(BlockHeight::new(0));

        Ok((from_height, to_height))
    }

    fn get_delegation(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Delegation>, ApiServerStorageError> {
        let delegation_result = self.delegation_table.get(&delegation_id);
        let delegation = match delegation_result {
            Some(data) => data,
            None => return Ok(None),
        };
        Ok(delegation.last_key_value().map(|(_, v)| v.clone()))
    }

    fn get_pool_block_stats(
        &self,
        pool_id: PoolId,
        block_range: (BlockHeight, BlockHeight),
    ) -> Result<Option<PoolBlockStats>, ApiServerStorageError> {
        Ok(self.pool_data_table.get(&pool_id).map(|by_height| {
            // skip the first one as that is the pool creation
            let from = std::cmp::max(
                block_range.0,
                by_height.keys().next().expect("not empty").next_height(),
            );
            // skip the last if it is decommissioned
            let last = by_height.values().last().expect("not empty");
            let to = if last.is_decommissioned() {
                *by_height.keys().last().expect("not empty")
            } else {
                block_range.1
            };

            PoolBlockStats {
                block_count: by_height.range(from..to).count() as u64,
            }
        }))
    }

    fn get_pool_delegations(
        &self,
        pool_id: PoolId,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError> {
        Ok(self
            .delegation_table
            .iter()
            .filter_map(|(delegation_id, delegation)| {
                let delegation = delegation.values().last().expect("must be present");
                (*delegation.pool_id() == pool_id)
                    .then_some((delegation_id.to_owned(), delegation.clone()))
            })
            .collect())
    }

    fn get_order(&self, order_id: OrderId) -> Result<Option<Order>, ApiServerStorageError> {
        let order_result = self.orders_table.get(&order_id);
        let order = order_result.and_then(|order| order.last_key_value().map(|(_, v)| v.clone()));
        Ok(order)
    }

    fn get_latest_pool_ids(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError> {
        let len = len as usize;
        let offset = offset as usize;
        let mut pool_data: Vec<_> = self
            .pool_data_table
            .iter()
            .map(|(pool_id, by_height)| {
                let created_height = by_height.keys().next().expect("not empty");
                let latest_data = by_height.values().last().expect("not empty");
                (pool_id, (created_height, latest_data))
            })
            .filter(|(_pool_id, data)| !data.1.is_decommissioned())
            .collect();

        pool_data.sort_by_key(|(_, (height, _data))| Reverse(*height));
        if offset >= pool_data.len() {
            return Ok(vec![]);
        }

        let latest_pools = pool_data[offset..std::cmp::min(offset + len, pool_data.len())]
            .iter()
            .map(|(pool_id, data)| (**pool_id, (data.1).clone()))
            .collect();

        Ok(latest_pools)
    }

    fn get_pool_data_with_largest_staker_balance(
        &self,
        len: u32,
        offset: u32,
    ) -> Result<Vec<(PoolId, PoolData)>, ApiServerStorageError> {
        let len = len as usize;
        let offset = offset as usize;
        let mut pool_data: Vec<_> = self
            .pool_data_table
            .iter()
            .map(|(pool_id, by_height)| (pool_id, by_height.values().last().expect("not empty")))
            .filter(|(_pool_id, data)| !data.is_decommissioned())
            .collect();

        pool_data.sort_by_key(|(_, data)| Reverse(data.staker_balance().expect("no overflow")));
        if offset >= pool_data.len() {
            return Ok(vec![]);
        }

        let latest_pools = pool_data[offset..std::cmp::min(offset + len, pool_data.len())]
            .iter()
            .map(|(pool_id, data)| (**pool_id, (*data).clone()))
            .collect();

        Ok(latest_pools)
    }

    fn get_main_chain_block_id(
        &self,
        block_height: BlockHeight,
    ) -> Result<Option<Id<Block>>, ApiServerStorageError> {
        let block_id_result = self.main_chain_blocks_table.get(&block_height);
        let block_id = match block_id_result {
            Some(id) => id,
            None => return Ok(None),
        };
        Ok(Some(*block_id))
    }

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, ApiServerStorageError> {
        let pool_data_result = self.pool_data_table.get(&pool_id);
        match pool_data_result {
            Some(data) => Ok(data.last_key_value().map(|(_, v)| v.clone())),
            None => Ok(None),
        }
    }

    fn get_utxo(&self, outpoint: UtxoOutPoint) -> Result<Option<Utxo>, ApiServerStorageError> {
        Ok(self
            .utxo_table
            .get(&outpoint)
            .and_then(|by_height| by_height.values().last())
            .cloned())
    }

    fn get_address_available_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let result = self.address_utxos.get(address).map_or(vec![], |outpoints| {
            outpoints
                .iter()
                .filter_map(|outpoint| {
                    let utxo =
                        self.get_utxo(outpoint.clone()).expect("no error").expect("must exist");
                    (!utxo.spent()).then_some((
                        outpoint.clone(),
                        self.get_utxo(outpoint.clone())
                            .expect("no error")
                            .expect("must exist")
                            .utxo_with_extra_info()
                            .clone(),
                    ))
                })
                .collect()
        });
        Ok(result)
    }

    fn get_address_all_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let result = self
            .address_utxos
            .get(address)
            .unwrap_or(&BTreeSet::new())
            .union(self.address_locked_utxos.get(address).unwrap_or(&BTreeSet::new()))
            .filter_map(|outpoint| {
                if let Some(utxo) = self.get_utxo(outpoint.clone()).expect("no error") {
                    (!utxo.spent())
                        .then_some((outpoint.clone(), utxo.utxo_with_extra_info().clone()))
                } else {
                    Some((
                        outpoint.clone(),
                        self.locked_utxo_table
                            .get(outpoint)
                            .expect("must exit")
                            .values()
                            .last()
                            .expect("not empty")
                            .utxo_with_extra_info()
                            .clone(),
                    ))
                }
            })
            .collect();
        Ok(result)
    }

    fn get_locked_utxos_until_now(
        &self,
        block_height: BlockHeight,
        time_range: (BlockTimestamp, BlockTimestamp),
    ) -> Result<Vec<(UtxoOutPoint, UtxoWithExtraInfo)>, ApiServerStorageError> {
        let result = self
            .locked_utxo_table
            .iter()
            .map(|(outpoint, by_height)| (outpoint, by_height.values().last().expect("not empty")))
            .filter_map(|(outpint, locked_utxo)| {
                match locked_utxo.lock() {
                    UtxoLock::UntilHeight(height) => height == block_height,
                    UtxoLock::UntilTime(time) => time > time_range.0 && time <= time_range.1,
                }
                .then_some((outpint.clone(), locked_utxo.utxo_with_extra_info().clone()))
            })
            .collect();
        Ok(result)
    }

    fn get_delegations_from_address(
        &self,
        address: &Destination,
    ) -> Result<Vec<(DelegationId, Delegation)>, ApiServerStorageError> {
        Ok(self
            .delegation_table
            .iter()
            .filter_map(|(delegation_id, by_height)| {
                let last = by_height.values().last().expect("not empty");
                (last.spend_destination() == address)
                    .then_some((delegation_id.to_owned(), last.clone()))
            })
            .collect())
    }

    fn get_fungible_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<FungibleTokenData>, ApiServerStorageError> {
        Ok(self
            .fungible_token_issuances
            .get(&token_id)
            .map(|by_height| by_height.values().last().cloned().expect("not empty")))
    }

    fn get_nft_token_issuance(
        &self,
        token_id: TokenId,
    ) -> Result<Option<NftIssuance>, ApiServerStorageError> {
        Ok(self
            .nft_token_issuances
            .get(&token_id)
            .map(|by_height| by_height.values().last().cloned().expect("not empty")))
    }

    fn get_token_num_decimals(
        &self,
        token_id: TokenId,
    ) -> Result<Option<u8>, ApiServerStorageError> {
        Ok(self
            .fungible_token_issuances
            .get(&token_id)
            .map(|data| data.values().last().expect("not empty").number_of_decimals)
            .or_else(|| self.nft_token_issuances.get(&token_id).map(|_| 0)))
    }

    fn get_token_ids(&self, len: u32, offset: u32) -> Result<Vec<TokenId>, ApiServerStorageError> {
        Ok(self
            .fungible_token_issuances
            .keys()
            .chain(self.nft_token_issuances.keys())
            .skip(offset as usize)
            .take(len as usize)
            .copied()
            .collect())
    }

    fn get_token_ids_by_ticker(
        &self,
        len: u32,
        offset: u32,
        ticker: &[u8],
    ) -> Result<Vec<TokenId>, ApiServerStorageError> {
        Ok(self
            .fungible_token_issuances
            .iter()
            .filter_map(|(key, value)| {
                (value.values().last().expect("not empty").token_ticker == ticker).then_some(key)
            })
            .chain(self.nft_token_issuances.iter().filter_map(|(key, value)| {
                let value_ticker = match &value.values().last().expect("not empty") {
                    NftIssuance::V0(data) => data.metadata.ticker(),
                };
                (value_ticker == ticker).then_some(key)
            }))
            .skip(offset as usize)
            .take(len as usize)
            .copied()
            .collect())
    }

    fn get_statistic(
        &self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<Option<Amount>, ApiServerStorageError> {
        Ok(self
            .statistics
            .get(&statistic)
            .and_then(|by_coin| by_coin.get(&coin_or_token_id))
            .map(|data| data.values().last().expect("not empty"))
            .copied())
    }

    fn get_all_statistic(
        &self,
        coin_or_token_id: CoinOrTokenId,
    ) -> Result<BTreeMap<CoinOrTokenStatistic, Amount>, ApiServerStorageError> {
        Ok(self
            .statistics
            .iter()
            .filter_map(|(statistic, by_coin)| Some((statistic, by_coin.get(&coin_or_token_id)?)))
            .map(|(statistic, data)| (*statistic, *data.values().last().expect("not empty")))
            .collect())
    }

    fn set_statistic(
        &mut self,
        statistic: CoinOrTokenStatistic,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
        amount: Amount,
    ) -> Result<(), ApiServerStorageError> {
        self.statistics
            .entry(statistic)
            .or_default()
            .entry(coin_or_token_id)
            .or_default()
            .insert(block_height, amount);
        Ok(())
    }

    fn del_statistics_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.statistics.values_mut().for_each(|stat| {
            stat.retain(|_, by_height| {
                by_height.retain(|k, _| *k <= block_height);
                !by_height.is_empty()
            })
        });
        Ok(())
    }
}

impl ApiServerInMemoryStorage {
    fn initialize_storage(
        &mut self,
        _chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.storage_version = CURRENT_STORAGE_VERSION;

        Ok(())
    }

    fn reinitialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.block_table.clear();
        self.block_aux_data_table.clear();
        self.address_balance_table.clear();
        self.address_locked_balance_table.clear();
        self.address_transactions_table.clear();
        self.delegation_table.clear();
        self.main_chain_blocks_table.clear();
        self.pool_data_table.clear();
        self.transaction_table.clear();
        self.utxo_table.clear();
        self.address_utxos.clear();
        self.fungible_token_issuances.clear();
        self.nft_token_issuances.clear();
        self.orders_table.clear();

        self.initialize_storage(chain_config)
    }

    fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        // Inefficient, but acceptable for testing with InMemoryStorage

        self.address_balance_table.iter_mut().for_each(|(_, balance)| {
            balance
                .iter()
                .filter(|((_, height), _)| *height > block_height)
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
                .iter()
                .for_each(|key| {
                    balance.remove(key);
                })
        });

        Ok(())
    }

    fn del_address_locked_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        // Inefficient, but acceptable for testing with InMemoryStorage

        self.address_locked_balance_table.iter_mut().for_each(|(_, balance)| {
            balance
                .iter()
                .filter(|((_, height), _)| *height > block_height)
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
                .iter()
                .for_each(|key| {
                    balance.remove(key);
                })
        });

        Ok(())
    }

    fn del_address_transactions_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        // Inefficient, but acceptable for testing with InMemoryStorage

        self.address_transactions_table.iter_mut().for_each(|(_, transactions)| {
            transactions
                .range((Excluded(block_height), Unbounded))
                .map(|b| b.0.into_int())
                .collect::<Vec<_>>()
                .iter()
                .for_each(|&b| {
                    transactions.remove(&BlockHeight::new(b));
                })
        });

        Ok(())
    }

    fn set_address_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.address_balance_table
            .entry(address.to_string())
            .or_default()
            .entry((coin_or_token_id, block_height))
            .and_modify(|e| *e = amount)
            .or_insert(amount);

        Ok(())
    }

    fn set_address_locked_balance_at_height(
        &mut self,
        address: &str,
        amount: Amount,
        coin_or_token_id: CoinOrTokenId,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.address_locked_balance_table
            .entry(address.to_string())
            .or_default()
            .entry((coin_or_token_id, block_height))
            .and_modify(|e| *e = amount)
            .or_insert(amount);

        Ok(())
    }

    fn set_address_transactions_at_height(
        &mut self,
        address: &str,
        transaction_ids: BTreeSet<Id<Transaction>>,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.address_transactions_table
            .entry(address.to_string())
            .or_default()
            .insert(block_height, transaction_ids.into_iter().collect());

        Ok(())
    }

    fn set_mainchain_block(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
        block: &BlockWithExtraData,
    ) -> Result<(), ApiServerStorageError> {
        self.block_table.insert(block_id, block.clone());
        self.block_aux_data_table.insert(
            block_id,
            BlockAuxData::new(block_id.into(), block_height, block.block.timestamp()),
        );
        self.main_chain_blocks_table.insert(block_height, block_id);
        self.best_block = BlockAuxData::new(block_id.into(), block_height, block.block.timestamp());
        Ok(())
    }

    fn set_delegation_at_height(
        &mut self,
        delegation_id: DelegationId,
        delegation: &Delegation,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.delegation_table
            .entry(delegation_id)
            .or_default()
            .insert(block_height, delegation.clone());
        Ok(())
    }

    fn set_order_at_height(
        &mut self,
        order_id: OrderId,
        order: Order,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.orders_table.entry(order_id).or_default().insert(block_height, order);
        Ok(())
    }

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Id<Block>,
        transaction: &TransactionInfo,
    ) -> Result<(), ApiServerStorageError> {
        // Emulate the behavior of real db where foreign key must be present
        if !self.block_table.contains_key(&owning_block) {
            return Err(ApiServerStorageError::LowLevelStorageError(
                "Owning block must exist in block table".to_string(),
            ));
        }

        self.transaction_table
            .insert(transaction_id, (owning_block, transaction.clone()));
        Ok(())
    }

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError> {
        self.block_aux_data_table.insert(block_id, *block_aux_data);
        Ok(())
    }

    fn del_main_chain_blocks_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.main_chain_blocks_table.retain(|k, id| {
            if k <= &block_height {
                true
            } else {
                self.block_aux_data_table.remove(id);
                false
            }
        });
        Ok(())
    }

    fn set_pool_data_at_height(
        &mut self,
        pool_id: PoolId,
        pool_data: &PoolData,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.pool_data_table
            .entry(pool_id)
            .or_default()
            .insert(block_height, pool_data.clone());
        Ok(())
    }

    fn del_delegations_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.delegation_table.retain(|_, v| {
            v.retain(|k, _| k <= &block_height);
            !v.is_empty()
        });

        Ok(())
    }

    fn del_pools_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.pool_data_table.retain(|_, v| {
            v.retain(|k, _| k <= &block_height);
            !v.is_empty()
        });

        Ok(())
    }

    fn del_orders_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.orders_table.retain(|_, v| {
            v.retain(|k, _| k <= &block_height);
            !v.is_empty()
        });

        Ok(())
    }

    fn set_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: Utxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.utxo_table.entry(outpoint.clone()).or_default().insert(block_height, utxo);
        self.address_utxos.entry(address.into()).or_default().insert(outpoint);
        Ok(())
    }

    fn set_locked_utxo_at_height(
        &mut self,
        outpoint: UtxoOutPoint,
        utxo: LockedUtxo,
        address: &str,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.locked_utxo_table
            .entry(outpoint.clone())
            .or_default()
            .insert(block_height, utxo);
        self.address_locked_utxos.entry(address.into()).or_default().insert(outpoint);
        Ok(())
    }

    fn del_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.utxo_table.retain(|outpoint, v| {
            v.retain(|k, _| k <= &block_height);
            if v.is_empty() {
                self.address_utxos.retain(|_, v| {
                    v.remove(outpoint);
                    !v.is_empty()
                });
            }
            !v.is_empty()
        });

        Ok(())
    }

    fn del_locked_utxo_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.locked_utxo_table.retain(|outpoint, v| {
            v.retain(|k, _| k <= &block_height);
            if v.is_empty() {
                self.address_locked_utxos.retain(|_, v| {
                    v.remove(outpoint);
                    !v.is_empty()
                });
            }
            !v.is_empty()
        });

        Ok(())
    }

    fn set_fungible_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: FungibleTokenData,
    ) -> Result<(), ApiServerStorageError> {
        self.fungible_token_issuances
            .entry(token_id)
            .or_default()
            .insert(block_height, issuance);
        Ok(())
    }

    fn set_nft_token_issuance(
        &mut self,
        token_id: TokenId,
        block_height: BlockHeight,
        issuance: NftIssuance,
    ) -> Result<(), ApiServerStorageError> {
        self.nft_token_issuances
            .entry(token_id)
            .or_default()
            .insert(block_height, issuance);
        Ok(())
    }

    fn del_token_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.fungible_token_issuances.retain(|_, v| {
            v.retain(|k, _| k <= &block_height);
            !v.is_empty()
        });

        Ok(())
    }

    fn del_nft_issuance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.nft_token_issuances.retain(|_, v| {
            v.retain(|k, _| k <= &block_height);
            !v.is_empty()
        });

        Ok(())
    }
}
