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
    block_aux_data::BlockAuxData, ApiServerStorageError, Delegation, Utxo,
};
use common::{
    chain::{
        Block, ChainConfig, DelegationId, Destination, GenBlock, PoolId, SignedTransaction,
        Transaction, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id},
};
use pos_accounting::PoolData;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::{Excluded, Unbounded},
};

use super::CURRENT_STORAGE_VERSION;

#[derive(Debug, Clone)]
struct ApiServerInMemoryStorage {
    block_table: BTreeMap<Id<Block>, Block>,
    block_aux_data_table: BTreeMap<Id<Block>, BlockAuxData>,
    address_balance_table: BTreeMap<String, BTreeMap<BlockHeight, Amount>>,
    address_transactions_table: BTreeMap<String, BTreeMap<BlockHeight, Vec<Id<Transaction>>>>,
    delegation_table: BTreeMap<DelegationId, BTreeMap<BlockHeight, Delegation>>,
    main_chain_blocks_table: BTreeMap<BlockHeight, Id<Block>>,
    pool_data_table: BTreeMap<PoolId, BTreeMap<BlockHeight, PoolData>>,
    transaction_table: BTreeMap<Id<Transaction>, (Option<Id<Block>>, SignedTransaction)>,
    utxo_table: BTreeMap<UtxoOutPoint, BTreeMap<BlockHeight, Utxo>>,
    address_utxos: BTreeMap<String, BTreeSet<UtxoOutPoint>>,
    best_block: (BlockHeight, Id<GenBlock>),
    storage_version: u32,
}

impl ApiServerInMemoryStorage {
    pub fn new(chain_config: &ChainConfig) -> Self {
        let mut result = Self {
            block_table: BTreeMap::new(),
            block_aux_data_table: BTreeMap::new(),
            address_balance_table: BTreeMap::new(),
            address_transactions_table: BTreeMap::new(),
            delegation_table: BTreeMap::new(),
            main_chain_blocks_table: BTreeMap::new(),
            pool_data_table: BTreeMap::new(),
            transaction_table: BTreeMap::new(),
            utxo_table: BTreeMap::new(),
            address_utxos: BTreeMap::new(),
            best_block: (0.into(), chain_config.genesis_block_id()),
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

    fn get_address_balance(&self, address: &str) -> Result<Option<Amount>, ApiServerStorageError> {
        self.address_balance_table.get(address).map_or_else(
            || Ok(None),
            |balance| Ok(balance.last_key_value().map(|(_, &v)| v)),
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

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, ApiServerStorageError> {
        let block_result = self.block_table.get(&block_id);
        let block = match block_result {
            Some(blk) => blk,
            None => return Ok(None),
        };
        Ok(Some(block.clone()))
    }

    #[allow(clippy::type_complexity)]
    fn get_transaction_with_block(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<BlockAuxData>, SignedTransaction)>, ApiServerStorageError> {
        let transaction_result = self.transaction_table.get(&transaction_id);
        let (block_id, tx) = match transaction_result {
            Some(tx) => tx,
            None => return Ok(None),
        };

        Ok(Some((
            block_id.and_then(|block_id| self.block_aux_data_table.get(&block_id)).cloned(),
            tx.clone(),
        )))
    }

    #[allow(clippy::type_complexity)]
    fn get_transaction(
        &self,
        transaction_id: Id<Transaction>,
    ) -> Result<Option<(Option<Id<Block>>, SignedTransaction)>, ApiServerStorageError> {
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

    fn get_best_block(&self) -> Result<(BlockHeight, Id<GenBlock>), ApiServerStorageError> {
        Ok(self.best_block)
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
        Ok(Some(block_aux_data.clone()))
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

    fn get_pool_delegations(
        &self,
        pool_id: PoolId,
    ) -> Result<BTreeMap<DelegationId, Delegation>, ApiServerStorageError> {
        Ok(self
            .delegation_table
            .iter()
            .filter_map(|(delegation_id, delegation)| {
                let delegation = delegation.values().last().expect("must be present");
                (delegation.pool_id() == pool_id).then_some((*delegation_id, delegation.clone()))
            })
            .collect())
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
    ) -> Result<Vec<(UtxoOutPoint, TxOutput)>, ApiServerStorageError> {
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
                            .output()
                            .clone(),
                    ))
                })
                .collect()
        });
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
                (last.spend_destination() == address).then_some((*delegation_id, last.clone()))
            })
            .collect())
    }
}

impl ApiServerInMemoryStorage {
    fn initialize_storage(
        &mut self,
        chain_config: &ChainConfig,
    ) -> Result<(), ApiServerStorageError> {
        self.best_block = (0.into(), chain_config.genesis_block_id());
        self.storage_version = CURRENT_STORAGE_VERSION;

        Ok(())
    }

    fn del_address_balance_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        // Inefficient, but acceptable for testing with InMemoryStorage

        self.address_balance_table.iter_mut().for_each(|(_, balance)| {
            balance
                .range((Excluded(block_height), Unbounded))
                .map(|b| b.0.into_int())
                .collect::<Vec<_>>()
                .iter()
                .for_each(|&b| {
                    balance.remove(&BlockHeight::new(b));
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
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.address_balance_table
            .entry(address.to_string())
            .or_default()
            .insert(block_height, amount);

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
        block: &Block,
    ) -> Result<(), ApiServerStorageError> {
        self.block_table.insert(block_id, block.clone());
        self.main_chain_blocks_table.insert(block_height, block_id);
        self.best_block = (block_height, block_id.into());
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

    fn set_transaction(
        &mut self,
        transaction_id: Id<Transaction>,
        owning_block: Option<Id<Block>>,
        transaction: &SignedTransaction,
    ) -> Result<(), ApiServerStorageError> {
        self.transaction_table
            .insert(transaction_id, (owning_block, transaction.clone()));
        Ok(())
    }

    fn set_block_aux_data(
        &mut self,
        block_id: Id<Block>,
        block_aux_data: &BlockAuxData,
    ) -> Result<(), ApiServerStorageError> {
        self.block_aux_data_table.insert(block_id, block_aux_data.clone());
        Ok(())
    }

    fn del_main_chain_blocks_above_height(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.main_chain_blocks_table.retain(|k, _| k <= &block_height);
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
}
