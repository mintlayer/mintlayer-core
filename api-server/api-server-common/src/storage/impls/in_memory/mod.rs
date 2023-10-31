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

use crate::storage::storage_api::{block_aux_data::BlockAuxData, ApiServerStorageError};
use common::{
    chain::{Block, ChainConfig, GenBlock, SignedTransaction, Transaction},
    primitives::{Amount, BlockHeight, Id},
};
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
    main_chain_blocks_table: BTreeMap<BlockHeight, Id<Block>>,
    transaction_table: BTreeMap<Id<Transaction>, (Option<Id<Block>>, SignedTransaction)>,
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
            main_chain_blocks_table: BTreeMap::new(),
            transaction_table: BTreeMap::new(),
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
        let best_block_table_handle = self.best_block;
        Ok(best_block_table_handle)
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

    fn set_block(
        &mut self,
        block_id: Id<Block>,
        block: &Block,
    ) -> Result<(), ApiServerStorageError> {
        self.block_table.insert(block_id, block.clone());
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

    fn set_best_block(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<GenBlock>,
    ) -> Result<(), ApiServerStorageError> {
        self.best_block = (block_height, block_id);
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

    fn set_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
        block_id: Id<Block>,
    ) -> Result<(), ApiServerStorageError> {
        self.main_chain_blocks_table.insert(block_height, block_id);
        Ok(())
    }

    fn del_main_chain_block_id(
        &mut self,
        block_height: BlockHeight,
    ) -> Result<(), ApiServerStorageError> {
        self.main_chain_blocks_table.remove(&block_height);
        Ok(())
    }
}
