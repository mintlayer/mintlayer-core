// Copyright (c) 2022 RBB S.r.l
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

use std::collections::{btree_map::Entry, BTreeMap};

use super::{error::ConnectTransactionError, TransactionSource};
use chainstate_types::storage_result;
use common::{
    chain::{Block, Transaction},
    primitives::Id,
};
use utxo::{BlockRewardUndo, BlockUndo, TxUndo};

#[derive(Debug, Eq, PartialEq)]
pub struct UtxosBlockUndoEntry {
    pub undo: BlockUndo,
    // indicates whether this BlockUndo was fetched from the db or it's new
    pub is_fresh: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct UtxosBlockUndoCache {
    data: BTreeMap<TransactionSource, UtxosBlockUndoEntry>,
}

impl UtxosBlockUndoCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(data: BTreeMap<TransactionSource, UtxosBlockUndoEntry>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &BTreeMap<TransactionSource, UtxosBlockUndoEntry> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<TransactionSource, UtxosBlockUndoEntry> {
        self.data
    }

    pub fn read_block_undo<F>(
        &self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<BlockUndo, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<BlockUndo>, storage_result::Error>,
    {
        match self.data.get(tx_source) {
            Some(entry) => Ok(entry.undo.clone()),
            None => match tx_source {
                TransactionSource::Chain(block_id) => {
                    let block_undo = fetcher_func(*block_id)?
                        .ok_or(ConnectTransactionError::MissingBlockUndo(*block_id))?;
                    Ok(block_undo)
                }
                TransactionSource::Mempool => Err(ConnectTransactionError::MissingMempoolTxsUndo),
            },
        }
    }

    pub fn fetch_block_undo<F>(
        &mut self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<&mut BlockUndo, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<BlockUndo>, storage_result::Error>,
    {
        match self.data.entry(*tx_source) {
            Entry::Occupied(entry) => Ok(&mut entry.into_mut().undo),
            Entry::Vacant(entry) => match tx_source {
                TransactionSource::Chain(block_id) => {
                    let block_undo = fetcher_func(*block_id)?
                        .ok_or(ConnectTransactionError::MissingBlockUndo(*block_id))?;
                    Ok(&mut entry
                        .insert(UtxosBlockUndoEntry {
                            undo: block_undo,
                            is_fresh: false,
                        })
                        .undo)
                }
                TransactionSource::Mempool => Err(ConnectTransactionError::MissingMempoolTxsUndo),
            },
        }
    }

    pub fn take_tx_undo<F>(
        &mut self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
        fetcher_func: F,
    ) -> Result<TxUndo, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<BlockUndo>, storage_result::Error>,
    {
        let block_undo = self.fetch_block_undo(tx_source, fetcher_func)?;

        if block_undo.has_children_of(tx_id) {
            Err(ConnectTransactionError::TxUndoWithDependency(*tx_id))
        } else {
            block_undo
                .take_tx_undo(tx_id)
                .ok_or(ConnectTransactionError::MissingTxUndo(*tx_id))
        }
    }

    pub fn take_block_reward_undo<F>(
        &mut self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<Option<BlockRewardUndo>, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<BlockUndo>, storage_result::Error>,
    {
        Ok(self.fetch_block_undo(tx_source, fetcher_func)?.take_block_reward_undo())
    }

    pub fn get_or_create_block_undo(&mut self, tx_source: &TransactionSource) -> &mut BlockUndo {
        &mut self
            .data
            .entry(*tx_source)
            .or_insert(UtxosBlockUndoEntry {
                is_fresh: true,
                undo: Default::default(),
            })
            .undo
    }

    pub fn set_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &BlockUndo,
    ) -> Result<(), utxo::BlockUndoError> {
        match self.data.entry(tx_source) {
            Entry::Vacant(e) => {
                e.insert(UtxosBlockUndoEntry {
                    undo: new_undo.clone(),
                    is_fresh: true,
                });
            }
            Entry::Occupied(mut e) => {
                e.get_mut().undo.combine(new_undo.clone())?;
            }
        };
        Ok(())
    }

    pub fn del_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), utxo::BlockUndoError> {
        // delete undo from current cache
        if self.data.remove(&tx_source).is_none() {
            // if current cache doesn't have such data - insert empty undo to be flushed to the parent
            self.data.insert(
                tx_source,
                UtxosBlockUndoEntry {
                    undo: Default::default(),
                    is_fresh: false,
                },
            );
        }
        Ok(())
    }
}
