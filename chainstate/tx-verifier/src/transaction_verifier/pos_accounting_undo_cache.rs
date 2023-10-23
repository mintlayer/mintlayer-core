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
use common::{
    chain::{Block, Transaction},
    primitives::Id,
};
use pos_accounting::{
    AccountingBlockRewardUndo, AccountingBlockUndo, AccountingBlockUndoError, AccountingTxUndo,
};

#[derive(Debug, Eq, PartialEq)]
pub struct PoSAccountingBlockUndoEntry {
    pub undo: AccountingBlockUndo,
    // indicates whether this BlockUndo was fetched from the db or it's new
    pub is_fresh: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PoSAccountingBlockUndoCache {
    data: BTreeMap<TransactionSource, PoSAccountingBlockUndoEntry>,
}

impl PoSAccountingBlockUndoCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(data: BTreeMap<TransactionSource, PoSAccountingBlockUndoEntry>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &BTreeMap<TransactionSource, PoSAccountingBlockUndoEntry> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<TransactionSource, PoSAccountingBlockUndoEntry> {
        self.data
    }

    fn fetch_block_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<Option<&mut AccountingBlockUndo>, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<AccountingBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        match self.data.entry(*tx_source) {
            Entry::Occupied(entry) => Ok(Some(&mut entry.into_mut().undo)),
            Entry::Vacant(entry) => match tx_source {
                TransactionSource::Chain(block_id) => {
                    let entry = fetcher_func(*block_id)?.map(|block_undo| {
                        &mut entry
                            .insert(PoSAccountingBlockUndoEntry {
                                undo: block_undo,
                                is_fresh: false,
                            })
                            .undo
                    });
                    Ok(entry)
                }
                TransactionSource::Mempool => Ok(None),
            },
        }
    }

    pub fn take_tx_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
        fetcher_func: F,
    ) -> Result<Option<AccountingTxUndo>, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<AccountingBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        Ok(self
            .fetch_block_undo(tx_source, fetcher_func)?
            .and_then(|entry| entry.take_tx_undo(tx_id)))
    }

    pub fn take_block_reward_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<Option<AccountingBlockRewardUndo>, ConnectTransactionError>
    where
        F: Fn(Id<Block>) -> Result<Option<AccountingBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        Ok(self
            .fetch_block_undo(tx_source, fetcher_func)?
            .and_then(|entry| entry.take_reward_undos()))
    }

    pub fn get_or_create_block_undo(
        &mut self,
        tx_source: &TransactionSource,
    ) -> &mut AccountingBlockUndo {
        &mut self
            .data
            .entry(*tx_source)
            .or_insert(PoSAccountingBlockUndoEntry {
                is_fresh: true,
                undo: Default::default(),
            })
            .undo
    }

    pub fn set_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &AccountingBlockUndo,
    ) -> Result<(), AccountingBlockUndoError> {
        match self.data.entry(tx_source) {
            Entry::Vacant(e) => {
                e.insert(PoSAccountingBlockUndoEntry {
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
    ) -> Result<(), AccountingBlockUndoError> {
        // delete undo from current cache
        if self.data.remove(&tx_source).is_none() {
            // if current cache doesn't have such data - insert empty undo to be flushed to the parent
            self.data.insert(
                tx_source,
                PoSAccountingBlockUndoEntry {
                    undo: Default::default(),
                    is_fresh: false,
                },
            );
        }
        Ok(())
    }
}
