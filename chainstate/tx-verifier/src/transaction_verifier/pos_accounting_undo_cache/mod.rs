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

use super::{error::ConnectTransactionError, CachedOperation, TransactionSource};
use common::{chain::Transaction, primitives::Id};
use pos_accounting::{BlockRewardUndo, BlockUndoError, TxUndo};

mod cached_block_undo;
pub use cached_block_undo::CachedPoSBlockUndo;

pub type CachedPoSBlockUndoOp = CachedOperation<CachedPoSBlockUndo>;

/// Struct that can hold PoS accounting undo data for blocks/mempool.
///
/// See `UtxosBlockUndoCache` for a general info
#[derive(Debug, Eq, PartialEq)]
pub struct PoSAccountingBlockUndoCache {
    data: BTreeMap<TransactionSource, CachedPoSBlockUndoOp>,
}

impl PoSAccountingBlockUndoCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(data: BTreeMap<TransactionSource, CachedPoSBlockUndoOp>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &BTreeMap<TransactionSource, CachedPoSBlockUndoOp> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<TransactionSource, CachedPoSBlockUndoOp> {
        self.data
    }

    /// Add undo object for a reward.
    /// If it's the first undo in the block then the BlockUndo struct is initialized.
    pub fn add_reward_undo(
        &mut self,
        tx_source: TransactionSource,
        reward_undo: BlockRewardUndo,
    ) -> Result<(), ConnectTransactionError> {
        match self.data.entry(tx_source) {
            Entry::Occupied(mut entry) => match entry.get() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => {
                    let mut block_undo = undo.clone();
                    block_undo.set_block_reward_undo(reward_undo);
                    entry.insert(CachedOperation::Write(block_undo));
                }
                CachedOperation::Erase => {
                    let block_undo = CachedPoSBlockUndo::new(Some(reward_undo), BTreeMap::new())?;
                    entry.insert(CachedOperation::Write(block_undo));
                }
            },
            Entry::Vacant(entry) => {
                let block_undo = CachedPoSBlockUndo::new(Some(reward_undo), BTreeMap::new())?;
                entry.insert(CachedOperation::Write(block_undo));
            }
        };

        Ok(())
    }

    /// Add undo object for a transaction.
    /// If it's the first undo in the block then the BlockUndo struct is initialized.
    pub fn add_tx_undo(
        &mut self,
        tx_source: TransactionSource,
        tx_id: Id<Transaction>,
        tx_undo: TxUndo,
    ) -> Result<(), ConnectTransactionError> {
        match self.data.entry(tx_source) {
            Entry::Occupied(mut entry) => match entry.get() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => {
                    let mut block_undo = undo.clone();
                    block_undo.insert_tx_undo(tx_id, tx_undo)?;
                    entry.insert(CachedOperation::Write(block_undo.clone()));
                }
                CachedOperation::Erase => {
                    let block_undo =
                        CachedPoSBlockUndo::new(None, BTreeMap::from_iter([(tx_id, tx_undo)]))?;
                    entry.insert(CachedOperation::Write(block_undo));
                }
            },
            Entry::Vacant(entry) => {
                let block_undo =
                    CachedPoSBlockUndo::new(None, BTreeMap::from_iter([(tx_id, tx_undo)]))?;
                entry.insert(CachedOperation::Write(block_undo));
            }
        };

        Ok(())
    }

    /// Take tx undo object out if available.
    /// If the block is fully disconnected the block undo object is erased.
    pub fn take_tx_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
        fetcher_func: F,
    ) -> Result<Option<TxUndo>, ConnectTransactionError>
    where
        F: Fn(TransactionSource) -> Result<Option<CachedPoSBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        let block_undo = match self.data.entry(*tx_source) {
            Entry::Vacant(_) => fetcher_func(*tx_source)?,
            Entry::Occupied(entry) => match entry.get() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => Some(undo.clone()),
                CachedOperation::Erase => panic!(
                    "Attempt to undo pos a transaction for a block that has been fully disconnected."
                ),
            },
        };

        if let Some(mut block_undo) = block_undo {
            let res = block_undo.take_tx_undo(tx_id)?;

            if res.is_some() {
                // if block undo used up completely then remove it from the db
                if block_undo.is_empty() {
                    self.data.insert(*tx_source, CachedOperation::Erase);
                } else {
                    self.data.insert(*tx_source, CachedOperation::Write(block_undo));
                }
            }
            return Ok(res);
        }

        Ok(None)
    }

    /// Take reward undo object out if available.
    /// If the block is fully disconnected the block undo object is erased.
    pub fn take_block_reward_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<Option<BlockRewardUndo>, ConnectTransactionError>
    where
        F: Fn(TransactionSource) -> Result<Option<CachedPoSBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        let block_undo = match self.data.entry(*tx_source) {
            Entry::Vacant(_) => fetcher_func(*tx_source)?,
            Entry::Occupied(entry) => match entry.get() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => Some(undo.clone()),
                CachedOperation::Erase => None,
            },
        };

        let res = block_undo.and_then(|mut block_undo| {
            let reward_undo = block_undo.take_block_reward_undo();

            if reward_undo.is_some() {
                // if block undo used up completely then remove it from the db
                if block_undo.is_empty() {
                    self.data.insert(*tx_source, CachedOperation::Erase);
                } else {
                    self.data.insert(*tx_source, CachedOperation::Write(block_undo));
                }
            }
            reward_undo
        });

        Ok(res)
    }

    // Set undo data for a particular block or mempool.
    // If there is some data already then it's combined with the new one.
    pub fn set_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &CachedPoSBlockUndo,
    ) -> Result<(), BlockUndoError> {
        match self.data.entry(tx_source) {
            Entry::Vacant(e) => {
                e.insert(CachedOperation::Write(new_undo.clone()));
            }
            Entry::Occupied(mut e) => match e.get_mut() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => {
                    undo.combine(new_undo.clone())?;
                }
                CachedOperation::Erase => {
                    e.insert(CachedOperation::Write(new_undo.clone()));
                }
            },
        };
        Ok(())
    }

    pub fn del_undo_data(&mut self, tx_source: TransactionSource) -> Result<(), BlockUndoError> {
        self.data.insert(tx_source, CachedOperation::Erase);
        Ok(())
    }
}
