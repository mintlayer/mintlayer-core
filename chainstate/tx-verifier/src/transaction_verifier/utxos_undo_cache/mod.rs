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
use utxo::{UtxosBlockRewardUndo, UtxosTxUndo, UtxosTxUndoWithSources};

mod cached_utxo_block_undo;
pub use cached_utxo_block_undo::CachedUtxosBlockUndo;

pub type CachedUtxoBlockUndoOp = CachedOperation<CachedUtxosBlockUndo>;

#[derive(Debug, Eq, PartialEq)]
pub struct UtxosBlockUndoCache {
    data: BTreeMap<TransactionSource, CachedUtxoBlockUndoOp>,
}

impl UtxosBlockUndoCache {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(data: BTreeMap<TransactionSource, CachedUtxoBlockUndoOp>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &BTreeMap<TransactionSource, CachedUtxoBlockUndoOp> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<TransactionSource, CachedUtxoBlockUndoOp> {
        self.data
    }

    pub fn get_block_undo<F, E>(
        &self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<Option<CachedUtxosBlockUndo>, ConnectTransactionError>
    where
        F: Fn(TransactionSource) -> Result<Option<CachedUtxosBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        match self.data.get(tx_source) {
            Some(op) => match op {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => {
                    Ok(Some(undo.clone()))
                }
                CachedOperation::Erase => Ok(None),
            },
            None => fetcher_func(*tx_source).map_err(ConnectTransactionError::from),
        }
    }

    pub fn add_tx_undo(
        &mut self,
        tx_source: TransactionSource,
        tx_id: Id<Transaction>,
        tx_undo: UtxosTxUndoWithSources,
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
                        CachedUtxosBlockUndo::new(None, BTreeMap::from_iter([(tx_id, tx_undo)]))?;
                    entry.insert(CachedOperation::Write(block_undo));
                }
            },
            Entry::Vacant(entry) => {
                let block_undo =
                    CachedUtxosBlockUndo::new(None, BTreeMap::from_iter([(tx_id, tx_undo)]))?;
                entry.insert(CachedOperation::Write(block_undo));
            }
        };

        Ok(())
    }

    pub fn add_reward_undo(
        &mut self,
        tx_source: TransactionSource,
        reward_undo: UtxosBlockRewardUndo,
    ) -> Result<(), ConnectTransactionError> {
        match self.data.entry(tx_source) {
            Entry::Occupied(mut entry) => match entry.get() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => {
                    let mut block_undo = undo.clone();
                    block_undo.set_block_reward_undo(reward_undo);
                    entry.insert(CachedOperation::Write(block_undo));
                }
                CachedOperation::Erase => {
                    let block_undo = CachedUtxosBlockUndo::new(Some(reward_undo), BTreeMap::new())?;
                    entry.insert(CachedOperation::Write(block_undo));
                }
            },
            Entry::Vacant(entry) => {
                let block_undo = CachedUtxosBlockUndo::new(Some(reward_undo), BTreeMap::new())?;
                entry.insert(CachedOperation::Write(block_undo));
            }
        };

        Ok(())
    }

    pub fn take_tx_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
        fetcher_func: F,
    ) -> Result<UtxosTxUndo, ConnectTransactionError>
    where
        F: Fn(TransactionSource) -> Result<Option<CachedUtxosBlockUndo>, E>,
        ConnectTransactionError: From<E>,
    {
        let mut block_undo = match self.data.entry(*tx_source) {
            Entry::Vacant(_) => fetcher_func(*tx_source)?
                .ok_or(ConnectTransactionError::MissingBlockUndo(*tx_source))?,
            Entry::Occupied(entry) => match entry.get() {
                CachedOperation::Write(undo) | CachedOperation::Read(undo) => undo.clone(),
                CachedOperation::Erase => panic!("already empty"),
            },
        };

        let res = block_undo
            .take_tx_undo(tx_id)?
            .ok_or(ConnectTransactionError::MissingTxUndo(*tx_id))?;

        // if block undo used up completely then remove it from the db
        if block_undo.is_empty() {
            self.data.insert(*tx_source, CachedOperation::Erase);
        } else {
            self.data.insert(*tx_source, CachedOperation::Write(block_undo));
        }

        Ok(res)
    }

    pub fn take_block_reward_undo<F, E>(
        &mut self,
        tx_source: &TransactionSource,
        fetcher_func: F,
    ) -> Result<Option<UtxosBlockRewardUndo>, ConnectTransactionError>
    where
        F: Fn(TransactionSource) -> Result<Option<CachedUtxosBlockUndo>, E>,
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

    pub fn set_undo_data(
        &mut self,
        tx_source: TransactionSource,
        new_undo: &CachedUtxosBlockUndo,
    ) -> Result<(), utxo::UtxosBlockUndoError> {
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

    pub fn del_undo_data(
        &mut self,
        tx_source: TransactionSource,
    ) -> Result<(), utxo::UtxosBlockUndoError> {
        self.data.insert(tx_source, CachedOperation::Erase);
        Ok(())
    }
}