// Copyright (c) 2024 RBB S.r.l
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

use common::{chain::Transaction, primitives::Id};
use pos_accounting::{
    AccountingBlockRewardUndo, AccountingBlockUndo, AccountingBlockUndoError, AccountingTxUndo,
};

use crate::transaction_verifier::{cached_operation::combine, CachedOperation};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CachedPoSBlockUndo {
    reward_undos: Option<CachedOperation<AccountingBlockRewardUndo>>,
    tx_undos: BTreeMap<Id<Transaction>, CachedOperation<AccountingTxUndo>>,
}

impl CachedPoSBlockUndo {
    pub fn new(
        reward_undo: Option<AccountingBlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, AccountingTxUndo>,
    ) -> Result<Self, AccountingBlockUndoError> {
        let mut block_undo = Self::default();

        if let Some(reward_undo) = reward_undo {
            block_undo.set_block_reward_undo(reward_undo);
        }

        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn from_block_undo(undo: AccountingBlockUndo) -> Self {
        let (reward_undos, tx_undos) = undo.consume();

        let reward_undos = reward_undos.map(|u| CachedOperation::Read(u));

        let tx_undos = tx_undos
            .into_iter()
            .map(|(id, undo)| (id, CachedOperation::Read(undo)))
            .collect::<BTreeMap<_, _>>();

        Self {
            reward_undos,
            tx_undos,
        }
    }

    pub fn consume(self) -> AccountingBlockUndo {
        let reward_undo = self.reward_undos.map(|op| op.get().cloned()).flatten();

        let tx_undos = self
            .tx_undos
            .into_iter()
            .filter_map(|(id, op)| op.get().map(|u| (id, u.clone())))
            .collect::<BTreeMap<_, _>>();

        AccountingBlockUndo::new(reward_undo, tx_undos)
    }

    pub fn is_empty(&self) -> bool {
        !self.reward_undos.as_ref().is_some_and(|u| u.get().is_some())
            && self.tx_undos.iter().all(|(_, op)| op.get().is_none())
    }

    pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, CachedOperation<AccountingTxUndo>> {
        &self.tx_undos
    }

    pub fn take_block_reward_undo(&mut self) -> Option<AccountingBlockRewardUndo> {
        self.reward_undos.take().map(|op| op.take()).flatten()
    }

    pub fn set_block_reward_undo(&mut self, reward_undo: AccountingBlockRewardUndo) {
        debug_assert!(self.reward_undos.is_none());
        self.reward_undos = Some(CachedOperation::Write(reward_undo));
    }

    pub fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: AccountingTxUndo,
    ) -> Result<(), AccountingBlockUndoError> {
        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => {
                e.insert(CachedOperation::Write(tx_undo));
                Ok(())
            }
            Entry::Occupied(_) => Err(AccountingBlockUndoError::UndoAlreadyExists(tx_id)),
        }
    }

    pub fn take_tx_undo(
        &mut self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<AccountingTxUndo>, AccountingBlockUndoError> {
        if let Some(tx_undo) = self.tx_undos.get_mut(tx_id) {
            let result =
                tx_undo.clone().take().ok_or(AccountingBlockUndoError::MissingTxUndo(*tx_id))?;
            *tx_undo = CachedOperation::<AccountingTxUndo>::Erase;
            return Ok(Some(result));
        }

        Ok(None)
    }

    pub fn combine(&mut self, other: Self) -> Result<(), AccountingBlockUndoError> {
        // combine reward
        match (&mut self.reward_undos, other.reward_undos) {
            (None, None) | (Some(_), None) => { /* do nothing */ }
            (None, Some(reward_undos)) => {
                self.reward_undos = Some(reward_undos);
            }
            (Some(left), Some(right)) => {
                utils::ensure!(
                    *left == right,
                    AccountingBlockUndoError::UndoAlreadyExistsForReward
                );
            }
        }

        other.tx_undos.into_iter().for_each(|(id, op)| {
            let result = combine(self.tx_undos.get(&id).cloned(), Some(op));
            if let Some(result) = result {
                self.tx_undos.insert(id, result);
            }
        });

        Ok(())
    }
}
