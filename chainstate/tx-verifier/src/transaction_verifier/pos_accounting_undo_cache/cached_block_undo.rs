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
use pos_accounting::{BlockRewardUndo, BlockUndo, BlockUndoError, TxUndo};

use crate::transaction_verifier::{cached_operation::combine, CachedOperation};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CachedPoSBlockUndo {
    reward_undos: Option<CachedOperation<BlockRewardUndo>>,
    tx_undos: BTreeMap<Id<Transaction>, CachedOperation<TxUndo>>,
}

impl CachedPoSBlockUndo {
    pub fn new(
        reward_undo: Option<BlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, TxUndo>,
    ) -> Result<Self, BlockUndoError> {
        let mut block_undo = Self::default();

        if let Some(reward_undo) = reward_undo {
            block_undo.set_block_reward_undo(reward_undo);
        }

        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn from_block_undo(undo: BlockUndo) -> Self {
        let (reward_undos, tx_undos) = undo.consume();

        let reward_undos = reward_undos.map(CachedOperation::Read);

        let tx_undos = tx_undos
            .into_iter()
            .map(|(id, undo)| (id, CachedOperation::Read(undo)))
            .collect::<BTreeMap<_, _>>();

        Self {
            reward_undos,
            tx_undos,
        }
    }

    /// Consume the data from the struct and move it into a type that is suitable fot storing in the db
    pub fn consume(self) -> BlockUndo {
        let reward_undo = self.reward_undos.and_then(|op| op.get().cloned());

        let tx_undos = self
            .tx_undos
            .into_iter()
            .filter_map(|(id, op)| op.get().map(|u| (id, u.clone())))
            .collect::<BTreeMap<_, _>>();

        BlockUndo::new(reward_undo, tx_undos)
    }

    /// Indicates whether reward and all transactions were used while disconnecting leaving this object empty
    pub(super) fn is_empty(&self) -> bool {
        !self.reward_undos.as_ref().is_some_and(|u| u.get().is_some())
            && self.tx_undos.iter().all(|(_, op)| op.get().is_none())
    }

    pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, CachedOperation<TxUndo>> {
        &self.tx_undos
    }

    /// Take reward undo object out if available
    pub(super) fn take_block_reward_undo(&mut self) -> Option<BlockRewardUndo> {
        self.reward_undos.take().and_then(|op| op.take())
    }

    /// Set undo for reward
    pub(super) fn set_block_reward_undo(&mut self, reward_undo: BlockRewardUndo) {
        debug_assert!(self.reward_undos.is_none());
        self.reward_undos = Some(CachedOperation::Write(reward_undo));
    }

    /// Insert new undo for transaction
    pub(super) fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: TxUndo,
    ) -> Result<(), BlockUndoError> {
        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => {
                e.insert(CachedOperation::Write(tx_undo));
                Ok(())
            }
            Entry::Occupied(_) => Err(BlockUndoError::UndoAlreadyExists(tx_id)),
        }
    }

    /// Take tx undo object out if available
    pub(super) fn take_tx_undo(
        &mut self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<TxUndo>, BlockUndoError> {
        if let Some(tx_undo) = self.tx_undos.get_mut(tx_id) {
            let result = tx_undo.clone().take().ok_or(BlockUndoError::MissingTxUndo(*tx_id))?;
            *tx_undo = CachedOperation::<TxUndo>::Erase;
            return Ok(Some(result));
        }

        Ok(None)
    }

    /// Combine two objects into one.
    /// All operations inside are made in terms of flushing data in transaction verifier hierarchy.
    pub(super) fn combine(&mut self, other: Self) -> Result<(), BlockUndoError> {
        // combine reward
        match (&mut self.reward_undos, other.reward_undos) {
            (None | Some(_), None) => { /* do nothing */ }
            (None, Some(reward_undos)) => {
                self.reward_undos = Some(reward_undos);
            }
            (Some(left), Some(right)) => {
                utils::ensure!(*left == right, BlockUndoError::UndoAlreadyExistsForReward);
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
