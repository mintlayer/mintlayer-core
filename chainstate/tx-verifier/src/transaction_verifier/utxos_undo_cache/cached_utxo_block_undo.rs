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

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use crate::transaction_verifier::{cached_operation::combine, CachedOperation};
use common::{
    chain::{OutPointSourceId, Transaction},
    primitives::Id,
};
use utxo::{
    ConsumedUtxosBlockUndo, UtxosBlockRewardUndo, UtxosBlockUndo, UtxosBlockUndoError, UtxosTxUndo,
    UtxosTxUndoWithSources,
};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CachedUtxosBlockUndo {
    reward_undo: Option<CachedOperation<UtxosBlockRewardUndo>>,
    tx_undos: BTreeMap<Id<Transaction>, CachedOperation<UtxosTxUndo>>,

    // These collections track the dependencies of tx to one another.
    // Only txs that aren't a dependency for others can be taken out.
    // Collections are a mirrored representation of one another. 2 instances are maintained
    // in order to gain log(N) runtime complexity.
    child_parent_dependencies: BTreeMap<(Id<Transaction>, Id<Transaction>), CachedOperation<()>>,
    parent_child_dependencies: BTreeMap<(Id<Transaction>, Id<Transaction>), CachedOperation<()>>,
}

impl CachedUtxosBlockUndo {
    pub fn new(
        reward_undo: Option<UtxosBlockRewardUndo>,
        tx_undos: BTreeMap<Id<Transaction>, UtxosTxUndoWithSources>,
    ) -> Result<Self, UtxosBlockUndoError> {
        let mut block_undo = CachedUtxosBlockUndo::default();

        if let Some(reward_undo) = reward_undo {
            block_undo.set_block_reward_undo(reward_undo)?;
        }

        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn from_utxo_block_undo(undo: UtxosBlockUndo) -> Self {
        let ConsumedUtxosBlockUndo {
            reward_undo,
            tx_undos,
            child_parent_dependencies,
            parent_child_dependencies,
        } = undo.consume();

        let reward_undo = reward_undo.map(CachedOperation::Read);

        let tx_undos = tx_undos
            .into_iter()
            .map(|(id, undo)| (id, CachedOperation::Read(undo)))
            .collect::<BTreeMap<_, _>>();

        let child_parent_dependencies = child_parent_dependencies
            .into_iter()
            .map(|(child, parent)| ((child, parent), CachedOperation::Read(())))
            .collect::<BTreeMap<_, _>>();

        let parent_child_dependencies = parent_child_dependencies
            .into_iter()
            .map(|(parent, child)| ((parent, child), CachedOperation::Read(())))
            .collect::<BTreeMap<_, _>>();

        Self {
            reward_undo,
            tx_undos,
            child_parent_dependencies,
            parent_child_dependencies,
        }
    }

    /// Consume the data from the struct and move it into a type that is suitable fot storing in the db
    pub fn consume(self) -> UtxosBlockUndo {
        let reward_undo = self.reward_undo.and_then(|op| op.get().cloned());

        let tx_undos = self
            .tx_undos
            .into_iter()
            .filter_map(|(id, op)| op.get().map(|u| (id, u.clone())))
            .collect::<BTreeMap<_, _>>();

        let child_parent_dependencies = self
            .child_parent_dependencies
            .into_iter()
            .filter_map(|(id, op)| op.get().map(|_| id))
            .collect::<BTreeSet<_>>();

        let parent_child_dependencies = self
            .parent_child_dependencies
            .into_iter()
            .filter_map(|(id, op)| op.get().map(|_| id))
            .collect::<BTreeSet<_>>();

        UtxosBlockUndo::from_data(
            reward_undo,
            tx_undos,
            child_parent_dependencies,
            parent_child_dependencies,
        )
    }

    /// Indicates whether reward and all transactions were used while disconnecting leaving this object empty
    pub(super) fn is_empty(&self) -> bool {
        !self.reward_undo.as_ref().is_some_and(|u| u.get().is_some())
            && self.tx_undos.iter().all(|(_, op)| op.get().is_none())
    }

    /// Insert new undo for transaction
    pub(super) fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: UtxosTxUndoWithSources,
    ) -> Result<(), UtxosBlockUndoError> {
        let (utxos, sources) = tx_undo.consume();

        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => e.insert(CachedOperation::Write(utxos)),
            Entry::Occupied(_) => return Err(UtxosBlockUndoError::UndoAlreadyExists(tx_id)),
        };

        sources
            .into_iter()
            .filter_map(|source_id| match source_id {
                OutPointSourceId::Transaction(id) => Some(id),
                OutPointSourceId::BlockReward(_) => None,
            })
            .for_each(|source_tx_id| {
                self.child_parent_dependencies
                    .insert((tx_id, source_tx_id), CachedOperation::Write(()));
                self.parent_child_dependencies
                    .insert((source_tx_id, tx_id), CachedOperation::Write(()));
            });

        Ok(())
    }

    /// Check if a tx is a dependency for other txs.
    pub(super) fn has_children_of(&self, tx_id: &Id<Transaction>) -> bool {
        self.parent_child_dependencies
            .iter()
            .filter(|((id, _), _)| id == tx_id)
            .any(|(_, op)| op.get().is_some())
    }

    fn get_parents_of(&self, tx_id: &Id<Transaction>) -> Vec<(Id<Transaction>, Id<Transaction>)> {
        self.child_parent_dependencies
            .iter()
            .filter(|((child, _), _)| child == tx_id)
            .filter_map(|((child, parent), op)| op.get().map(|_| (*child, *parent)))
            .collect()
    }

    /// Take reward undo object out if available
    pub(super) fn take_block_reward_undo(&mut self) -> Option<UtxosBlockRewardUndo> {
        self.reward_undo.take().and_then(|op| op.take())
    }

    /// Take tx undo object out if available
    pub(super) fn take_tx_undo(
        &mut self,
        tx_id: &Id<Transaction>,
    ) -> Result<Option<UtxosTxUndo>, UtxosBlockUndoError> {
        if !self.has_children_of(tx_id) {
            // If not this tx can be taken and returned.
            // But first, remove itself as a dependency of others.
            let to_remove = self.get_parents_of(tx_id);

            to_remove.iter().for_each(|(id1, id2)| {
                self.child_parent_dependencies.insert((*id1, *id2), CachedOperation::Erase);
                self.parent_child_dependencies.insert((*id2, *id1), CachedOperation::Erase);
            });

            let res = self.tx_undos.insert(*tx_id, CachedOperation::Erase).and_then(|op| op.take());
            Ok(res)
        } else {
            Err(UtxosBlockUndoError::TxUndoWithDependency(*tx_id))
        }
    }

    /// Set undo for reward
    pub(super) fn set_block_reward_undo(
        &mut self,
        reward_undo: UtxosBlockRewardUndo,
    ) -> Result<(), UtxosBlockUndoError> {
        utils::ensure!(
            self.reward_undo.is_none(),
            UtxosBlockUndoError::UndoAlreadyExistsForReward
        );
        self.reward_undo = Some(CachedOperation::Write(reward_undo));
        Ok(())
    }

    /// Combine two objects into one.
    /// All operations inside are made in terms of flushing data in transaction verifier hierarchy.
    pub(super) fn combine(&mut self, other: Self) -> Result<(), UtxosBlockUndoError> {
        // combine reward
        match (&mut self.reward_undo, other.reward_undo) {
            (None | Some(_), None) => { /* do nothing */ }
            (None, Some(reward_undo)) => {
                self.reward_undo = Some(reward_undo);
            }
            (Some(left), Some(right)) => {
                utils::ensure!(
                    *left == right,
                    UtxosBlockUndoError::UndoAlreadyExistsForReward
                );
            }
        }

        // combine utxos
        other.tx_undos.into_iter().for_each(|(id, op)| {
            let result = combine(self.tx_undos.get(&id).cloned(), Some(op));
            if let Some(result) = result {
                self.tx_undos.insert(id, result);
            }
        });

        // combine dependencies
        other.child_parent_dependencies.into_iter().for_each(|(k, op)| {
            let result = combine(self.child_parent_dependencies.get(&k).cloned(), Some(op));
            if let Some(result) = result {
                self.child_parent_dependencies.insert(k, result);
            }
        });
        other.parent_child_dependencies.into_iter().for_each(|(k, op)| {
            let result = combine(self.parent_child_dependencies.get(&k).cloned(), Some(op));
            if let Some(result) = result {
                self.parent_child_dependencies.insert(k, result);
            }
        });

        Ok(())
    }
}
