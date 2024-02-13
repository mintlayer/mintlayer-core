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

use crate::transaction_verifier::CachedOperation;
use common::{
    chain::{OutPointSourceId, Transaction},
    primitives::Id,
};
use utxo::{
    UtxosBlockRewardUndo, UtxosBlockUndo, UtxosBlockUndoError, UtxosTxUndo, UtxosTxUndoWithSources,
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
            block_undo.set_block_reward_undo(reward_undo);
        }

        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn from_utxo_block_undo(undo: UtxosBlockUndo) -> Self {
        let (reward_undo, tx_undos, child_parent_dependencies, parent_child_dependencies) =
            undo.consume();

        let reward_undo = reward_undo.map(|u| CachedOperation::Read(u));

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

    pub fn consume(self) -> UtxosBlockUndo {
        let reward_undo = self.reward_undo.map(|op| op.get().cloned()).flatten();

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

    pub fn is_empty(&self) -> bool {
        !self.reward_undo.as_ref().is_some_and(|u| u.get().is_some())
            && self.tx_undos.iter().all(|(_, op)| op.get().is_none())
    }

    pub fn insert_tx_undo(
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

    pub fn has_children_of(&self, tx_id: &Id<Transaction>) -> bool {
        // Check if the tx is a dependency for other txs.
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

    pub fn take_block_reward_undo(&mut self) -> Option<UtxosBlockRewardUndo> {
        self.reward_undo.take().map(|op| op.take()).flatten()
    }

    pub fn take_tx_undo(
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

            let res = self
                .tx_undos
                .insert(*tx_id, CachedOperation::Erase)
                .map(|op| op.take())
                .flatten();
            Ok(res)
        } else {
            Err(UtxosBlockUndoError::TxUndoWithDependency(*tx_id))
        }
    }

    pub fn set_block_reward_undo(&mut self, reward_undo: UtxosBlockRewardUndo) {
        debug_assert!(self.reward_undo.is_none());
        self.reward_undo = Some(CachedOperation::Write(reward_undo));
    }

    pub fn combine(&mut self, other: Self) -> Result<(), UtxosBlockUndoError> {
        // combine reward
        match (&mut self.reward_undo, other.reward_undo) {
            (None, None) | (Some(_), None) => { /* do nothing */ }
            (None, Some(reward_undo)) => {
                self.reward_undo = Some(reward_undo);
            }
            (Some(_), Some(_)) => return Err(UtxosBlockUndoError::UndoAlreadyExistsForReward),
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

fn combine<T>(
    left: Option<CachedOperation<T>>,
    right: Option<CachedOperation<T>>,
) -> Option<CachedOperation<T>> {
    match (left, right) {
        (None, None) => None,
        (None, Some(v)) | (Some(v), None) => Some(v),
        (Some(left), Some(right)) => {
            let result = match (left, right) {
                (CachedOperation::Write(_), CachedOperation::Write(other)) => {
                    CachedOperation::Write(other)
                }
                (CachedOperation::Write(_), CachedOperation::Read(_)) => panic!("invariant"),
                (CachedOperation::Write(_), CachedOperation::Erase) => CachedOperation::Erase,
                (CachedOperation::Read(_), CachedOperation::Write(other)) => {
                    CachedOperation::Write(other)
                }
                (CachedOperation::Read(_), CachedOperation::Read(other)) => {
                    CachedOperation::Read(other)
                }
                (CachedOperation::Read(_), CachedOperation::Erase) => CachedOperation::Erase,
                (CachedOperation::Erase, CachedOperation::Write(other)) => {
                    // it is possible in mempool to disconnect a tx and connect it again,
                    // e.g. if memory limit was raised
                    CachedOperation::Write(other)
                }
                (CachedOperation::Erase, CachedOperation::Read(_)) => panic!("invariant"),
                (CachedOperation::Erase, CachedOperation::Erase) => CachedOperation::Erase,
            };
            Some(result)
        }
    }
}
