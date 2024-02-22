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
use tokens_accounting::{BlockUndo, BlockUndoError, TxUndo};

use crate::transaction_verifier::{cached_operation::combine, CachedOperation};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CachedTokensBlockUndo {
    tx_undos: BTreeMap<Id<Transaction>, CachedOperation<TxUndo>>,
}

impl CachedTokensBlockUndo {
    pub fn new(tx_undos: BTreeMap<Id<Transaction>, TxUndo>) -> Result<Self, BlockUndoError> {
        let mut block_undo = Self::default();
        tx_undos
            .into_iter()
            .try_for_each(|(tx_id, tx_undo)| block_undo.insert_tx_undo(tx_id, tx_undo))?;
        Ok(block_undo)
    }

    pub fn from_block_undo(undo: BlockUndo) -> Self {
        let tx_undos = undo
            .consume()
            .into_iter()
            .map(|(id, undo)| (id, CachedOperation::Read(undo)))
            .collect::<BTreeMap<_, _>>();

        Self { tx_undos }
    }

    /// Consume the data from the struct and move it into a type that is suitable fot storing in the db
    pub fn consume(self) -> BlockUndo {
        let tx_undos = self
            .tx_undos
            .into_iter()
            .filter_map(|(id, op)| op.get().map(|u| (id, u.clone())))
            .collect::<BTreeMap<_, _>>();

        BlockUndo::new(tx_undos)
    }

    /// Indicates whether reward and all transactions were used while disconnecting leaving this object empty
    pub(super) fn is_empty(&self) -> bool {
        self.tx_undos.iter().all(|(_, op)| op.get().is_none())
    }

    pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, CachedOperation<TxUndo>> {
        &self.tx_undos
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
        other.tx_undos.into_iter().for_each(|(id, op)| {
            let result = combine(self.tx_undos.get(&id).cloned(), Some(op));
            if let Some(result) = result {
                self.tx_undos.insert(id, result);
            }
        });

        Ok(())
    }
}
