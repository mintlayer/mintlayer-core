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

use crate::PoSAccountingUndo;

use common::{chain::Transaction, primitives::Id};
use serialization::{Decode, Encode};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockUndoError {
    #[error("Attempted to insert a transaction in undo that already exists: `{0}`")]
    UndoAlreadyExists(Id<Transaction>),
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct TxUndo(Vec<PoSAccountingUndo>);

impl TxUndo {
    pub fn new(undos: Vec<PoSAccountingUndo>) -> Self {
        Self(undos)
    }

    pub fn inner(&self) -> &[PoSAccountingUndo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<PoSAccountingUndo> {
        self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo {
    tx_undos: BTreeMap<Id<Transaction>, TxUndo>,
}

impl BlockUndo {
    pub fn new(tx_undos: BTreeMap<Id<Transaction>, TxUndo>) -> Self {
        Self { tx_undos }
    }

    pub fn is_empty(&self) -> bool {
        self.tx_undos.is_empty()
    }

    pub fn tx_undos(&self) -> &BTreeMap<Id<Transaction>, TxUndo> {
        &self.tx_undos
    }

    pub fn insert_tx_undo(
        &mut self,
        tx_id: Id<Transaction>,
        tx_undo: TxUndo,
    ) -> Result<(), BlockUndoError> {
        match self.tx_undos.entry(tx_id) {
            Entry::Vacant(e) => {
                e.insert(tx_undo);
                Ok(())
            }
            Entry::Occupied(_) => Err(BlockUndoError::UndoAlreadyExists(tx_id)),
        }
    }

    pub fn take_tx_undo(&mut self, tx_id: &Id<Transaction>) -> Option<TxUndo> {
        self.tx_undos.remove(tx_id)
    }

    pub fn combine(&mut self, other: BlockUndo) -> Result<(), BlockUndoError> {
        other
            .tx_undos
            .into_iter()
            .try_for_each(|(id, u)| match self.tx_undos.entry(id) {
                Entry::Vacant(e) => {
                    e.insert(u);
                    Ok(())
                }
                Entry::Occupied(_) => Err(BlockUndoError::UndoAlreadyExists(id)),
            })
    }
}
