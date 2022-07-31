// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(dead_code, unused_variables, unused_imports)]
// todo: remove ^ when all untested codes are tested

mod rw_impls;
mod view_impls;

use std::collections::{BTreeMap, HashMap};

use crate::utxo_impl::{FlushableUtxoView, Utxo, UtxosCache, UtxosView};
use crate::{BlockUndo, Error};
use chainstate_types::storage_result::Error as StorageError;
use common::chain::{Block, GenBlock, OutPoint};
use common::primitives::{Id, H256};

pub trait UtxosStorageRead {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, StorageError>;
    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, StorageError>;
    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, StorageError>;
}

pub trait UtxosStorageWrite: UtxosStorageRead {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), StorageError>;
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), StorageError>;

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), StorageError>;

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), StorageError>;
    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), StorageError>;
}

#[must_use]
pub struct UtxosDB<'a, S>(&'a S);

impl<'a, S> UtxosDB<'a, S> {
    pub fn new(store: &'a S) -> Self {
        Self(store)
    }
}

#[must_use]
pub struct UtxosDBMut<'a, S>(&'a mut S);

impl<'a, S> UtxosDBMut<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self(store)
    }
}

#[cfg(test)]
mod test;
