// Copyright (c) 2021-2022 RBB S.r.l
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

use super::{UtxosStorageRead, UtxosStorageWrite};
use crate::{Utxo, UtxosBlockUndo, UtxosView};
use chainstate_types::storage_result::Error;
use common::{
    chain::{Block, GenBlock, OutPoint},
    primitives::Id,
};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct UtxosDBInMemoryImpl {
    store: BTreeMap<OutPoint, Utxo>,
    undo_store: BTreeMap<Id<Block>, UtxosBlockUndo>,
    best_block_id: Id<GenBlock>,
}

impl UtxosDBInMemoryImpl {
    pub fn new(best_block: Id<GenBlock>, initial_utxos: BTreeMap<OutPoint, Utxo>) -> Self {
        Self {
            store: initial_utxos,
            undo_store: BTreeMap::new(),
            best_block_id: best_block,
        }
    }
}

impl UtxosStorageRead for UtxosDBInMemoryImpl {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, Error> {
        let res = self.store.get(outpoint);
        Ok(res.cloned())
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<UtxosBlockUndo>, Error> {
        let res = self.undo_store.get(&id);
        Ok(res.cloned())
    }

    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, Error> {
        Ok(Some(self.best_block_id))
    }
}

impl UtxosStorageWrite for UtxosDBInMemoryImpl {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), Error> {
        self.store.insert(outpoint.clone(), entry);
        Ok(())
    }
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), Error> {
        self.store.remove(outpoint);
        Ok(())
    }
    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Error> {
        self.best_block_id = *block_id;
        Ok(())
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> Result<(), Error> {
        self.undo_store.insert(id, undo.clone());
        Ok(())
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Error> {
        self.undo_store.remove(&id);
        Ok(())
    }
}

impl UtxosView for UtxosDBInMemoryImpl {
    fn utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        self.store.get(outpoint).cloned()
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.store.get(outpoint).is_some()
    }

    fn best_block_hash(&self) -> Id<GenBlock> {
        self.best_block_id
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}
