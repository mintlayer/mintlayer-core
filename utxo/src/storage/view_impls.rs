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

use super::{UtxosDB, UtxosDBMut, UtxosStorageRead, UtxosStorageWrite};
use crate::{ConsumedUtxoCache, FlushableUtxoView, Utxo, UtxosView};
use common::{
    chain::{GenBlock, OutPoint},
    primitives::Id,
};

mod utxosdb_utxosview_impls {
    use super::*;

    pub fn utxo<S: UtxosStorageRead>(db: &S, outpoint: &OutPoint) -> Option<Utxo> {
        db.get_utxo(outpoint).unwrap_or_else(|e| {
            panic!(
                "Database error while attempting to retrieve utxo from the database: {}",
                e
            )
        })
    }

    pub fn has_utxo<S: UtxosStorageRead>(db: &S, outpoint: &OutPoint) -> bool {
        utxo(db, outpoint).is_some()
    }

    pub fn best_block_hash<S: UtxosStorageRead>(db: &S) -> Id<GenBlock> {
        db.get_best_block_for_utxos().unwrap_or_else(|e| panic!("Database error while attempting to retrieve utxo set best block hash from the database: {}",
        e)).expect("Failed to get best block hash")
    }

    pub fn estimated_size<S: UtxosStorageRead>(_db: &S) -> Option<usize> {
        None
    }
}

impl<S: UtxosStorageRead> UtxosView for UtxosDB<S> {
    fn utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        utxosdb_utxosview_impls::utxo(self, outpoint)
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        utxosdb_utxosview_impls::has_utxo(self, outpoint)
    }

    fn best_block_hash(&self) -> Id<GenBlock> {
        utxosdb_utxosview_impls::best_block_hash(self)
    }

    fn estimated_size(&self) -> Option<usize> {
        utxosdb_utxosview_impls::estimated_size(self)
    }
}

impl<S: UtxosStorageWrite> UtxosView for UtxosDBMut<S> {
    fn utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        utxosdb_utxosview_impls::utxo(self, outpoint)
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        utxosdb_utxosview_impls::has_utxo(self, outpoint)
    }

    fn best_block_hash(&self) -> Id<GenBlock> {
        utxosdb_utxosview_impls::best_block_hash(self)
    }

    fn estimated_size(&self) -> Option<usize> {
        utxosdb_utxosview_impls::estimated_size(self)
    }
}

impl<S: UtxosStorageWrite> FlushableUtxoView for UtxosDBMut<S> {
    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), crate::Error> {
        // check each entry if it's dirty. Only then will the db be updated.
        for (key, entry) in utxos.container {
            let outpoint = &key;
            if entry.is_dirty() {
                if let Some(utxo) = entry.utxo() {
                    self.0.set_utxo(outpoint, utxo.clone())?;
                } else {
                    // entry is spent
                    self.0.del_utxo(outpoint)?;
                };
            }
        }
        self.0.set_best_block_for_utxos(&utxos.best_block)?;
        Ok(())
    }
}
