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

use super::{UtxosDB, UtxosStorageRead, UtxosStorageWrite};
use crate::{ConsumedUtxoCache, Error, FlushableUtxoView, Utxo, UtxosView};
use common::{
    chain::{GenBlock, UtxoOutPoint},
    primitives::Id,
};

impl<S: UtxosStorageRead> UtxosView for UtxosDB<S> {
    type Error = S::Error;

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        self.get_utxo(outpoint)
    }

    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Self::Error> {
        self.utxo(outpoint).map(|u| u.is_some())
    }

    fn best_block_hash(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.get_best_block_for_utxos()
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

impl<S: UtxosStorageWrite> FlushableUtxoView for UtxosDB<S> {
    type Error = Error;

    fn batch_write(&mut self, utxos: ConsumedUtxoCache) -> Result<(), Error> {
        // check each entry if it's dirty. Only then will the db be updated.
        for (key, entry) in utxos.container {
            let outpoint = &key;
            if entry.is_dirty() {
                if let Some(utxo) = entry.utxo() {
                    self.0.set_utxo(outpoint, utxo.clone()).map_err(|_| Error::StorageWrite)?;
                } else {
                    // entry is spent
                    self.0.del_utxo(outpoint).map_err(|_| Error::StorageWrite)?;
                };
            }
        }
        self.0
            .set_best_block_for_utxos(&utxos.best_block)
            .map_err(|_| Error::StorageWrite)?;
        Ok(())
    }
}
