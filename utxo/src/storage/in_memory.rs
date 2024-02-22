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
use crate::{Utxo, UtxosView};
use chainstate_types::storage_result::{self, Error};
use common::{
    chain::{GenBlock, UtxoOutPoint},
    primitives::Id,
};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct UtxosDBInMemoryImpl {
    store: BTreeMap<UtxoOutPoint, Utxo>,
    best_block_id: Id<GenBlock>,
}

impl UtxosDBInMemoryImpl {
    pub fn new(best_block: Id<GenBlock>, initial_utxos: BTreeMap<UtxoOutPoint, Utxo>) -> Self {
        Self {
            store: initial_utxos,
            best_block_id: best_block,
        }
    }
}

impl UtxosStorageRead for UtxosDBInMemoryImpl {
    type Error = storage_result::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Error> {
        let res = self.store.get(outpoint);
        Ok(res.cloned())
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Error> {
        Ok(self.best_block_id)
    }
}

impl UtxosStorageWrite for UtxosDBInMemoryImpl {
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> Result<(), Error> {
        self.store.insert(outpoint.clone(), entry);
        Ok(())
    }
    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<(), Error> {
        self.store.remove(outpoint);
        Ok(())
    }
    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Error> {
        self.best_block_id = *block_id;
        Ok(())
    }
}

impl UtxosView for UtxosDBInMemoryImpl {
    type Error = std::convert::Infallible;

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        Ok(self.store.get(outpoint).cloned())
    }

    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Self::Error> {
        Ok(self.store.get(outpoint).is_some())
    }

    fn best_block_hash(&self) -> Result<Id<GenBlock>, Self::Error> {
        Ok(self.best_block_id)
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}
