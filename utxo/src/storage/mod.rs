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

pub mod in_memory;

mod rw_impls;
mod view_impls;

use crate::{FlushableUtxoView, Utxo, UtxosBlockUndo, UtxosCache};
use common::{
    chain::{Block, ChainConfig, GenBlock, UtxoOutPoint},
    primitives::{BlockHeight, Id},
};
use std::ops::{Deref, DerefMut};

pub trait UtxosStorageRead {
    type Error: std::error::Error;
    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error>;
    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Self::Error>;
    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<UtxosBlockUndo>, Self::Error>;
}

pub trait UtxosStorageWrite: UtxosStorageRead {
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> Result<(), Self::Error>;
    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<(), Self::Error>;

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Self::Error>;

    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> Result<(), Self::Error>;
    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Self::Error>;
}

#[must_use]
pub struct UtxosDB<S>(S);

impl<S: UtxosStorageRead> UtxosDB<S> {
    pub fn new(store: S) -> Self {
        Self(store)
    }
}

impl<S: UtxosStorageWrite> UtxosDB<S> {
    pub fn initialize_db(store: S, chain_config: &ChainConfig) {
        let genesis = chain_config.genesis_block();
        let genesis_id = chain_config.genesis_block_id();

        let mut utxos_db = Self(store);

        // before deriving cache, there has to be a best block
        utxos_db.set_best_block_for_utxos(&genesis_id).expect("Setting genesis failed");

        let mut utxos_cache = UtxosCache::new(&utxos_db).expect("Utxo cache setup failed");

        for (index, output) in genesis.utxos().iter().enumerate() {
            utxos_cache
                .add_utxo(
                    &UtxoOutPoint::new(genesis_id.into(), index as u32),
                    Utxo::new_for_blockchain(output.clone(), BlockHeight::new(0)),
                    false,
                )
                .expect("Adding genesis utxo failed");
        }

        let consumed_utxos_cache = utxos_cache.consume();

        utxos_db.batch_write(consumed_utxos_cache).expect("Writing genesis utxos failed");
    }
}

impl<T> UtxosStorageRead for T
where
    T: Deref,
    <T as Deref>::Target: UtxosStorageRead,
{
    type Error = <T::Target as UtxosStorageRead>::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        self.deref().get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.deref().get_best_block_for_utxos()
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<UtxosBlockUndo>, Self::Error> {
        self.deref().get_undo_data(id)
    }
}

impl<T> UtxosStorageWrite for T
where
    T: DerefMut,
    <T as Deref>::Target: UtxosStorageWrite,
{
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> Result<(), Self::Error> {
        self.deref_mut().set_utxo(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<(), Self::Error> {
        self.deref_mut().del_utxo(outpoint)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Self::Error> {
        self.deref_mut().set_best_block_for_utxos(block_id)
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &UtxosBlockUndo) -> Result<(), Self::Error> {
        self.deref_mut().set_undo_data(id, undo)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Self::Error> {
        self.deref_mut().del_undo_data(id)
    }
}

#[cfg(test)]
mod test;
