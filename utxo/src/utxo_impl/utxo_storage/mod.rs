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

pub mod in_memory;
mod rw_impls;
mod view_impls;

use std::collections::BTreeMap;

use crate::{BlockUndo, FlushableUtxoView, Utxo, UtxosView};
use chainstate_types::storage_result::Error;
use common::{
    chain::{Block, ChainConfig, GenBlock, OutPoint, TxOutput},
    primitives::{BlockHeight, Id},
};

pub trait UtxosStorageRead {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, Error>;
    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, Error>;
    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, Error>;
}

pub trait UtxosStorageWrite: UtxosStorageRead {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), Error>;
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), Error>;

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Error>;

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), Error>;
    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Error>;
}

#[must_use]
pub struct UtxosDB<'a, S>(&'a S);

impl<'a, S: UtxosStorageRead> UtxosDB<'a, S> {
    pub fn new(store: &'a S) -> Self {
        let utxos_db = Self(store);
        debug_assert!(
            utxos_db
                .get_best_block_for_utxos()
                .expect("Database error while reading utxos best block")
                .is_some(),
            "Attempted to load an uninitialized utxos db"
        );
        utxos_db
    }
}

#[must_use]
pub struct UtxosDBMut<'a, S>(&'a mut S);

impl<'a, S: UtxosStorageWrite> UtxosDBMut<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        let utxos_db = Self(store);
        debug_assert!(
            utxos_db
                .get_best_block_for_utxos()
                .expect("Database error while reading utxos best block")
                .is_some(),
            "Attempted to load an uninitialized utxos db"
        );
        utxos_db
    }

    pub fn initialize_db(store: &'a mut S, chain_config: &ChainConfig) {
        let genesis = chain_config.genesis_block();
        let genesis_id = chain_config.genesis_block_id();

        let mut utxos_db = Self(store);

        // before deriving cache, there has to be a best block
        utxos_db.set_best_block_for_utxos(&genesis_id).expect("Setting genesis failed");

        let mut utxos_cache = utxos_db.derive_cache();

        for (index, output) in genesis.utxos().iter().enumerate() {
            utxos_cache
                .add_utxo(
                    &OutPoint::new(genesis_id.into(), index as u32),
                    Utxo::new(output.clone(), false, BlockHeight::new(0)),
                    false,
                )
                .expect("Adding genesis utxo failed");
        }

        let consumed_utxos_cache = utxos_cache.consume();

        utxos_db
            .batch_write(consumed_utxos_cache)
            .expect("Writing genesis utxos failed");
    }
}

#[cfg(test)]
mod test;
