#![allow(dead_code)]

use crate::{Error, Store, UndoRead, UndoWrite, UtxoRead, UtxoWrite};
use common::chain::block::Block;
use common::chain::OutPoint;
use common::primitives::Id;
use utxo::{utxo_storage::UtxosPersistentStorage, BlockUndo, Utxo};

#[derive(Clone)]
pub struct UtxoDBInterface {
    store: Store,
}

impl UtxoDBInterface {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl UtxosPersistentStorage for UtxoDBInterface {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), utxo::Error> {
        self.store.add_utxo(outpoint, entry).map_err(|e| e.into())
    }
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), utxo::Error> {
        self.store.del_utxo(outpoint).map_err(|e| e.into())
    }
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, utxo::Error> {
        self.store.get_utxo(outpoint).map_err(|e| e.into())
    }
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), utxo::Error> {
        // TODO: fix; don't store in general block id
        self.store.set_best_block_for_utxos(block_id).map_err(|e| e.into())
    }
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, utxo::Error> {
        // TODO: fix; don't get general block id
        self.store.get_best_block_for_utxos().map_err(|e| e.into())
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), utxo::Error> {
        self.store.add_undo_data(id, undo).map_err(|e| e.into())
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), utxo::Error> {
        self.store.del_undo_data(id).map_err(|e| e.into())
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, utxo::Error> {
        self.store.get_undo_data(id).map_err(|e| e.into())
    }
}

impl From<Error> for utxo::Error {
    fn from(e: Error) -> Self {
        utxo::Error::DBError(format!("{:?}", e))
    }
}

// TODO: write basic tests for reads/writes in db for UtxoDBInterface
