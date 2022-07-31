use common::{
    chain::{Block, GenBlock, OutPoint},
    primitives::Id,
};

use crate::{BlockUndo, Utxo};

use super::{UtxosDB, UtxosDBMut, UtxosStorageRead, UtxosStorageWrite};

use chainstate_types::storage_result::Error as StorageError;

impl<'a, S: UtxosStorageRead> UtxosStorageRead for UtxosDBMut<'a, S> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, StorageError> {
        self.0.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, StorageError> {
        self.0.get_best_block_for_utxos()
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, StorageError> {
        self.0.get_undo_data(id)
    }
}

impl<'a, S: UtxosStorageWrite> UtxosStorageWrite for UtxosDBMut<'a, S> {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), StorageError> {
        self.0.set_utxo(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), StorageError> {
        self.0.del_utxo(outpoint)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), StorageError> {
        self.0.set_best_block_for_utxos(block_id)
    }
    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), StorageError> {
        self.0.set_undo_data(id, undo)
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), StorageError> {
        self.0.del_undo_data(id)
    }
}

impl<'a, S: UtxosStorageRead> UtxosStorageRead for UtxosDB<'a, S> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, StorageError> {
        self.0.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, StorageError> {
        self.0.get_best_block_for_utxos()
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, StorageError> {
        self.0.get_undo_data(id)
    }
}
