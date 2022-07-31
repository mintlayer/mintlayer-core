use std::collections::{BTreeMap, HashMap};

use super::{UtxosStorageRead, UtxosStorageWrite};
use crate::{BlockUndo, Utxo};
use chainstate_types::storage_result::Error;
use common::{
    chain::{Block, GenBlock, OutPoint},
    primitives::{Id, H256},
};

#[derive(Clone)]
pub struct UtxosDBInMemoryImpl {
    store: BTreeMap<OutPoint, Utxo>,
    undo_store: HashMap<H256, BlockUndo>,
    best_block_id: Option<Id<GenBlock>>,
}

impl UtxosDBInMemoryImpl {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            undo_store: HashMap::new(),
            best_block_id: None,
        }
    }

    pub(crate) fn internal_store(&mut self) -> &BTreeMap<OutPoint, Utxo> {
        &self.store
    }
}

impl UtxosStorageRead for UtxosDBInMemoryImpl {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, Error> {
        let res = self.store.get(outpoint);
        Ok(res.cloned())
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, Error> {
        let res = self.undo_store.get(&id.get());
        Ok(res.cloned())
    }

    fn get_best_block_for_utxos(&self) -> Result<Option<Id<GenBlock>>, Error> {
        Ok(self.best_block_id)
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
        self.best_block_id = Some(*block_id);
        Ok(())
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), Error> {
        self.undo_store.insert(id.get(), undo.clone());
        Ok(())
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Error> {
        self.undo_store.remove(&id.get());
        Ok(())
    }
}
