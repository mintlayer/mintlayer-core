#![allow(dead_code, unused_variables, unused_imports)]
// todo: remove ^ when all untested codes are tested

use std::collections::{BTreeMap, HashMap};

use crate::utxo_impl::{FlushableUtxoView, Utxo, UtxosCache, UtxosView};
use common::chain::block::Block;
use common::chain::OutPoint;
use common::primitives::{H256, Id};
use crate::{BlockUndo, Error};

pub trait UtxosPersistentStorage {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), crate::Error>;
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), crate::Error>;
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, crate::Error>;
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), crate::Error>;
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, crate::Error>;

    fn set_undo_data(&mut self, id:Id<Block>, undo:&BlockUndo)-> Result<(), crate::Error>;
    fn del_undo_data(&mut self, id:Id<Block>) -> Result<(), crate::Error>;
    fn get_undo_data(&self, id:Id<Block>) -> Result<Option<BlockUndo>, crate::Error>;
}

pub struct UtxoDB<'a, S: UtxosPersistentStorage>(&'a mut S);

impl<'a, S: UtxosPersistentStorage> UtxoDB<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self(store)
    }

    pub fn set_undo_data(&mut self, id:Id<Block>, undo:&BlockUndo) -> Result<(), crate::Error> {
        self.0.set_undo_data(id,undo)
    }

    pub fn del_undo_data(&mut self, id:Id<Block> )-> Result<(), crate::Error> {
        self.0.del_undo_data(id)
    }

    pub fn get_undo_data(&self, id:Id<Block>) -> Result<Option<BlockUndo>, crate::Error> {
        self.0.get_undo_data(id)
    }
}

impl<'a, S: UtxosPersistentStorage> UtxosView for UtxoDB<'a, S> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        match self.0.get_utxo(outpoint) {
            Ok(res) => res,
            Err(_) => {
                //todo: handle errors
                None
            }
        }
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.get_utxo(outpoint).is_some()
    }

    fn get_best_block_hash(&self) -> Option<Id<Block>> {
        match self.0.get_best_block_id() {
            Ok(opt_id) => opt_id,
            Err(_) => {
                // TODO: handle errors
                None
            }
        }
    }

    fn derive_cache(&self) -> UtxosCache {
        let mut cache = UtxosCache::new(self);
        if let Some(hash) = self.get_best_block_hash() {
            cache.set_best_block(hash);
        }
        cache
    }

    fn estimated_size(&self) -> usize {
        todo!()
    }
}

impl<'a, S: UtxosPersistentStorage> FlushableUtxoView for UtxoDB<'a, S> {
    fn batch_write(
        &mut self,
        utxos: crate::utxo_impl::ConsumedUtxoCache,
    ) -> Result<(), crate::Error> {
        // check each entry if it's dirty. Only then will the db be updated.
        for (key, entry) in utxos.container {
            let outpoint = &key;
            if entry.is_dirty() {
                if let Some(utxo) = entry.utxo() {
                    self.0.set_utxo(outpoint, utxo)?;
                    } else {
                    // entry is spent
                    self.0.del_utxo(outpoint)?;
                };
            }
        }
        self.0.set_best_block_id(&utxos.best_block)?;
        Ok(())
    }
}

struct UtxoInMemoryDBInterface {
    store: BTreeMap<OutPoint, Utxo>,
    undo_store: HashMap<H256,BlockUndo>,
    best_block_id: Option<Id<Block>>,
}

impl UtxoInMemoryDBInterface {
    fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            undo_store: HashMap::new(),
            best_block_id: None,
        }
    }
}

impl UtxosPersistentStorage for UtxoInMemoryDBInterface {
    fn set_utxo(
        &mut self,
        outpoint: &OutPoint,
        entry: Utxo,
    ) -> Result<(), crate::utxo_impl::Error> {
        self.store.insert(outpoint.clone(), entry);
        Ok(())
    }
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), crate::utxo_impl::Error> {
        self.store.remove(outpoint);
        Ok(())
    }
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, crate::utxo_impl::Error> {
        let res = self.store.get(outpoint);
        Ok(res.cloned())
    }
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), crate::utxo_impl::Error> {
        // TODO: fix; don't store in general block id
        self.best_block_id = Some(block_id.clone());
        Ok(())
    }
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, crate::utxo_impl::Error> {
        // TODO: fix; don't get general block id
        Ok(self.best_block_id.clone())
    }

    fn set_undo_data(&mut self, id: Id<Block>, undo: &BlockUndo) -> Result<(), Error> {
        self.undo_store.insert(id.get(),undo.clone());
        Ok(())
    }

    fn del_undo_data(&mut self, id: Id<Block>) -> Result<(), Error> {
        self.undo_store.remove(&id.get());
        Ok(())
    }

    fn get_undo_data(&self, id: Id<Block>) -> Result<Option<BlockUndo>, Error> {
        let res = self.undo_store.get(&id.get());
        Ok(res.cloned())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utxo_impl::{
        flush_to_base, utxo_storage::UtxoDB, FlushableUtxoView, Utxo, UtxoEntry, UtxosCache,
        UtxosView,
    };
    use crate::ConsumedUtxoCache;
    use common::chain::{Destination, OutPointSourceId, Transaction, TxInput, TxOutput};
    use common::primitives::{Amount, BlockHeight};
    use common::primitives::{Id, H256};
    use crypto::random::{make_pseudo_rng, Rng, seq};
    use iter_tools::Itertools;
    use std::collections::BTreeMap;
    use common::chain::config::create_mainnet;
    use common::primitives::consensus_data::ConsensusData;
    use crate::test_helper::{create_tx_outputs, create_utxo};


    fn create_utxo_entries(num_of_utxos: u8) -> BTreeMap<OutPoint, UtxoEntry> {
        let mut map = BTreeMap::new();
        for _ in 0..num_of_utxos {
            let (utxo, outpoint) = create_utxo(0);
            let entry = UtxoEntry::new(utxo.clone(), true, true);
            map.insert(outpoint, entry);
        }

        map
    }


    #[test]
    fn test_utxo() {
        common::concurrency::model(move || {
            let utxos = create_utxo_entries(10);
            let new_best_block_hash = Id::new(&H256::random());

            let utxos = ConsumedUtxoCache {
                container: utxos,
                best_block: new_best_block_hash.clone(),
            };

            let mut db_interface = UtxoInMemoryDBInterface::new();
            let mut utxo_db = UtxoDB::new(&mut db_interface);

            // test batch_write
            let res = utxo_db.batch_write(utxos.clone());
            assert!(res.is_ok());

            // randomly get a key for checking
            let keys = utxos.container.keys().collect_vec();
            let rng = make_pseudo_rng().gen_range(0..keys.len());
            let outpoint = keys[rng].clone();

            // test the get_utxo
            let utxo_opt = utxo_db.get_utxo(&outpoint);

            let outpoint_key = &outpoint;
            let utxo_entry =
                utxos.container.get(outpoint_key).expect("an entry should be found");
            assert_eq!(utxo_entry.utxo(), utxo_opt);

            // check has_utxo
            assert!(utxo_db.has_utxo(&outpoint));

            //check the best block hash
            assert_eq!(utxo_db.get_best_block_hash(), Some(new_best_block_hash));

            // try to write a non-dirty utxo
            {
                let (utxo, outpoint) = create_utxo(1);
                let mut map = BTreeMap::new();
                let entry = UtxoEntry::new(utxo, true, false);
                map.insert(outpoint.clone(), entry);

                let new_hash = Id::new(&H256::random());
                let another_cache = ConsumedUtxoCache {
                    container: map,
                    best_block: new_hash,
                };

                utxo_db.batch_write(another_cache).expect("batch write should work");

                assert!(!utxo_db.has_utxo(&outpoint));
            }

            // write down a spent utxo.
            {
                let rng = make_pseudo_rng().gen_range(0..keys.len());
                let outpoint_key = keys[rng];
                let outpoint = outpoint_key;
                let utxo = utxos
                    .container
                    .get(outpoint_key)
                    .expect("entry should exist")
                    .utxo()
                    .expect("utxo should exist");

                let mut parent = UtxosCache::default();
                assert!(parent.add_utxo(utxo, outpoint, false).is_ok());
                parent.set_best_block(
                    utxo_db.get_best_block_hash().expect("best block should be there"),
                );

                let mut child = UtxosCache::new(&parent);
                assert!(child.spend_utxo(outpoint).is_ok());

                let res = flush_to_base(child, &mut utxo_db);
                assert!(res.is_ok());

                assert!(!utxo_db.has_utxo(outpoint));
            }
        });
    }

}
