use std::collections::{BTreeMap, HashMap};

use crate::utxo_impl::{FlushableUtxoView, OutPointKey, Utxo, UtxoEntry, UtxosCache, UtxosView};
use common::chain::block::Block;
use common::chain::OutPoint;
use common::primitives::Id;

pub trait UtxosPersistentStorage {
    fn set_utxo(&mut self, outpoint: &OutPoint, entry: Utxo) -> Result<(), crate::Error>;
    fn del_utxo(&mut self, outpoint: &OutPoint) -> Result<(), crate::Error>;
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, crate::Error>;
    fn set_best_block_id(&mut self, block_id: &Id<Block>) -> Result<(), crate::Error>;
    fn get_best_block_id(&self) -> Result<Option<Id<Block>>, crate::Error>;
}

pub struct UtxoDB<'a, S: UtxosPersistentStorage>(&'a mut S);

impl<'a, S: UtxosPersistentStorage> UtxoDB<'a, S> {
    pub fn new(store: &'a mut S) -> Self {
        Self(store)
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
        utxos: HashMap<OutPointKey, UtxoEntry>,
        block_hash: Id<Block>,
    ) -> Result<(), crate::Error> {
        // check each entry if it's dirty. Only then will the db be updated.
        for (key, entry) in utxos {
            let outpoint: OutPoint = (&key).into();
            if entry.is_dirty() {
                if let Some(utxo) = entry.utxo() {
                    self.0.set_utxo(&outpoint, utxo)?;
                } else {
                    // entry is spent
                    self.0.del_utxo(&outpoint)?;
                }
            }
        }
        self.0.set_best_block_id(&block_hash)?;
        Ok(())
    }
}

struct UtxoInMemoryDBInterface {
    store: BTreeMap<OutPoint, Utxo>,
    best_block_id: Option<Id<Block>>,
}

impl UtxoInMemoryDBInterface {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utxo_impl::{
        flush_to_base, utxo_storage::UtxoDB, FlushableUtxoView, OutPointKey, Utxo, UtxoEntry,
        UtxosCache, UtxosView,
    };
    use common::chain::{Destination, OutPointSourceId, Transaction, TxOutput};
    use common::primitives::{Amount, BlockHeight};
    use common::primitives::{Id, H256};
    use iter_tools::Itertools;
    use rand::Rng;
    use std::collections::HashMap;
    fn create_utxo(block_height: u64) -> (Utxo, OutPoint) {
        let output = TxOutput::new(Amount::new(10), Destination::PublicKey);
        let utxo = Utxo::new(output, false, BlockHeight::new(block_height));

        let utxo_id: Id<Transaction> = Id::new(&H256::random());
        let outpoint = OutPoint::new(OutPointSourceId::Transaction(utxo_id), 0);

        (utxo, outpoint)
    }

    fn create_utxos(num_of_utxos: u8) -> HashMap<OutPointKey, UtxoEntry> {
        let mut map = HashMap::new();
        for _ in 0..num_of_utxos {
            let (utxo, outpoint) = create_utxo(0);
            let entry = UtxoEntry::new(utxo.clone(), true, true);
            map.insert(OutPointKey::from(&outpoint), entry);
        }

        map
    }

    #[test]
    fn test_utxo() {
        common::concurrency::model(move || {
            let utxos = create_utxos(10);

            let mut db_interface = UtxoInMemoryDBInterface::new();
            let mut utxo_db = UtxoDB::new(&mut db_interface);

            // test batch_write
            let new_best_block_hash = Id::new(&H256::random());
            let res = utxo_db.batch_write(utxos.clone(), new_best_block_hash.clone());
            assert!(res.is_ok());

            // randomly get a key for checking
            let keys = &utxos.keys().collect_vec();
            let rng = rand::thread_rng().gen_range(0..keys.len());
            let outpoint = OutPoint::from(keys[rng]);

            // test the get_utxo
            let utxo_opt = utxo_db.get_utxo(&outpoint);

            let outpoint_key = OutPointKey::from(&outpoint);
            let utxo_entry = utxos.get(&outpoint_key).expect("an entry should be found");
            assert_eq!(utxo_entry.utxo(), utxo_opt);

            // check has_utxo
            assert!(utxo_db.has_utxo(&outpoint));

            //check the best block hash
            assert_eq!(utxo_db.get_best_block_hash(), Some(new_best_block_hash));

            // try to write a non-dirty utxo
            {
                let (utxo, outpoint) = create_utxo(1);
                let mut map = HashMap::new();
                let entry = UtxoEntry::new(utxo, true, false);
                map.insert(OutPointKey::from(&outpoint), entry);

                let new_hash = Id::new(&H256::random());
                utxo_db.batch_write(map, new_hash).expect("batch write should work");

                assert!(!utxo_db.has_utxo(&outpoint));
            }

            // write down a spent utxo.
            {
                let rng = rand::thread_rng().gen_range(0..keys.len());
                let outpoint_key = keys[rng];
                let outpoint = OutPoint::from(outpoint_key);
                let utxo = utxos
                    .get(outpoint_key)
                    .expect("entry should exist")
                    .utxo()
                    .expect("utxo should exist");

                let mut parent = UtxosCache::default();
                assert!(parent.add_utxo(utxo, &outpoint, false).is_ok());
                parent.set_best_block(
                    utxo_db.get_best_block_hash().expect("best block should be there"),
                );

                let mut child = UtxosCache::new(&parent);
                assert!(child.spend_utxo(&outpoint));

                let new_block_hash = Id::new(&H256::random());
                let res = flush_to_base(child, new_block_hash, &mut utxo_db);
                assert!(res.is_ok());

                assert!(!utxo_db.has_utxo(&outpoint));
            }
        });
    }
}
