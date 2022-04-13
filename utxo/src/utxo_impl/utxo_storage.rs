use std::collections::HashMap;

use crate::utxo_impl::{FlushableUtxoView, OutPointKey, Utxo, UtxoEntry, UtxosCache, UtxosView};
use common::chain::block::Block;
use common::chain::{OutPoint, OutPointSourceId, Transaction, TxOutput};
use common::primitives::{BlockHeight, Id, Idable, H256};

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

    fn get_best_block_hash(&self) -> Option<H256> {
        match self.0.get_best_block_id() {
            Ok(opt_id) => opt_id.map(|id| id.get()),
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
        block_hash: H256,
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
        self.0.set_best_block_id(&Id::<Block>::new(&block_hash))?;
        Ok(())
    }
}
