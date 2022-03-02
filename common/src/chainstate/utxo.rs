use crate::chain::{OutPoint, Transaction, TxOutput};
use crate::chainstate::Error;
use crate::primitives::{BlockHeight, Id, H256};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use crate::chain::block::Block;
use crate::Uint256;
use parity_scale_codec::{Decode, Encode};

/// The Unspent Transaction Output
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct Utxo {
    output: TxOutput,
    is_block_reward: bool,
    /// At which height this containing tx was included in the active block chain
    height: BlockHeight,
}

impl Utxo {
    fn new(output: TxOutput, is_block_reward: bool, height: BlockHeight) -> Self {
        Self {
            output,
            is_block_reward,
            height,
        }
    }

    fn is_block_reward(&self) -> bool {
        self.is_block_reward
    }

    fn height(&self) -> BlockHeight {
        self.height
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxoEntry {
    /// The utxo is None when it has been spent.
    utxo: Option<Utxo>,
    /// The utxo entry is dirty when the version is different from its parent
    is_dirty: bool,
    /// The utxo entry is fresh when the parent does not have this utxo
    is_fresh: bool,
}

impl UtxoEntry {
    fn new(utxo: Utxo, is_fresh: bool, is_dirty: bool) -> Self {
        Self {
            utxo: Some(utxo),
            is_dirty,
            is_fresh,
        }
    }

    fn new_empty() -> Self {
        Self {
            utxo: None,
            is_dirty: true,
            is_fresh: false,
        }
    }

    fn is_dirty(&self) -> bool {
        self.is_dirty
    }

    fn is_fresh(&self) -> bool {
        self.is_fresh
    }

    fn is_spent(&self) -> bool {
        self.utxo.is_some()
    }
}

pub trait UtxosView {
    /// Retrieves utxo.
    /// Returns a tuple of (`&UtxoEntry`, `bool`),
    /// where bool == true if the first element result came from parent's `get_utxo` method.
    fn get_utxo(&self, outpoint: &OutPoint) -> (Option<&UtxoEntry>, bool);

    /// Checks whether outpoint is unspent.
    /// Returns a tuple of (`bool`, `bool`),
    /// where first element is false if no utxo is found,
    /// where the bool == true if the first element result came from parent's `have_utxo` method.
    fn have_utxo(&self, outpoint: &OutPoint) -> (bool, bool);

    /// Retrieves the block hash of the best block in this current view
    /// Returns a tuple of (`Option<&H256>`, `bool`),
    /// where the bool == true  if first element result came from parent's `get_best_block_hash` method.
    fn get_best_block_hash(&self) -> (Option<&H256>, bool);

    /// Estimated size of the whole view (0 if not implemented)
    fn size(&self) -> usize;

    /// Performs bulk modification
    fn batch_write(&self, utxos: HashMap<H256, UtxoEntry>, block_hash: H256) -> bool;
}

#[derive(Clone)]
pub struct UtxosCache<'a> {
    parent: Option<&'a dyn UtxosView>,
    current_block_hash: Option<H256>,
    utxos: HashMap<H256, UtxoEntry>,
}

impl<'a> UtxosCache<'a> {
    /// Adds a utxo entry in the cache.
    /// Consumes a struct and returns a new one or an error.
    fn add_utxo(self, utxo: Utxo, outpoint: &OutPoint, is_overwrite: bool) -> Result<Self, Error> {
        let mut is_fresh = false;
        if !is_overwrite {
            match self.utxos.get(&outpoint.get_tx_id().hash()) {
                None => {
                    // If the coin doesn't exist in the current cache
                    is_fresh = true;
                }
                Some(entry) => {
                    if !entry.is_spent() {
                        // Attempted to overwrite an unspent coin
                        return Err(Error::OverwritingUtxo);
                    }
                    // If the coin exists in this cache as a spent coin and is DIRTY, then
                    // its spentness hasn't been flushed to the parent cache. We're
                    // re-adding the coin to this cache now but we can't mark it as FRESH.
                    // If we mark it FRESH and then spend it before the cache is flushed
                    // we would remove it from this cache and would never flush spentness
                    // to the parent cache.
                    //
                    // Re-adding a spent coin can happen in the case of a re-org (the coin
                    // is 'spent' when the block adding it is disconnected and then
                    // re-added when it is also added in a newly connected block).

                    //if is spent but not DIRTY, then it can be marked FRESH.
                    is_fresh = !entry.is_dirty;
                }
            }
        }

        let entry = UtxoEntry {
            utxo: Some(utxo),
            is_dirty: true,
            is_fresh,
        };

        let mut entry_copy = self;
        if entry_copy.utxos.insert(outpoint.get_tx_id().hash(), entry.clone()).is_none() {
            println!("warning: failed to insert entry {:?} to the map", entry);
        }

        Ok(entry_copy)
    }

    /// Updates the `utxo` field of a `UntoEntry` to `None`, given the outpoint.
    /// This will return a new view.
    fn spend_utxo(self, outpoint: &OutPoint) -> Self {
        let id = outpoint.get_tx_id().hash();
        let mut self_copy = self.clone();
        if let Some(entry) = self.utxos.get(&id) {
            let mut entry = entry.clone();
            entry.is_dirty = true;
            entry.is_fresh = true;
            entry.utxo = None;

            if self_copy.utxos.insert(id, entry).is_none() {
                println!("warning: failed to update utxo as unspent");
            }
        }

        self_copy
    }
}

impl<'a> Default for UtxosCache<'a> {
    fn default() -> Self {
        Self {
            parent: None,
            current_block_hash: None,
            utxos: HashMap::new(),
        }
    }
}

impl<'a> Debug for UtxosCache<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtxosCache")
            .field("current_block_hash", &self.current_block_hash)
            .field("utxos", &self.utxos)
            .finish()
    }
}

impl<'a> UtxosView for UtxosCache<'a> {
    fn get_utxo(&self, outpoint: &OutPoint) -> (Option<&UtxoEntry>, bool) {
        let tx_id = outpoint.get_tx_id().hash();
        if let Some(res) = self.utxos.get(&tx_id) {
            return (Some(res), false);
        }

        // if utxo is not found in this view, use parent's `get_utxo`.
        self.parent.map_or_else(
            || (None, false),
            |parent| {
                println!("i had to access parent.");
                let (res, _) = parent.get_utxo(outpoint);
                // set to true since the parent is accessed.
                (res, true)
            },
        )
    }

    fn have_utxo(&self, outpoint: &OutPoint) -> (bool, bool) {
        let (res, has_access_parent) = self.get_utxo(outpoint);
        (
            match res {
                // no utxo is found
                None => false,
                Some(res) => !res.is_spent(),
            },
            has_access_parent,
        )
    }

    fn get_best_block_hash(&self) -> (Option<&H256>, bool) {
        if let Some(res) = self.current_block_hash.as_ref() {
            return (Some(res), false);
        }

        // if the block_hash is empty in this view, use parent's `get_best_block_hash`.
        self.parent.map_or_else(
            || (None, false),
            |parent| {
                let (res, _) = parent.get_best_block_hash();
                // set to true since the parent is accessed.
                (res, true)
            },
        )
    }

    fn size(&self) -> usize {
        self.utxos.len()
    }

    fn batch_write(&self, _: HashMap<H256, UtxoEntry>, _: H256) -> bool {
        false
    }
}

/*
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use rand::Rng;
    use crate::chain::{Destination, OutPoint, OutPointSourceId, Transaction, TxOutput};
    use crate::chainstate::utxo::{Utxo, UtxoEntry, UtxosCache, UtxosView};
    use crate::primitives::{Amount, BlockHeight, H256, Id};
    use crate::Uint256;

    // initialization with random amount.
    fn init<'a>(num_of_entries:u64) -> (UtxosCache<'a>, Vec<Id<Transaction>>) {
        let mut cache = UtxosCache::default();

        // Use a limited set of random transaction ids, so we do test overwriting entries.
        let mut tx_ids = vec![];
        for i in 0..num_of_entries {
            let utxo_id:Id<Transaction> = Id::new(&H256::random());

            let mut rng = rand::thread_rng().gen_range(0..u128::MAX);
            let output = TxOutput::new(Amount::new(rng),Destination::PublicKey);
            let utxo = Utxo {
                output,
                is_block_reward: rng% 3 == 0,
                height: BlockHeight::new(i)
            };

            let utxo_entry = UtxoEntry {
                utxo:Some(utxo),
                is_dirty: false,
                is_fresh: true
            };

            cache.utxos.insert(utxo_id.get(),utxo_entry);

            if i+1 == num_of_entries {
                cache.current_block_hash = Some(utxo_id.get())
            }

            tx_ids.push(utxo_id);
        }

        (cache,tx_ids)
    }

    fn random_modification<'a>(num_of_removals:u64, num_of_modifications:u64, num_of_additions:u64, parent:&'a UtxosCache, tx_ids:&[Id<Transaction>])
    -> (UtxosCache<'a>, Vec<Id<Transaction>>, Vec<(Id<Transaction>,usize)>) {
        let mut child = UtxosCache::default();
        child.parent = Some(parent);

        let mut ctr = num_of_modifications;

        for _ in 0..num_of_modifications {
            let rng = rand::thread_rng().gen_range(0..tx_ids.len());
            let tx_id = &tx_ids[rng].get();

            let mut entry = parent.utxos.get(tx_id).expect("hash should be available.").clone();
            entry.is_dirty = true;
            entry.utxo.is_block_reward = !entry.utxo.is_block_reward;

            child.utxos.insert(tx_id.clone(),entry);
        }

        let mut removed_tx_ids = vec![];
        for _ in 0..num_of_removals {
            let rng = rand::thread_rng().gen_range(0..tx_ids.len());
            let tx_id = &tx_ids[rng];

            let entry = UtxoEntry{
                utxo: None,
                is_dirty: false,
                is_fresh:
            };
            child.utxos.insert(tx_id.get(),entry);
            removed_tx_ids.push((tx_id.clone(),rng));
        }

        let mut additional_tx_ids = vec![];
        for i in 0..num_of_additions {
            let height = tx_ids.len() as u64 + i;

            let utxo_id:Id<Transaction> = Id::new(&H256::random());

            let mut rng = rand::thread_rng().gen_range(0..u128::MAX);
            let output = TxOutput::new(Amount::new(rng),Destination::PublicKey);
            let utxo = Utxo {
                output,
                is_block_reward: rng% 3 == 0,
                height: BlockHeight::new(height as u64)
            };

            let utxo_entry = UtxoEntry {
                utxo:Some(utxo),
                is_dirty: true
            };

            child.utxos.insert(utxo_id.get(),utxo_entry);

            if i+1 == num_of_additions {
                child.current_block_hash = Some(utxo_id.get())
            }
            additional_tx_ids.push(utxo_id);
        }

        (child, additional_tx_ids,removed_tx_ids)
    }

    fn create_outpoint(id:&Id<Transaction>, idx:u32) -> OutPoint {
        let outpoint_id = OutPointSourceId::Transaction(id.clone());
        OutPoint::new(outpoint_id,idx)
    }

    #[test]
    fn utxo_check() {
        let (parent_utxo_cache, mut tx_ids) = init(15);
        println!("tx ids: {:?}", tx_ids);
        let (updated_cache, new_ids, removed_ids) = random_modification(2,4,5,&parent_utxo_cache, &tx_ids);

        let tx_ids_len = tx_ids.len();

        removed_ids.iter().rev().for_each(|(id, idx)| {
            let outpoint = create_outpoint(id,*idx as u32);

            assert_eq!(updated_cache.have_utxo(&outpoint), (true,true));
            let (utxo_entry, from_parent) = updated_cache.get_utxo(&outpoint);
            assert!(from_parent);

            assert_eq!(
                utxo_entry.expect("The utxo entry should be available"),
                parent_utxo_cache.utxos.get(&id.get()).expect("The utxo entry from parent cache should be available")
            );

            tx_ids.remove(*idx);
        });

        new_ids.iter().enumerate().for_each(|(idx,id)| {
            let outpoint = create_outpoint(id, idx as u32);

            assert_eq!(updated_cache.have_utxo(&outpoint), (true,false));
            let (utxo_entry, from_parent) = updated_cache.get_utxo(&outpoint);
            assert!(!from_parent);

            let utxo_entry = utxo_entry.expect("The utxo entry should be available");
            assert!(utxo_entry.is_dirty);
        });

        // tx_ids.iter().enumerate().for_each(|(idx,id)| {
        //     println!("AT ID: {:?}", id.get());
        //     let outpoint = create_outpoint(id, idx as u32);
        //
        //     assert_eq!(updated_cache.have_utxo(&outpoint), (true,true));
        //     let (utxo_entry, from_parent) = updated_cache.get_utxo(&outpoint);
        //     assert!(from_parent);
        //
        //     let utxo_entry = utxo_entry.expect("The utxo entry should be available");
        //     assert!(!utxo_entry.is_dirty);
        //
        // })

    }

}
*/
