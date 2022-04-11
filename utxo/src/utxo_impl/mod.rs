//TODO: remove once the functions are used.
#![allow(dead_code)]
use crate::Error;
use common::chain::{OutPoint, OutPointSourceId, Transaction, TxOutput};
use common::primitives::{BlockHeight, Id, Idable, H256};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};

use common::chain::block::Block;
use parity_scale_codec::{Decode, Encode};

//todo: proper placement and derivation of this max
const MAX_OUTPUTS_PER_BLOCK: u32 = 500;

/// OutpointKey serves as a "key" equivalent of Outpoint.
// This is because the Outpoint does not implement `Hash`.
// Most of the fields of Outpoint do not implement `Hash` as well.
// To avoid adding #[derive(Hash)] on all sub structs of Outpoint, this OutpointKey was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutPointKey {
    outpoint_hash: H256,
    is_block_reward: bool,
    index: u32,
}

impl OutPointKey {
    pub fn outpoint_hash(&self) -> &H256 {
        &self.outpoint_hash
    }
}

// Because the outpoint is mostly being passed around as reference, it only makes sense that
// only a reference of outpoint is used to create an OutPointKey.
// The outpoint is widely used as it is, so it's better not to consume it.
impl From<&OutPoint> for OutPointKey {
    fn from(outpoint: &OutPoint) -> Self {
        let is_block_reward = match outpoint.get_tx_id() {
            OutPointSourceId::Transaction(_) => false,
            OutPointSourceId::BlockReward(_) => true,
        };

        let outpoint_hash = match &outpoint.get_tx_id() {
            OutPointSourceId::Transaction(inner) => inner.get(),
            OutPointSourceId::BlockReward(inner) => inner.get(),
        };

        Self {
            outpoint_hash,
            is_block_reward,
            index: outpoint.get_output_index(),
        }
    }
}

// In the process of creating an Outpoint from the OutpointKey.
impl From<&OutPointKey> for OutPoint {
    fn from(key: &OutPointKey) -> Self {
        let id = if key.is_block_reward {
            let utxo_id: Id<Block> = Id::new(&key.outpoint_hash);
            OutPointSourceId::BlockReward(utxo_id)
        } else {
            let utxo_id: Id<Transaction> = Id::new(&key.outpoint_hash);
            OutPointSourceId::Transaction(utxo_id)
        };

        OutPoint::new(id, key.index)
    }
}

// Determines whether the utxo is for the blockchain of for mempool
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum UtxoSource {
    /// At which height this containing tx was included in the active block chain
    BlockChain(BlockHeight),
    MemPool,
}

/// The Unspent Transaction Output
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct Utxo {
    output: TxOutput,
    is_block_reward: bool,
    /// identifies whether the utxo is for the blockchain or for mempool.
    source: UtxoSource,
}

impl Utxo {
    pub fn new(output: TxOutput, is_block_reward: bool, height: BlockHeight) -> Self {
        Self {
            output,
            is_block_reward,
            source: UtxoSource::BlockChain(height),
        }
    }

    /// a utxo for mempool, that does not need the block height.
    pub fn new_for_mempool(output: TxOutput, is_block_reward: bool) -> Self {
        Self {
            output,
            is_block_reward,
            source: UtxoSource::MemPool,
        }
    }

    pub fn is_block_reward(&self) -> bool {
        self.is_block_reward
    }

    pub fn height(&self) -> Option<BlockHeight> {
        match self.source {
            UtxoSource::BlockChain(height) => Some(height),
            UtxoSource::MemPool => None,
        }
    }

    pub fn output(&self) -> &TxOutput {
        &self.output
    }

    pub fn set_height(&mut self, value: BlockHeight) -> bool {
        match self.source {
            UtxoSource::BlockChain(_) => {
                self.source = UtxoSource::BlockChain(value);
                true
            }
            // cannot set the height if the utxo is meant for the mempool.
            UtxoSource::MemPool => false,
        }
    }
}

pub trait UtxosView {
    /// Retrieves utxo.
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo>;

    /// Checks whether outpoint is unspent.
    fn has_utxo(&self, outpoint: &OutPoint) -> bool;

    /// Retrieves the block hash of the best block in this view
    fn get_best_block_hash(&self) -> Option<H256>;

    /// Estimated size of the whole view (should be 0 if empty.)
    fn estimated_size(&self) -> usize;

    /// Performs bulk modification
    fn batch_write(
        &mut self,
        utxos: HashMap<OutPointKey, UtxoEntry>,
        block_hash: H256,
    ) -> Result<(), Error>;

    fn derive_cache(&self) -> UtxosCache;
}

// flush the cache into the provided base. This will consume the cache and throw it away.
// It uses the batch_write function since it's available in different kinds of views.
pub fn flush_to_base<T: UtxosView>(
    cache: UtxosCache,
    block_hash: H256,
    base: &mut T,
) -> Result<(), Error> {
    base.batch_write(cache.utxos, block_hash)
}

#[derive(Clone, Default)]
pub struct UtxosCache<'a> {
    parent: Option<&'a dyn UtxosView>,
    current_block_hash: Option<H256>,
    utxos: HashMap<OutPointKey, UtxoEntry>,
    //TODO: do we need this?
    memory_usage: usize,
}

/// Tells the state of the utxo
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum UtxoStatus {
    Spent,
    Entry(Utxo),
}

/// Just the Utxo with additional information.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct UtxoEntry {
    status: UtxoStatus,
    /// The utxo entry is dirty when this version is different from the parent.
    is_dirty: bool,
    /// The utxo entry is fresh when the parent does not have this utxo or
    /// if it exists in parent but not in current cache.
    is_fresh: bool,
}

impl UtxoEntry {
    pub fn new(utxo: Utxo, is_fresh: bool, is_dirty: bool) -> UtxoEntry {
        UtxoEntry {
            status: UtxoStatus::Entry(utxo),
            is_dirty,
            is_fresh,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.is_dirty
    }

    pub fn is_fresh(&self) -> bool {
        self.is_fresh
    }

    pub fn is_spent(&self) -> bool {
        self.status == UtxoStatus::Spent
    }

    pub fn utxo(&self) -> Option<Utxo> {
        match &self.status {
            UtxoStatus::Spent => None,
            UtxoStatus::Entry(utxo) => Some(utxo.clone()),
        }
    }

    fn utxo_mut(&mut self) -> Option<&mut Utxo> {
        match &mut self.status {
            UtxoStatus::Spent => None,
            UtxoStatus::Entry(utxo) => Some(utxo),
        }
    }
}

impl<'a> UtxosCache<'a> {
    /// returns a UtxoEntry, given the outpoint.
    // the reason why it's not a `&UtxoEntry`, is because the flags are bound to change esp.
    // when the utxo was actually retrieved from the parent.
    fn get_utxo_entry(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        let key = OutPointKey::from(outpoint);

        if let Some(res) = self.utxos.get(&key) {
            return Some(res.clone());
        }

        // since the utxo does not exist in this view, try to check from parent.
        self.parent.and_then(|parent| {
            parent.get_utxo(outpoint).map(|utxo| UtxoEntry {
                // if the utxo exists in parent:
                // dirty is FALSE because this view does not have the utxo, therefore is different from parent
                // fresh is FALSE because this view does not have the utxo but the parent has.
                status: UtxoStatus::Entry(utxo),
                is_dirty: false,
                is_fresh: false,
            })
        })
    }

    pub fn new(parent: &'a dyn UtxosView) -> Self {
        UtxosCache {
            parent: Some(parent),
            current_block_hash: None,
            utxos: HashMap::new(),
            memory_usage: 0,
        }
    }

    pub fn set_best_block(&mut self, block_hash: H256) {
        self.current_block_hash = Some(block_hash);
    }

    //TODO: haven't tested this yet.
    pub fn add_utxos(
        &mut self,
        tx: &Transaction,
        source: UtxoSource,
        check_for_overwrite: bool,
    ) -> Result<(), Error> {
        let id = OutPointSourceId::from(tx.get_id());

        for (idx, output) in tx.get_outputs().iter().enumerate() {
            let outpoint = OutPoint::new(id.clone(), idx as u32);

            let overwrite = if check_for_overwrite {
                self.has_utxo(&outpoint)
            } else {
                // TODO: a temporary return of false.
                false
            };

            let utxo = Utxo {
                output: output.clone(),
                // TODO: where do we get the block reward from the transaction?
                is_block_reward: false,
                source: source.clone(),
            };

            self.add_utxo(utxo, &outpoint, overwrite)?;
        }
        Ok(())
    }

    /// Adds a utxo entry in the cache.
    pub fn add_utxo(
        &mut self,
        utxo: Utxo,
        outpoint: &OutPoint,
        possible_overwrite: bool,
    ) -> Result<(), Error> {
        let key = OutPointKey::from(outpoint);
        let is_fresh = match self.utxos.get(&key) {
            None => {
                // An insert can be done. This utxo doesn't exist yet, so it's fresh.
                !possible_overwrite
            }
            Some(curr_entry) => {
                // TODO: update the memory usage
                // self.memory_usage should be deducted based on this current entry.

                if !possible_overwrite {
                    if !curr_entry.is_spent() {
                        // Attempted to overwrite an existing utxo
                        return Err(Error::OverwritingUtxo);
                    }
                    // If the utxo exists in this cache as a 'spent' utxo and is DIRTY, then
                    // its spentness hasn't been flushed to the parent cache. We're
                    // re-adding the utxo to this cache now but we can't mark it as FRESH.
                    // If we mark it FRESH and then spend it before the cache is flushed
                    // we would remove it from this cache and would never flush spentness
                    // to the parent cache.
                    //
                    // Re-adding a 'spent' utxo can happen in the case of a re-org (the utxo
                    // is 'spent' when the block adding it is disconnected and then
                    // re-added when it is also added in a newly connected block).
                    // if utxo is spent and is not dirty, then it can be marked as fresh.
                    !curr_entry.is_dirty || curr_entry.is_fresh
                } else {
                    // copy from the original entry
                    curr_entry.is_fresh
                }
            }
        };

        // create a new entry
        let new_entry = UtxoEntry::new(utxo, is_fresh, true);

        // TODO: update the memory usage
        // self.memory_usage should be added based on this new entry.

        self.utxos.insert(key, new_entry);

        Ok(())
    }

    /// Flags the utxo as "spent", given an outpoint.
    /// Returns true if an update was performed.
    pub fn spend_utxo(&mut self, outpoint: &OutPoint) -> bool {
        match self.get_utxo_entry(outpoint) {
            None => false,
            Some(entry) => {
                let key = OutPointKey::from(outpoint);

                // TODO: update the memory usage
                // self.memory_usage must be deducted from this entry's size

                // check whether this entry is fresh
                if entry.is_fresh {
                    // This is only available in this view. Remove immediately.
                    self.utxos.remove(&key);
                } else {
                    // mark this as 'spent'
                    let entry = UtxoEntry {
                        status: UtxoStatus::Spent,
                        is_dirty: true,
                        is_fresh: false,
                    };
                    self.utxos.insert(key, entry);
                }
                true
            }
        }
    }

    /// Checks whether utxo exists in the cache
    pub fn has_utxo_in_cache(&self, outpoint: &OutPoint) -> bool {
        let key = OutPointKey::from(outpoint);
        self.utxos.contains_key(&key)
    }

    /// Returns a mutable reference of the utxo, given the outpoint.
    pub fn get_mut_utxo(&mut self, outpoint: &OutPoint) -> Option<&mut Utxo> {
        self.get_utxo_entry(outpoint).and_then(|status| {
            match status.status {
                UtxoStatus::Spent => None,
                UtxoStatus::Entry(utxo) => {
                    let key = OutPointKey::from(outpoint);
                    self.utxos.insert(key, UtxoEntry::new(utxo, status.is_fresh, status.is_dirty));
                    //TODO: update the memory storage here
                    self.utxos.get_mut(&key).and_then(|entry| entry.utxo_mut())
                }
            }
        })
    }

    //TODO: this needs to be tested.
    pub fn uncache(&mut self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        let key = OutPointKey::from(outpoint);
        if let Some(entry) = self.utxos.get(&key) {
            // see bitcoin's Uncache.
            if !entry.is_fresh && !entry.is_dirty {
                //todo: decrement the memory usage
                return self.utxos.remove(&key);
            }
        }
        None
    }
}

impl<'a> Debug for UtxosCache<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UtxosCache")
            // we wouldn't want to display the parent's children; only to check whether it has a parent.
            .field("has_parent", &self.parent.is_some())
            .field("current_block_hash", &self.current_block_hash)
            .field("utxos", &self.utxos)
            .finish()
    }
}

impl<'a> UtxosView for UtxosCache<'a> {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        let key = OutPointKey::from(outpoint);
        if let Some(res) = self.utxos.get(&key) {
            return res.utxo();
        }

        // if utxo is not found in this view, use parent's `get_utxo`.
        self.parent.and_then(|parent| parent.get_utxo(outpoint))
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.get_utxo(outpoint).is_some()
    }

    fn get_best_block_hash(&self) -> Option<H256> {
        self.current_block_hash.or_else(||
            // if the block_hash is empty in this view, use parent's `get_best_block_hash`.
            self.parent.and_then(|parent| parent.get_best_block_hash()))
    }

    fn estimated_size(&self) -> usize {
        todo!()
    }

    fn batch_write(
        &mut self,
        utxo_entries: HashMap<OutPointKey, UtxoEntry>,
        block_hash: H256,
    ) -> Result<(), Error> {
        for (key, entry) in utxo_entries {
            let parent_entry = self.utxos.get(&key);

            // Ignore non-dirty entries (optimization).
            if entry.is_dirty {
                match parent_entry {
                    None => {
                        // The parent cache does not have an entry, while the child cache does.
                        // We can ignore it if it's both spent and FRESH in the child
                        if !(entry.is_fresh && entry.is_spent()) {
                            // Create the utxo in the parent cache, move the data up
                            // and mark it as dirty.
                            let mut entry_copy = entry.clone();
                            entry_copy.is_dirty = true;

                            self.utxos.insert(key, entry_copy);
                            // TODO: increase the memory usage
                        }
                    }
                    // found entry in the parent cache
                    Some(parent_entry) => {
                        if entry.is_fresh() && !parent_entry.is_spent() {
                            // The utxo was marked FRESH in the child cache, but the utxo
                            // exists in the parent cache. If this ever happens, it means
                            // the FRESH flag was misapplied and there is a logic error in
                            // the calling code.
                            return Err(Error::UtxoAlreadyExists);
                        }

                        if parent_entry.is_fresh && entry.is_spent() {
                            // The grandparent cache does not have an entry, and the utxo
                            // has been spent. We can just delete it from the parent cache.
                            self.utxos.remove(&key);
                        } else {
                            // A normal modification.
                            let mut entry_copy = entry.clone();
                            entry_copy.is_dirty = true;
                            entry_copy.is_fresh = parent_entry.is_fresh;
                            self.utxos.insert(key, entry_copy);
                            // TODO: update the memory usage

                            // NOTE: It isn't safe to mark the utxo as FRESH in the parent
                            // cache. If it already existed and was spent in the parent
                            // cache then marking it FRESH would prevent that spentness
                            // from being flushed to the grandparent.
                        }
                    }
                }
            }
        }

        self.current_block_hash = Some(block_hash);
        Ok(())
    }

    fn derive_cache(&self) -> UtxosCache {
        UtxosCache::new(self)
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod test_helper;

#[cfg(test)]
mod simulation;
