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

use crate::{
    utxo_entry::{IsDirty, IsFresh, UtxoEntry},
    {Error, FlushableUtxoView, TxUndo, Utxo, UtxoSource, UtxosView},
};
use common::{
    chain::{GenBlock, OutPoint, OutPointSourceId, Transaction},
    primitives::{BlockHeight, Id, Idable},
};
use logging::log;
use std::{
    collections::BTreeMap,
    fmt::{Debug, Formatter},
};

#[derive(Clone)]
pub struct ConsumedUtxoCache {
    pub(crate) container: BTreeMap<OutPoint, UtxoEntry>,
    pub(crate) best_block: Id<GenBlock>,
}

#[derive(Clone)]
pub struct UtxosCache<'a> {
    parent: Option<&'a dyn UtxosView>,
    current_block_hash: Id<GenBlock>,
    // pub(crate) visibility is required for tests that are in a different mod
    pub(crate) utxos: BTreeMap<OutPoint, UtxoEntry>,
    // TODO: calculate memory usage (mintlayer/mintlayer-core#354)
    #[allow(dead_code)]
    memory_usage: usize,
}

impl<'a> UtxosCache<'a> {
    #[cfg(test)]
    pub fn new_for_test(best_block: Id<GenBlock>) -> Self {
        Self {
            parent: None,
            current_block_hash: best_block,
            utxos: Default::default(),
            memory_usage: 0,
        }
    }

    /// Returns a UtxoEntry, given the outpoint.
    // the reason why it's not a `&UtxoEntry`, is because the flags are bound to change esp.
    // when the utxo was actually retrieved from the parent.
    fn get_utxo_entry(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        if let Some(res) = self.utxos.get(outpoint) {
            return Some(res.clone());
        }

        // since the utxo does not exist in this view, try to check from parent.
        self.parent.and_then(|parent| {
            // if the utxo exists in parent:
            // dirty is FALSE because this view does not have the utxo, therefore is different from parent
            // fresh is FALSE because this view does not have the utxo but the parent has.
            parent
                .utxo(outpoint)
                .map(|utxo| UtxoEntry::new(Some(utxo), IsFresh::No, IsDirty::No))
        })
    }

    pub fn new(parent: &'a dyn UtxosView) -> Self {
        UtxosCache {
            parent: Some(parent),
            current_block_hash: parent.best_block_hash(),
            utxos: BTreeMap::new(),
            memory_usage: 0,
        }
    }

    pub fn set_best_block(&mut self, block_hash: Id<GenBlock>) {
        self.current_block_hash = block_hash;
    }

    pub fn add_utxos(
        &mut self,
        tx: &Transaction,
        source: UtxoSource,
        check_for_overwrite: bool,
    ) -> Result<(), Error> {
        let id = OutPointSourceId::from(tx.get_id());

        for (idx, output) in tx.outputs().iter().enumerate() {
            let outpoint = OutPoint::new(id.clone(), idx as u32);
            // by default no overwrite allowed.
            let overwrite = check_for_overwrite && self.has_utxo(&outpoint);
            let utxo = Utxo::new(output.clone(), false, source.clone());

            self.add_utxo(&outpoint, utxo, overwrite)?;
        }
        Ok(())
    }

    /// Marks the inputs of a transaction as 'spent', adds outputs to the utxo set.
    /// Returns a TxUndo if function is a success or an error if the tx's input cannot be spent.
    pub fn spend_utxos(&mut self, tx: &Transaction, height: BlockHeight) -> Result<TxUndo, Error> {
        let tx_undo: Result<Vec<Utxo>, Error> =
            tx.inputs().iter().map(|tx_in| self.spend_utxo(tx_in.outpoint())).collect();

        self.add_utxos(tx, UtxoSource::Blockchain(height), false)?;

        tx_undo.map(TxUndo::new)
    }

    /// Adds an utxo entry to the cache
    pub fn add_utxo(
        &mut self,
        outpoint: &OutPoint,
        utxo: Utxo,
        possible_overwrite: bool, // TODO: change this to an enum that explains what happens
    ) -> Result<(), Error> {
        // TODO: update the memory usage
        // self.memory_usage should be deducted based on this current entry.

        let is_fresh = match self.utxos.get(outpoint) {
            None => {
                // An insert can be done. This utxo doesn't exist yet, so it's fresh.
                !possible_overwrite
            }
            Some(curr_entry) => {
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
                    !curr_entry.is_dirty() || curr_entry.is_fresh()
                } else {
                    // copy from the original entry
                    curr_entry.is_fresh()
                }
            }
        };

        // create a new entry
        let new_entry = UtxoEntry::new(Some(utxo), IsFresh::from(is_fresh), IsDirty::Yes);

        // TODO: update the memory usage
        // self.memory_usage should be added based on this new entry.

        self.utxos.insert(outpoint.clone(), new_entry);

        Ok(())
    }

    /// Flags the utxo as "spent", given an outpoint.
    /// Returns the Utxo if an update was performed.
    pub fn spend_utxo(&mut self, outpoint: &OutPoint) -> Result<Utxo, Error> {
        let entry = self.get_utxo_entry(outpoint).ok_or(Error::NoUtxoFound)?;
        // TODO: update the memory usage
        // self.memory_usage must be deducted from this entry's size

        // check whether this entry is fresh
        if entry.is_fresh() {
            // This is only available in this view. Remove immediately.
            self.utxos.remove(outpoint);
        } else {
            // mark this as 'spent'
            let new_entry = UtxoEntry::new(None, IsFresh::No, IsDirty::Yes);
            self.utxos.insert(outpoint.clone(), new_entry);
        }

        entry.take_utxo().ok_or(Error::UtxoAlreadySpent)
    }

    /// Checks whether utxo exists in the cache
    pub fn has_utxo_in_cache(&self, outpoint: &OutPoint) -> bool {
        self.utxos.contains_key(outpoint)
    }

    /// Returns a mutable reference of the utxo, given the outpoint.
    pub fn get_mut_utxo(&mut self, outpoint: &OutPoint) -> Option<&mut Utxo> {
        let entry = self.get_utxo_entry(outpoint)?;
        let utxo = entry.utxo()?;

        let utxo: &mut UtxoEntry = self.utxos.entry(outpoint.clone()).or_insert_with(|| {
            //TODO: update the memory storage here
            UtxoEntry::new(
                Some(utxo.clone()),
                IsFresh::from(entry.is_fresh()),
                IsDirty::from(entry.is_dirty()),
            )
        });

        utxo.utxo_mut()
    }

    /// removes the utxo in the cache with the outpoint
    pub fn uncache(&mut self, outpoint: &OutPoint) -> Result<(), Error> {
        let key = outpoint;
        if let Some(entry) = self.utxos.get(key) {
            // see bitcoin's Uncache.
            if !entry.is_fresh() && !entry.is_dirty() {
                //todo: decrement the memory usage
                self.utxos.remove(key);
                return Ok(());
            }
        }
        Err(Error::NoUtxoFound)
    }

    pub fn consume(self) -> ConsumedUtxoCache {
        ConsumedUtxoCache {
            container: self.utxos,
            best_block: self.current_block_hash,
        }
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
    fn utxo(&self, outpoint: &OutPoint) -> Option<Utxo> {
        let key = outpoint;
        if let Some(res) = self.utxos.get(key) {
            return res.utxo().cloned();
        }

        // if utxo is not found in this view, use parent's `get_utxo`.
        self.parent.and_then(|parent| parent.utxo(outpoint))
    }

    fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.utxo(outpoint).is_some()
    }

    fn best_block_hash(&self) -> Id<GenBlock> {
        self.current_block_hash
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }

    fn derive_cache(&self) -> UtxosCache {
        UtxosCache::new(self)
    }
}

impl<'a> FlushableUtxoView for UtxosCache<'a> {
    fn batch_write(&mut self, utxo_entries: ConsumedUtxoCache) -> Result<(), Error> {
        for (key, entry) in utxo_entries.container {
            // Ignore non-dirty entries (optimization).
            if entry.is_dirty() {
                let parent_entry = self.utxos.get(&key);
                match parent_entry {
                    None => {
                        // The parent cache does not have an entry, while the child cache does.
                        // We can ignore it if it's both spent and FRESH in the child
                        if !(entry.is_fresh() && entry.is_spent()) {
                            // Create the utxo in the parent cache, move the data up
                            // and mark it as dirty.
                            let entry_copy = UtxoEntry::new(
                                entry.utxo().cloned(),
                                IsFresh::from(entry.is_fresh()),
                                IsDirty::Yes,
                            );

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
                            log::error!("CRITICAL: An invariant in Utxo was broken");
                            return Err(Error::FreshUtxoAlreadyExists);
                        }

                        if parent_entry.is_fresh() && entry.is_spent() {
                            // The grandparent cache does not have an entry, and the utxo
                            // has been spent. We can just delete it from the parent cache.
                            self.utxos.remove(&key);
                        } else {
                            // A normal modification.
                            let entry_copy = UtxoEntry::new(
                                entry.utxo().cloned(),
                                IsFresh::from(parent_entry.is_fresh()),
                                IsDirty::Yes,
                            );
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

        self.current_block_hash = utxo_entries.best_block;
        Ok(())
    }
}

#[cfg(test)]
mod unit_test {
    use super::*;
    use crate::tests::test_helper::{insert_single_entry, Presence};
    use common::primitives::H256;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_absent(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut cache = UtxosCache::new_for_test(H256::random().into());

        // when the outpoint does not exist.
        let (_, outp) = insert_single_entry(&mut rng, &mut cache, Presence::Absent, None, None);
        assert_eq!(Error::NoUtxoFound, cache.uncache(&outp).unwrap_err());
        assert!(!cache.has_utxo_in_cache(&outp));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_not_fresh_not_dirty(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut cache = UtxosCache::new_for_test(H256::random().into());

        // when the entry is not dirty and not fresh
        let (_, outp) = insert_single_entry(
            &mut rng,
            &mut cache,
            Presence::Present,
            Some((IsFresh::No, IsDirty::No)),
            None,
        );
        assert!(cache.uncache(&outp).is_ok());
        assert!(!cache.has_utxo_in_cache(&outp));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_dirty_not_fresh(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut cache = UtxosCache::new_for_test(H256::random().into());

        // when the entry is dirty, entry cannot be removed.
        let (_, outp) = insert_single_entry(
            &mut rng,
            &mut cache,
            Presence::Present,
            Some((IsFresh::No, IsDirty::Yes)),
            None,
        );
        assert_eq!(Error::NoUtxoFound, cache.uncache(&outp).unwrap_err());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uncache_fresh_and_dirty(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut cache = UtxosCache::new_for_test(H256::random().into());

        // when the entry is both fresh and dirty, entry cannot be removed.
        let (_, outp) = insert_single_entry(
            &mut rng,
            &mut cache,
            Presence::Present,
            Some((IsFresh::Yes, IsDirty::Yes)),
            None,
        );
        assert_eq!(Error::NoUtxoFound, cache.uncache(&outp).unwrap_err());
    }
}
