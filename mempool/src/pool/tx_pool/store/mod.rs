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

mod mem_usage;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    ops::Deref,
    sync::Arc,
};

use common::{
    chain::{SignedTransaction, Transaction},
    primitives::Id,
};
use logging::log;
use utils::{debug_assert_or_log, ensure, newtype};

use super::{Fee, Time, TxEntry, TxEntryWithFee};

use crate::{
    FeeRate, MempoolConfig,
    error::{MempoolPolicyError, MempoolStoreError, MempoolStoreInvariantError},
    pool::{
        dependency::{TxConsumedDependency, TxProvidedDependency, TxRequiredDependency},
        tx_pool::store::mem_usage::MemUsageTracker,
    },
};

pub use mem_usage::Tracked;

// The HashMap and HashSet used by MempoolStore. We use those from hashbrown because it's easier
// to estimate their memory usage, see the corresponding comment in mem_usage.
// Note:
// 1. The standard hash containers also use the hashbrown crate under the hood (e.g. std lib 1.95
//    uses hashbrown 0.16.1), but hashbrown's default hasher is weaker compared to SipHash, which
//    is used in the std lib. We want to continue using SipHash, so we parameterize the hashbrown
//    containers with the std lib's `RandomState`.
// 2. The hashbrown containers only define the `new` method in the `DefaultHashBuilder` case,
//    so we can't use it. But `Default` is still implemented.
//    Same for `with_capacity` (use `with_capacity_and_hasher(cap, Default::default())` instead).
pub type StoreHashMap<K, V> =
    hashbrown::hash_map::HashMap<K, V, std::collections::hash_map::RandomState>;
pub type StoreHashSet<K> = hashbrown::hash_set::HashSet<K, std::collections::hash_map::RandomState>;

newtype! {
    /// A set of ids of in-mempool (or "unconfirmed") ancestors of a certain tx.
    #[derive(Debug)]
    pub struct Ancestors(StoreHashSet<Id<Transaction>>);
}

newtype! {
    /// A set of ids of descendants of a certain tx.
    #[derive(Debug)]
    pub struct Descendants(StoreHashSet<Id<Transaction>>);
}

newtype! {
    /// A set of ids of txs that will form a cluster after a certain new tx is added to the mempool
    /// (the new tx id itself is not included).
    ///
    /// A cluster is a connected component of the in-mempool dependency graph.
    #[derive(Debug)]
    pub struct NewTxCluster(StoreHashSet<Id<Transaction>>);
}

newtype! {
    /// A set of ids of txs that currently form a cluster in the mempool.
    #[derive(Debug)]
    pub struct Cluster(StoreHashSet<Id<Transaction>>);
}

newtype! {
    #[derive(Debug)]
    pub struct Conflicts(StoreHashSet<Id<Transaction>>);
}

newtype! {
    #[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Clone, Copy)]
    pub struct DescendantScore(FeeRate);
}

impl DescendantScore {
    /// Converts a `DescendantScore` to a `FeeRate` using a minimum fee rate as a lower bound.
    pub fn to_feerate(self, min_feerate: FeeRate) -> FeeRate {
        std::cmp::max(self.0, min_feerate)
    }
}

newtype! {
    #[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
    pub struct AncestorScore(FeeRate);
}

#[cfg(test)]
pub type StrictDropPolicy = mem_usage::AssertDropPolicy;
#[cfg(not(test))]
pub type StrictDropPolicy = mem_usage::NoOpDropPolicy;

pub type TrackedMap<K, V> = Tracked<BTreeMap<K, V>>;
pub type TrackedHashMap<K, V> = Tracked<StoreHashMap<K, V>>;
pub type TrackedSet<K> = Tracked<BTreeSet<K>>;
pub type TrackedTxIdMultiMap<K> = TrackedSet<(K, Id<Transaction>)>;

#[derive(Debug)]
pub struct MempoolStore {
    /// Mempool config
    mempool_config: Arc<MempoolConfig>,

    // This is the "main" data structure storing Mempool entries. All other structures in the
    // MempoolStore contain ids (hashes) of entries, sorted according to some order of interest.
    // (Note: TxMempoolEntry is boxed, because the hashbrown table stores items directly
    // and doesn't free the memory when an item is removed - it's only replaced with a tombstone.
    // Since TxMempoolEntry is relatively big (size_of = 350+ bytes), we'd waste a noticeable
    // amount of memory without boxing.)
    txs_by_id: TrackedHashMap<Id<Transaction>, Tracked<Box<TxMempoolEntry>, StrictDropPolicy>>,

    // Mempool entries sorted by descendant score.
    // We keep this index so that when the mempool grows full, we know which transactions are the
    // most economically reasonable to evict. When an entry is removed from the mempool for
    // fullness reasons, it must be removed together with all of its descendants (as these descendants
    // would no longer be valid to mine). Entries with a lower descendant score will be evicted
    // first.
    // The descendant score of an entry is defined as:
    //  max(fee/size of entry's tx, fee/size with all descendants).
    //  TODO if we wish to follow Bitcoin Core, "size" is not simply the encoded size, but
    // rather a value that takes into account witness and sigop data (see CTxMemPoolEntry::GetTxSize).
    txs_by_descendant_score: TrackedTxIdMultiMap<DescendantScore>,

    // Mempool entries sorted by ancestor score.
    // This is used to select the most economically attractive transactions for block production.
    // The ancestor score of an entry is defined as
    //  min(fee/size of entry's tx, fee/size with all ancestors).
    txs_by_ancestor_score: TrackedTxIdMultiMap<AncestorScore>,

    // Entries that have remained in the mempool for a long time (see DEFAULT_MEMPOOL_EXPIRY) are
    // evicted. To efficiently know which entries to evict, we store the mempool entries sorted by
    // their creation time, from earliest to latest.
    txs_by_creation_time: TrackedTxIdMultiMap<Time>,

    // We keep the information of which inputs are spent by entries currently in the mempool.
    // This allows us to recognize conflicts (double-spends) and handle them.
    spender_txs: Tracked<BTreeMap<TxConsumedDependency, Id<Transaction>>>,

    // Map from a provided dependency to the tx that provides it.
    provider_txs: Tracked<BTreeMap<TxProvidedDependency, Id<Transaction>>>,

    // Track transactions by internal unique sequence number. This is used to recover the order in
    // which the transactions have been inserted into the mempool, so they can be re-inserted in
    // the same order after a reorg. We keep both mapping from transactions to sequence numbers and
    // the mapping from sequence number back to transaction. The sequence number to be allocated to
    // the next incoming transaction is kept separately.
    txs_by_seq_no: TrackedMap<usize, Id<Transaction>>,
    seq_nos_by_tx: TrackedHashMap<Id<Transaction>, usize>,
    next_seq_no: usize,

    /// Memory usage accumulator
    mem_tracker: mem_usage::MemUsageTracker,

    #[cfg(test)]
    heavy_validity_checks_enabled: bool,
}

// If a transaction is removed from the mempool for any reason other than inclusion in a block,
// then all its in-mempool descendants must be removed as well, and thus there is no need to update
// these descendants' ancestor data.
// Currently there is no special logic pertaining to the variants other than `Block`, but in the future we may
// want to add such logic. For example, Bitcoin Core has a `Conflict` variant for transactions removed from
// the mempool because they conflict with transactions in a new incoming block, and the wallet
// handles this variant differently from the others.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MempoolRemovalReason {
    Block,
    Expiry,
    SizeLimit,
    Replaced,
}

impl MempoolStore {
    pub fn new(mempool_config: Arc<MempoolConfig>) -> Self {
        Self {
            mempool_config,
            txs_by_descendant_score: Tracked::default(),
            txs_by_ancestor_score: Tracked::default(),
            txs_by_id: Tracked::default(),
            txs_by_creation_time: Tracked::default(),
            spender_txs: Tracked::default(),
            provider_txs: Tracked::default(),
            txs_by_seq_no: Tracked::default(),
            seq_nos_by_tx: Tracked::default(),
            next_seq_no: 0,
            mem_tracker: mem_usage::MemUsageTracker::new(),
            #[cfg(test)]
            heavy_validity_checks_enabled: true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.txs_by_id.is_empty()
    }

    pub fn get_entry(&self, id: &Id<Transaction>) -> Option<&TxMempoolEntry> {
        self.txs_by_id.get(id).map(|tx| tx.as_ref())
    }

    /// A helper function to reduce the noise of error mapping.
    ///
    /// The tx is supposed to be present in the mempool by construction, so it's an invariant
    /// error if it's not found.
    pub fn get_existing_entry(
        &self,
        id: &Id<Transaction>,
    ) -> Result<&TxMempoolEntry, MempoolStoreInvariantError> {
        self.get_entry(id)
            .ok_or(MempoolStoreInvariantError::SupposedlyExistingEntryNotFound(
                *id,
            ))
    }

    /// A helper function to reduce the noise of error mapping.
    ///
    /// The tx id is supposed to come from user code, so it's not an invariant violation if
    /// the tx can't be found.
    pub fn get_specified_entry(
        &self,
        id: &Id<Transaction>,
    ) -> Result<&TxMempoolEntry, MempoolStoreError> {
        self.get_entry(id).ok_or(MempoolStoreError::TxEntryNotFound(*id))
    }

    pub fn contains(&self, id: &Id<Transaction>) -> bool {
        self.txs_by_id.contains_key(id)
    }

    pub fn memory_usage(&self) -> usize {
        self.mem_tracker.get_usage()
    }

    pub fn txs_by_id(
        &self,
    ) -> &TrackedHashMap<Id<Transaction>, Tracked<Box<TxMempoolEntry>, StrictDropPolicy>> {
        &self.txs_by_id
    }

    pub fn txs_by_descendant_score(&self) -> &TrackedTxIdMultiMap<DescendantScore> {
        &self.txs_by_descendant_score
    }

    pub fn txs_by_ancestor_score(&self) -> &TrackedTxIdMultiMap<AncestorScore> {
        &self.txs_by_ancestor_score
    }

    pub fn txs_by_creation_time(&self) -> &TrackedTxIdMultiMap<Time> {
        &self.txs_by_creation_time
    }

    #[cfg(test)]
    pub fn seq_nos_by_tx(&self) -> &TrackedHashMap<Id<Transaction>, usize> {
        &self.seq_nos_by_tx
    }

    pub fn assert_valid(&self) {
        #[cfg(test)]
        self.assert_valid_inner()
    }

    #[cfg(test)]
    pub fn disable_heavy_validity_checks(&mut self) {
        self.heavy_validity_checks_enabled = false;
    }

    #[cfg(test)]
    fn assert_valid_inner(&self) {
        if !self.heavy_validity_checks_enabled {
            return;
        }

        use mem_usage::MemoryUsage;
        fn hash_map_size_deep<K: Eq + std::hash::Hash, V: MemoryUsage, D>(
            map: &StoreHashMap<K, Tracked<V, D>>,
        ) -> usize {
            let vals_size = map.values().map(|v| v.indirect_memory_usage()).sum::<usize>();
            map.indirect_memory_usage() + vals_size
        }

        let expected_size = hash_map_size_deep(&self.txs_by_id)
            + self.txs_by_descendant_score.indirect_memory_usage()
            + self.txs_by_ancestor_score.indirect_memory_usage()
            + self.txs_by_creation_time.indirect_memory_usage()
            + self.spender_txs.indirect_memory_usage()
            + self.provider_txs.indirect_memory_usage()
            + self.txs_by_seq_no.indirect_memory_usage()
            + self.seq_nos_by_tx.indirect_memory_usage();
        assert_eq!(
            self.mem_tracker.get_usage(),
            expected_size,
            "Memory size tracker out of sync",
        );

        let entries: Vec<_> = self.txs_by_descendant_score.iter().map(|(_, id)| id).collect();

        for id in self.txs_by_id.keys() {
            assert_eq!(
                entries.iter().filter(|entry_id| ***entry_id == *id).count(),
                1
            )
        }

        for entry in self.txs_by_id.values() {
            for child in &entry.children {
                assert!(self.txs_by_id.get(child).expect("child").parents.contains(entry.tx_id()))
            }
        }
    }

    fn append_to_parents(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
            for parent_id in entry.parents() {
                tracker.modify(
                    txs_by_id.get_mut(parent_id).expect("append_to_parents"),
                    |parent, _| parent.get_children_mut().insert(*entry.tx_id()),
                );
            }
        })
    }

    fn remove_from_parents(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
            for parent_id in entry.parents() {
                tracker.modify(
                    txs_by_id.get_mut(parent_id).expect("remove_from_parents"),
                    |parent, _| parent.get_children_mut().remove(entry.tx_id()),
                );
            }
        })
    }

    fn remove_from_children(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
            for child_id in entry.children() {
                tracker.modify(
                    txs_by_id.get_mut(child_id).expect("remove_from_children"),
                    |child, _| child.get_parents_mut().remove(entry.tx_id()),
                );
            }
        })
    }

    fn update_ancestor_state_for_add(
        &mut self,
        entry_with_ancestors: &TxMempoolEntryWithAncestors,
    ) -> Result<(), MempoolPolicyError> {
        let entry = entry_with_ancestors.entry();
        let ancestors = entry_with_ancestors.ancestors();

        for ancestor_id in &ancestors.0 {
            self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
                tracker.modify(
                    txs_by_id.get_mut(ancestor_id).expect("ancestor"),
                    |ancestor, tracker| -> Result<(), MempoolPolicyError> {
                        let old_descendant_score = ancestor.descendant_score();

                        let total_fee = (ancestor.fees_with_descendants + entry.fee)
                            .ok_or(MempoolPolicyError::AncestorFeeUpdateOverflow)?;
                        ancestor.fees_with_descendants = total_fee;
                        ancestor.size_with_descendants = entry
                            .size()
                            .checked_add(ancestor.size_with_descendants.get())
                            .expect("non-zero size");
                        ancestor.count_with_descendants += 1;

                        let new_descendant_score = ancestor.descendant_score();

                        Self::replace_in_descendant_score_index(
                            tracker,
                            &mut self.txs_by_descendant_score,
                            *ancestor.tx_id(),
                            old_descendant_score,
                            new_descendant_score,
                        );

                        Ok(())
                    },
                )
            })?;
        }

        Ok(())
    }

    fn update_ancestor_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for ancestor in entry.collect_ancestors(self).0 {
            self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
                tracker.modify(
                    txs_by_id.get_mut(&ancestor).expect("ancestor"),
                    |ancestor, tracker| {
                        let old_descendant_score = ancestor.descendant_score();

                        ancestor.fees_with_descendants = (ancestor.fees_with_descendants
                            - entry.fee)
                            .expect("fee with descendants");
                        let size_desc = ancestor.size_with_descendants.get() - entry.size().get();
                        ancestor.size_with_descendants =
                            NonZeroUsize::new(size_desc).expect("non-zero size");
                        ancestor.count_with_descendants -= 1;

                        let new_descendant_score = ancestor.descendant_score();

                        Self::replace_in_descendant_score_index(
                            tracker,
                            &mut self.txs_by_descendant_score,
                            *ancestor.tx_id(),
                            old_descendant_score,
                            new_descendant_score,
                        );
                    },
                )
            })
        }
    }

    fn mark_outpoints_as_spent(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.spender_txs, |spender_txs, _| {
            spender_txs.extend(
                entry
                    .tx_entry()
                    .requires()
                    .filter_map(TxRequiredDependency::into_consumed)
                    .map(|dep| (dep, *entry.tx_id())),
            );
        })
    }

    fn unspend_outpoints(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.spender_txs, |spender_txs, _| {
            entry.tx_entry().requires().for_each(|dep| {
                if let Some(dep) = dep.into_consumed() {
                    let removed = spender_txs.remove(&dep);
                    assert_eq!(removed, Some(*entry.tx_id()));
                }
            });
        })
    }

    pub fn add_transaction(&mut self, entry: TxEntryWithFee) -> Result<(), MempoolPolicyError> {
        let entry_with_ancestors = TxMempoolEntryWithAncestors::new(&*self, entry)?;
        self.add_tx_entry(entry_with_ancestors)
    }

    pub fn add_tx_entry(
        &mut self,
        entry_with_ancestors: TxMempoolEntryWithAncestors,
    ) -> Result<(), MempoolPolicyError> {
        let entry = entry_with_ancestors.entry();
        self.append_to_parents(entry);
        self.update_ancestor_state_for_add(&entry_with_ancestors)?;
        self.mark_outpoints_as_spent(entry);
        self.add_to_provider_txs(entry);

        let tx_id = *entry.tx_id();
        let seq_no = self.next_seq_no;
        self.next_seq_no += 1;

        self.add_to_descendant_score_index(entry);
        self.add_to_ancestor_score_index(entry);
        self.mem_tracker.modify(
            &mut self.txs_by_creation_time,
            |txs_by_creation_time, _tracker| {
                txs_by_creation_time.insert((entry.creation_time(), tx_id));
            },
        );

        self.mem_tracker.modify(&mut self.txs_by_seq_no, |m, _| m.insert(seq_no, tx_id));
        self.mem_tracker.modify(&mut self.seq_nos_by_tx, |m, _| m.insert(tx_id, seq_no));

        let entry = self.mem_tracker.track(Box::new(entry_with_ancestors.take_entry()));
        let prev = self.mem_tracker.modify(&mut self.txs_by_id, |m, _| m.insert(tx_id, entry));
        assert!(prev.is_none(), "Entry already in store");
        Ok(())
    }

    fn add_to_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(
            &mut self.txs_by_descendant_score,
            |by_desc_score, _tracker| {
                by_desc_score.insert((entry.descendant_score(), *entry.tx_id()));
            },
        );
    }

    fn add_to_ancestor_score_index(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker
            .modify(&mut self.txs_by_ancestor_score, |by_anc_score, _tracker| {
                by_anc_score.insert((entry.ancestor_score(), *entry.tx_id()));
            });
    }

    fn replace_in_descendant_score_index(
        tracker: &mut MemUsageTracker,
        txs_by_descendant_score: &mut TrackedTxIdMultiMap<DescendantScore>,
        ancestor_id: Id<Transaction>,
        old_score: DescendantScore,
        new_score: DescendantScore,
    ) {
        if new_score != old_score {
            tracker.modify(txs_by_descendant_score, |by_ds, _| {
                let removed = by_ds.remove(&(old_score, ancestor_id));
                debug_assert_or_log!(
                    removed,
                    "Ancestor with id {ancestor_id:x} was not present in txs_by_descendant_score",
                );
                by_ds.insert((new_score, ancestor_id));
            });
        }
    }

    fn replace_in_ancestor_score_index(
        tracker: &mut MemUsageTracker,
        txs_by_ancestor_score: &mut TrackedTxIdMultiMap<AncestorScore>,
        descendant_id: Id<Transaction>,
        old_score: AncestorScore,
        new_score: AncestorScore,
    ) {
        if new_score != old_score {
            tracker.modify(txs_by_ancestor_score, |by_as, _| {
                let removed = by_as.remove(&(old_score, descendant_id));
                debug_assert_or_log!(
                    removed,
                    "Descendant with id {descendant_id:x} was not present in txs_by_ancestor_score",
                );
                by_as.insert((new_score, descendant_id));
            });
        }
    }

    fn update_descendant_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for descendant_id in entry.collect_descendants(self).0 {
            self.mem_tracker.modify(&mut self.txs_by_id, |by_id, tracker| {
                tracker.modify(
                    by_id.get_mut(&descendant_id).expect("descendant"),
                    |descendant, tracker| {
                        let old_ancestor_score = descendant.ancestor_score();

                        descendant.fees_with_ancestors = (descendant.fees_with_ancestors
                            - entry.fee)
                            .expect("fee with descendants");
                        let size_anc = descendant.size_with_ancestors.get() - entry.size().get();
                        descendant.size_with_ancestors =
                            NonZeroUsize::new(size_anc).expect("non-zero size");
                        descendant.count_with_ancestors -= 1;

                        let new_ancestor_score = descendant.ancestor_score();

                        Self::replace_in_ancestor_score_index(
                            tracker,
                            &mut self.txs_by_ancestor_score,
                            *descendant.tx_id(),
                            old_ancestor_score,
                            new_ancestor_score,
                        );
                    },
                )
            })
        }
    }

    pub fn remove_tx(
        &mut self,
        tx_id: &Id<Transaction>,
        reason: MempoolRemovalReason,
    ) -> Option<TxMempoolEntry> {
        log::debug!("remove_tx: {:x}", tx_id.to_hash());
        let entry = self.mem_tracker.modify(&mut self.txs_by_id, |by_id, _| by_id.remove(tx_id));

        if let Some(entry) = entry {
            let entry = self.mem_tracker.release(entry);
            self.update_ancestor_state_for_drop(&entry);
            if reason == MempoolRemovalReason::Block {
                self.update_descendant_state_for_drop(&entry)
            }
            self.drop_tx(&entry);
            Some(*entry)
        } else {
            //  FIXME: debug assert?
            assert!(!self.txs_by_descendant_score.iter().any(|(_, id)| id == tx_id));
            assert!(!self.spender_txs.iter().any(|(_, id)| *id == *tx_id));
            assert!(!self.provider_txs.iter().any(|(_, id)| *id == *tx_id));
            None
        }
    }

    fn update_for_drop(&mut self, entry: &TxMempoolEntry) {
        self.remove_from_parents(entry);
        self.remove_from_children(entry);
    }

    fn drop_tx(&mut self, entry: &TxMempoolEntry) {
        self.update_for_drop(entry);
        self.remove_from_descendant_score_index(entry);
        self.remove_from_ancestor_score_index(entry);
        self.remove_from_creation_time_index(entry);
        self.remove_from_seq_no_index(entry);
        self.remove_from_provider_txs(entry);
        self.unspend_outpoints(entry);
    }

    fn remove_from_ancestor_score_index(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.txs_by_ancestor_score, |by_as, _tracker| {
            by_as.remove(&(entry.ancestor_score(), *entry.tx_id()));
        })
    }

    fn remove_from_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.txs_by_descendant_score, |by_ds, _tracker| {
            by_ds.remove(&(entry.descendant_score(), *entry.tx_id()));
        })
    }

    fn remove_from_creation_time_index(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.txs_by_creation_time, |by_ct, _tracker| {
            by_ct.remove(&(entry.creation_time(), *entry.tx_id()));
        })
    }

    fn remove_from_seq_no_index(&mut self, entry: &TxMempoolEntry) {
        let tx_id = entry.tx_id();
        let seq = self.mem_tracker.modify(&mut self.seq_nos_by_tx, |sn, _| sn.remove(tx_id));
        let seq = seq.expect("Seq no for given transaction must exist");
        let tx_id_seq = self.mem_tracker.modify(&mut self.txs_by_seq_no, |txs, _| txs.remove(&seq));
        assert_eq!(tx_id_seq, Some(*tx_id), "Inconsistent transaction seq nos");
    }

    fn add_to_provider_txs(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.provider_txs, |provider_txs, _| {
            provider_txs.extend(entry.tx_entry().provides().map(|dep| (dep, *entry.tx_id())));
        })
    }

    fn remove_from_provider_txs(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.provider_txs, |provider_txs, _| {
            entry.tx_entry().provides().for_each(|dep| {
                let removed = provider_txs.remove(&dep);
                assert_eq!(removed, Some(*entry.tx_id()));
            });
        })
    }

    pub fn drop_conflicts(&mut self, conflicts: Conflicts) {
        for conflict in conflicts.0 {
            self.remove_tx(&conflict, MempoolRemovalReason::Replaced);
        }
    }

    // Remove given transaction and its descendants. Return the IDs of the removed transactions
    pub fn drop_tx_and_descendants(
        &mut self,
        tx_id: &Id<Transaction>,
        reason: MempoolRemovalReason,
    ) -> impl Iterator<Item = TxMempoolEntry> + '_ {
        let to_remove: Vec<_> = self
            .txs_by_id
            .get(tx_id)
            .map(|entry| entry.depth_postorder_descendants(self).map(|e| *e.tx_id()).collect())
            .unwrap_or_default();
        to_remove.into_iter().filter_map(move |tx_id| self.remove_tx(&tx_id, reason))
    }

    pub fn find_conflicting_tx(&self, dep: &TxConsumedDependency) -> Option<&Id<Transaction>> {
        self.spender_txs.get(dep)
    }

    /// Take all the transactions from the store in the original order of insertion
    pub fn into_transactions(mut self) -> impl Iterator<Item = TxEntry> {
        use mem_usage::MemUsageTracker;

        let mut txs_by_id = MemUsageTracker::forget(std::mem::take(&mut self.txs_by_id));
        let txs_by_seq_no = MemUsageTracker::forget(std::mem::take(&mut self.txs_by_seq_no));

        txs_by_seq_no.into_values().map(move |id| {
            MemUsageTracker::forget(txs_by_id.remove(&id).expect("entry must be present")).entry
        })
    }

    /// Collect all ancestors of the specified existing transaction.
    /// Mainly intended for testing.
    pub fn collect_ancestors(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Ancestors, MempoolPolicyError> {
        let entry = self.get_existing_entry(tx_id)?;
        Ok(entry.collect_ancestors(self))
    }

    /// Collect all descendants of the specified existing transaction.
    /// Mainly intended for testing.
    pub fn collect_descendants(
        &self,
        tx_id: &Id<Transaction>,
    ) -> Result<Descendants, MempoolPolicyError> {
        let entry = self.get_existing_entry(tx_id)?;
        Ok(entry.collect_descendants(self))
    }

    /// Collect the cluster that the specified existing transaction belongs to.
    /// Mainly intended for testing.
    pub fn collect_cluster(&self, tx_id: &Id<Transaction>) -> Result<Cluster, MempoolPolicyError> {
        let entry = self.get_existing_entry(tx_id)?;
        entry.collect_cluster(self)
    }

    /// For internal containers that have capacity, check if the capacity is excessive; shrink
    /// the container if it is.
    pub fn shrink_capacity_if_needed(&mut self) {
        // Note:
        // * Hashbrown tables never shrink their capacity automatically.
        // * According to the pseudo-test `estimate_max_tx_count_in_store`, the store with the default
        //   size of 300Mb can fit over 230'000 txs of the smallest possible size. Due to how hashbrown
        //   tables work (1/8 of all buckets should always be empty, and reallocation doubles the number
        //   of buckets), `txs_by_id` and `seq_nos_by_tx` may end up with more than 500'000 buckets each.
        //   Given that the bucket size in each table is 40 bytes (in non-test builds), this results in
        //   roughly 20Mb of allocated memory per table, which will not go down even if the tables'
        //   element counts become zero. Since table's entire allocation_size counts towards the
        //   mempool size, this will effectively reduce the max mempool size by 40Mb.
        // * On the other hand, the mempool re-creates its store completely every time a new block
        //   arrives, so the situation described above can only exist for a few minutes. Still,
        //   it's better for the store not to depend on such a behavior of its owner code and
        //   manage the capacities explicitly.

        // Implementation notes:
        // * table's `capacity` doesn't count the tombstones, so in a degenerate case like the one
        //   described above it's possible to have a table with a huge allocation size and small
        //   capacity. So below we don't use capacity when deciding whether to shrink, and estimate
        //   (roughly) the number of buckets instead.
        // * even though `shrink_to` accepts capacity, it'll compare the estimated number of buckets
        //   (from the passed capacity) with the current one and reallocate/rehash the table if the
        //   latter is bigger.

        fn maybe_shrink<K, V>(
            table: &mut TrackedHashMap<K, V>,
            mem_tracker: &mut MemUsageTracker,
            table_name: &str,
        ) where
            K: Eq + std::hash::Hash,
        {
            let bucket_size = hash_map_bucket_size(table);
            let bucket_count = hash_map_bucket_count_upper_bound(table);

            let max_bucket_count = table.len() * HASH_TABLE_MAX_BUCKET_COUNT_FACTOR;
            let adjusted_capacity = table.len() * HASH_TABLE_ADJUSTED_CAPACITY_FACTOR;

            if bucket_count > max_bucket_count {
                let potentially_reclaimable_mem_size =
                    (bucket_count - adjusted_capacity) * bucket_size;

                // Only bother shrinking if the win is noticeable.
                if potentially_reclaimable_mem_size >= HASH_TABLE_MIN_RECLAIMABLE_MEM_SIZE {
                    log::debug!("Shrinking {table_name} to {adjusted_capacity}");
                    mem_tracker.modify(table, |table, _| table.shrink_to(adjusted_capacity));
                }
            }
        }

        maybe_shrink(&mut self.txs_by_id, &mut self.mem_tracker, "txs_by_id");
        maybe_shrink(
            &mut self.seq_nos_by_tx,
            &mut self.mem_tracker,
            "seq_nos_by_tx",
        );
    }
}

pub fn hash_map_bucket_size<K, V>(_: &StoreHashMap<K, V>) -> usize {
    std::mem::size_of::<(K, V)>()
}

// Return the upper bound for the number of buckets in the map.
pub fn hash_map_bucket_count_upper_bound<K, V>(map: &StoreHashMap<K, V>) -> usize
where
    K: Eq + std::hash::Hash,
{
    // Note: the actual number of buckets will be smaller than this, because `allocation_size` also
    // includes control bytes and padding.
    map.allocation_size() / hash_map_bucket_size(map)
}

// Constants that determine whether store's hash tables should be shrunk and, if yes, to what capacity.
pub const HASH_TABLE_MAX_BUCKET_COUNT_FACTOR: usize = 5;
pub const HASH_TABLE_ADJUSTED_CAPACITY_FACTOR: usize = 2;
pub const HASH_TABLE_MIN_RECLAIMABLE_MEM_SIZE: usize = 10_000;

#[cfg(test)]
impl Drop for MempoolStore {
    fn drop(&mut self) {
        // Clean up all the tracked stuff that could assert during testing. We do not miss any
        // memory size updates because the tracker is being destroyed at the same time.
        mem_usage::MemUsageTracker::forget(std::mem::take(&mut self.txs_by_id))
            .into_values()
            .for_each(|entry| std::mem::drop(mem_usage::MemUsageTracker::forget(entry)));
    }
}

// TODO: move TxMempoolEntry and TxMempoolEntryWithAncestors to a separate file.
#[derive(Debug, Eq, Clone)]
pub struct TxMempoolEntry {
    entry: TxEntry,
    fee: Fee,
    parents: StoreHashSet<Id<Transaction>>,
    children: StoreHashSet<Id<Transaction>>,
    count_with_descendants: usize,
    count_with_ancestors: usize,
    fees_with_descendants: Fee,
    fees_with_ancestors: Fee,
    size_with_descendants: NonZeroUsize,
    size_with_ancestors: NonZeroUsize,
}

impl TxMempoolEntry {
    fn new<'a>(
        entry: TxEntryWithFee,
        parents: StoreHashSet<Id<Transaction>>,
        ancestors: impl ExactSizeIterator<Item = &'a TxMempoolEntry>,
    ) -> Result<TxMempoolEntry, MempoolPolicyError> {
        let fee = entry.fee();
        let entry = entry.into_tx_entry();
        let size = entry.size();
        let ancestors_count = ancestors.len();

        let mut size_with_ancestors = size;
        let mut fees_with_ancestors = fee;

        for ancestor in ancestors {
            size_with_ancestors = size_with_ancestors
                .checked_add(ancestor.size().get())
                .expect("Sizes should not overflow");
            fees_with_ancestors = (fees_with_ancestors + ancestor.fee())
                .ok_or(MempoolPolicyError::AncestorFeeOverflow)?;
        }

        Ok(Self {
            size_with_ancestors,
            count_with_ancestors: 1 + ancestors_count,
            size_with_descendants: size,
            entry,
            fee,
            parents,
            children: StoreHashSet::default(),
            count_with_descendants: 1,
            fees_with_descendants: fee,
            fees_with_ancestors,
        })
    }

    #[cfg(test)]
    pub fn new_from_data(
        tx: SignedTransaction,
        fee: Fee,
        parents: StoreHashSet<Id<Transaction>>,
        ancestors: BTreeSet<TxMempoolEntry>,
        creation_time: Time,
    ) -> Result<TxMempoolEntry, MempoolPolicyError> {
        use crate::tx_origin::LocalTxOrigin;
        let origin = LocalTxOrigin::Mempool.into();
        let options = crate::TxOptions::default_for(origin);
        let entry = TxEntry::new(tx, creation_time, origin, options);
        Self::new(TxEntryWithFee::new(entry, fee), parents, ancestors.iter())
    }

    pub fn transaction(&self) -> &SignedTransaction {
        self.entry.transaction()
    }

    pub fn fee(&self) -> Fee {
        self.fee
    }

    pub fn count_with_descendants(&self) -> usize {
        self.count_with_descendants
    }

    #[cfg(test)]
    pub fn fees_with_descendants(&self) -> Fee {
        self.fees_with_descendants
    }

    #[cfg(test)]
    pub fn fees_with_ancestors(&self) -> Fee {
        self.fees_with_ancestors
    }

    pub fn descendant_score(&self) -> DescendantScore {
        let a = FeeRate::from_total_tx_fee(self.fees_with_descendants, self.size_with_descendants)
            .expect("cannot overflow due to max supply");
        let b = FeeRate::from_total_tx_fee(self.fee, self.size())
            .expect("cannot overflow due to max supply");
        std::cmp::max(a, b).into()
    }

    pub fn ancestor_score(&self) -> AncestorScore {
        log::debug!(
            "fees with ancestors: {:?}, size_with_ancestors: {}, fee: {:?}, size: {}",
            self.fees_with_ancestors,
            self.size_with_ancestors,
            self.fee,
            self.size(),
        );
        let a = FeeRate::from_total_tx_fee(self.fees_with_ancestors, self.size_with_ancestors)
            .expect("cannot overflow due to max supply");
        let b = FeeRate::from_total_tx_fee(self.fee, self.size())
            .expect("cannot overflow due to max supply");
        let score = std::cmp::min(a, b).into();

        log::debug!("ancestor score for {:x}: {score:?}", self.tx_id());
        score
    }

    pub fn tx_id(&self) -> &Id<Transaction> {
        self.entry.tx_id()
    }

    pub fn tx_entry(&self) -> &TxEntry {
        &self.entry
    }

    pub fn size(&self) -> NonZeroUsize {
        self.entry.size()
    }

    pub fn creation_time(&self) -> Time {
        self.entry.creation_time()
    }

    // Note: only the parents that are currently in the mempool are included here (i.e. the
    // "unconfirmed" parents).
    pub fn parents(&self) -> impl Iterator<Item = &Id<Transaction>> {
        self.parents.iter()
    }

    pub fn children(&self) -> impl Iterator<Item = &Id<Transaction>> {
        self.children.iter()
    }

    fn get_children_mut(&mut self) -> &mut StoreHashSet<Id<Transaction>> {
        &mut self.children
    }

    fn get_parents_mut(&mut self) -> &mut StoreHashSet<Id<Transaction>> {
        &mut self.parents
    }

    pub fn is_replaceable(&self, store: &MempoolStore) -> bool {
        self.entry.transaction().is_replaceable()
            || self.collect_ancestors(store).0.iter().any(|ancestor| {
                store.get_entry(ancestor).expect("entry").entry.transaction().is_replaceable()
            })
    }

    pub fn depth_postorder_descendants<'a>(
        &'a self,
        store: &'a MempoolStore,
    ) -> impl Iterator<Item = &'a TxMempoolEntry> {
        let children_fn = |entry: &&'a TxMempoolEntry| {
            entry
                .children
                .iter()
                .map(|id| store.get_entry(id).expect("child must be present"))
        };
        utils::graph_traversals::dag_depth_postorder(self, children_fn)
    }

    /// Collect ancestors of this transaction.
    ///
    /// The transaction itself may not be in the store.
    pub fn collect_ancestors(&self, store: &MempoolStore) -> Ancestors {
        let result = collect_relatives(
            store,
            self.parents.iter().copied(),
            RelativesKind::Ancestors,
            |_| Ok::<_, MempoolStoreInvariantError>(()),
            Some(self.count_with_ancestors - 1),
        );

        match result {
            Ok(ancestors) => Ancestors::new(ancestors),
            Err(MempoolStoreInvariantError::SupposedlyExistingEntryNotFound(tx_id)) => {
                // Note: this panic existed here for ages, but in the form of a direct call
                // of `expect` after `get_entry`.
                // TODO: it's better to get rid of this panic and all `get_entry().expect()`
                // calls, which are still abundant.
                panic!("Tx with id {tx_id:x} not found in mempool");
            }
        }
    }

    /// Collect descendants of this transaction.
    ///
    /// The transaction itself may not be in the store.
    pub fn collect_descendants(&self, store: &MempoolStore) -> Descendants {
        let result = collect_relatives(
            store,
            self.children.iter().copied(),
            RelativesKind::Descendants,
            |_| Ok::<_, MempoolStoreInvariantError>(()),
            Some(self.count_with_descendants - 1),
        );

        match result {
            Ok(descendants) => Descendants::new(descendants),
            Err(MempoolStoreInvariantError::SupposedlyExistingEntryNotFound(tx_id)) => {
                // Same note/TODO as in collect_ancestors.
                panic!("Tx with id {tx_id:x} not found in mempool");
            }
        }
    }

    /// Collect the cluster that this transaction belongs to.
    ///
    /// The transaction itself *must* be in the store.
    ///
    /// This function is mainly intended for testing purposes.
    pub fn collect_cluster(&self, store: &MempoolStore) -> Result<Cluster, MempoolPolicyError> {
        let cluster = collect_relatives(
            store,
            [*self.tx_id()],
            RelativesKind::Cluster,
            |_| Ok::<_, MempoolPolicyError>(()),
            Some(self.count_with_ancestors + self.count_with_descendants - 1),
        )?;

        Ok(Cluster::new(cluster))
    }
}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for TxMempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(other.tx_id().cmp(self.tx_id()))
    }
}

impl PartialEq for TxMempoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.tx_id() == other.tx_id()
    }
}

impl Ord for TxMempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.tx_id().cmp(self.tx_id())
    }
}

/// A helper struct that encapsulates a newly created `TxMempoolEntry` and its ancestors.
pub struct TxMempoolEntryWithAncestors {
    entry: TxMempoolEntry,
    ancestors: Ancestors,
}

impl TxMempoolEntryWithAncestors {
    pub fn new(store: &MempoolStore, entry: TxEntryWithFee) -> Result<Self, MempoolPolicyError> {
        let parents = collect_tx_parents(store, entry.tx_entry());

        // Collect the cluster first, checking its size on each iteration.
        // After that, the ancestors may be collected without the tx count check.
        // Note: it's technically possible to unite ancestor and cluster collecting, to reduce
        // the total number of steps during traversal. But it's probably not worth the extra
        // complexity.
        let cluster = NewTxCluster::new(collect_relatives(
            store,
            parents.iter().copied(),
            RelativesKind::Cluster,
            |collected_size| {
                ensure_cluster_tx_count_limit(&store.mempool_config, 1 + collected_size)
            },
            None,
        )?);
        enforce_cluster_size_limit(store, &entry, &cluster)?;

        let ancestors = Ancestors::new(collect_relatives(
            store,
            parents.iter().copied(),
            RelativesKind::Ancestors,
            |_| Ok::<_, MempoolPolicyError>(()),
            None,
        )?);

        let ancestor_entries_iter = ancestors
            .deref()
            .iter()
            .map(|id| store.get_entry(id).expect("ancestors to exist"));

        let entry = TxMempoolEntry::new(entry, parents, ancestor_entries_iter)?;
        Ok(Self { entry, ancestors })
    }

    #[cfg(test)]
    pub fn new_from_existing_entry(store: &MempoolStore, entry: TxMempoolEntry) -> Self {
        let ancestors = entry.collect_ancestors(store);
        Self { entry, ancestors }
    }

    pub fn entry(&self) -> &TxMempoolEntry {
        &self.entry
    }

    pub fn take_entry(self) -> TxMempoolEntry {
        self.entry
    }

    pub fn ancestors(&self) -> &Ancestors {
        &self.ancestors
    }
}

#[derive(Clone, Copy)]
pub enum RelativesKind {
    Ancestors,
    Descendants,
    Cluster,
}

/// Collect relatives of the specified "initial" transactions.
///
/// At the end the result will contain the initial tx ids and, depending on `kind`:
/// a) their ancestors,
/// b) their descendants,
/// c) the union of clusters that they belong to (if initial_tx_ids are parents of a new tx,
///    then it's the cluster that will form after the tx is added to the mempool).
///
/// After each tx is added to the result, `on_new_tx_added` is called with the current size
/// of the result as the argument.
///
/// `expected_result_size`, if specified, is used to reserve the needed capacity in the result
/// to avoid redundant reallocations.
pub fn collect_relatives<E>(
    store: &MempoolStore,
    initial_tx_ids: impl IntoIterator<Item = Id<Transaction>>,
    kind: RelativesKind,
    mut on_new_tx_added: impl FnMut(/*cur_result_size:*/ usize) -> Result<(), E>,
    expected_result_size: Option<usize>,
) -> Result<StoreHashSet<Id<Transaction>>, E>
where
    E: From<MempoolStoreInvariantError>,
{
    let initial_tx_ids = initial_tx_ids.into_iter();
    let initial_tx_ids_min_size_hint = initial_tx_ids.size_hint().0;
    let expected_result_size = expected_result_size.unwrap_or(initial_tx_ids_min_size_hint);

    let mut stack = Vec::with_capacity(initial_tx_ids_min_size_hint);
    let mut result =
        StoreHashSet::with_capacity_and_hasher(expected_result_size, Default::default());

    let mut visit = |stack: &mut Vec<Id<Transaction>>, tx_id: &Id<Transaction>| -> Result<(), E> {
        if result.insert(*tx_id) {
            on_new_tx_added(result.len())?;
            stack.push(*tx_id);
        }
        Ok(())
    };

    for tx_id in initial_tx_ids {
        visit(&mut stack, &tx_id)?;
    }

    while let Some(tx_id) = stack.pop() {
        let entry = store.get_existing_entry(&tx_id)?;

        let (iter1, iter2) = match kind {
            RelativesKind::Ancestors => (Some(entry.parents()), None),
            RelativesKind::Descendants => (None, Some(entry.children())),
            RelativesKind::Cluster => (Some(entry.parents()), Some(entry.children())),
        };
        for tx_id in iter1.into_iter().flatten().chain(iter2.into_iter().flatten()) {
            visit(&mut stack, tx_id)?;
        }
    }

    Ok(result)
}

fn collect_tx_parents(store: &MempoolStore, entry: &TxEntry) -> StoreHashSet<Id<Transaction>> {
    entry
        .requires()
        .filter_map(|required_dep| {
            let provided_dep = TxProvidedDependency::from_requirement(required_dep);
            store.provider_txs.get(&provided_dep)
        })
        .copied()
        .collect()
}

fn ensure_cluster_tx_count_limit(
    mempool_config: &MempoolConfig,
    cluster_size: usize,
) -> Result<(), MempoolPolicyError> {
    let limit = *mempool_config.max_cluster_tx_count;
    ensure!(
        cluster_size <= limit,
        MempoolPolicyError::ClusterMaxTxCountLimitViolated { limit }
    );
    Ok(())
}

fn enforce_cluster_size_limit(
    store: &MempoolStore,
    new_tx_entry: &TxEntryWithFee,
    cluster: &NewTxCluster,
) -> Result<(), MempoolPolicyError> {
    let cluster_size_bytes = {
        let mut total_size = new_tx_entry.tx_entry().size().get();

        for tx_id in cluster.iter() {
            let entry = store.get_existing_entry(tx_id)?;
            total_size += entry.size().get();
        }

        total_size
    };

    let limit = *store.mempool_config.max_cluster_size_bytes;
    ensure!(
        cluster_size_bytes <= limit,
        MempoolPolicyError::ClusterTotalTxSizeLimitViolated {
            actual_size: cluster_size_bytes,
            limit
        }
    );

    Ok(())
}
