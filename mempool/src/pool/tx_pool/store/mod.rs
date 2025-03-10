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
};

use common::{
    chain::{SignedTransaction, Transaction, TxInput},
    primitives::Id,
};
use logging::log;
use utils::newtype;

use super::{Fee, Time, TxEntry, TxEntryWithFee};
use crate::{error::MempoolPolicyError, pool::entry::TxDependency, FeeRate};
use mem_usage::Tracked;

newtype! {
    #[derive(Debug)]
    pub struct Ancestors(BTreeSet<Id<Transaction>>);
}

impl Ancestors {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

newtype! {
    #[derive(Debug)]
    pub struct Descendants(BTreeSet<Id<Transaction>>);
}

newtype! {
    #[derive(Debug)]
    pub struct Conflicts(BTreeSet<Id<Transaction>>);
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
type StrictDropPolicy = mem_usage::AssertDropPolicy;
#[cfg(not(test))]
type StrictDropPolicy = mem_usage::NoOpDropPolicy;

type TrackedMap<K, V> = Tracked<BTreeMap<K, V>>;
type TrackedSet<K> = Tracked<BTreeSet<K>>;
type TrackedTxIdMultiMap<K> = TrackedSet<(K, Id<Transaction>)>;

#[derive(Debug)]
pub struct MempoolStore {
    // This is the "main" data structure storing Mempool entries. All other structures in the
    // MempoolStore contain ids (hashes) of entries, sorted according to some order of interest.
    pub txs_by_id: TrackedMap<Id<Transaction>, Tracked<TxMempoolEntry, StrictDropPolicy>>,

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
    pub txs_by_descendant_score: TrackedTxIdMultiMap<DescendantScore>,

    // Mempool entries sorted by ancestor score.
    // This is used to select the most economically attractive transactions for block production.
    // The ancestor score of an entry is defined as
    //  min(score/size of entry's tx, score/size with all ancestors).
    pub txs_by_ancestor_score: TrackedTxIdMultiMap<AncestorScore>,

    // Entries that have remained in the mempool for a long time (see DEFAULT_MEMPOOL_EXPIRY) are
    // evicted. To efficiently know which entries to evict, we store the mempool entries sorted by
    // their creation time, from earliest to latest.
    pub txs_by_creation_time: TrackedTxIdMultiMap<Time>,

    // We keep the information of which inputs are spent by entries currently in the mempool.
    // This allows us to recognize conflicts (double-spends) and handle them
    pub spender_txs: Tracked<BTreeMap<TxDependency, Id<Transaction>>>,

    // Track transactions by internal unique sequence number. This is used to recover the order in
    // which the transactions have been inserted into the mempool, so they can be re-inserted in
    // the same order after a reorg. We keep both mapping from transactions to sequence numbers and
    // the mapping from sequence number back to transaction. The sequence number to be allocated to
    // the next incoming transaction is kept separately.
    txs_by_seq_no: Tracked<BTreeMap<usize, Id<Transaction>>>,
    seq_nos_by_tx: Tracked<BTreeMap<Id<Transaction>, usize>>,
    next_seq_no: usize,

    /// Memory usage accumulator
    mem_tracker: mem_usage::MemUsageTracker,
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
    pub fn new() -> Self {
        Self {
            txs_by_descendant_score: Tracked::default(),
            txs_by_ancestor_score: Tracked::default(),
            txs_by_id: Tracked::default(),
            txs_by_creation_time: Tracked::default(),
            spender_txs: Tracked::default(),
            txs_by_seq_no: Tracked::default(),
            seq_nos_by_tx: Tracked::default(),
            next_seq_no: 0,
            mem_tracker: mem_usage::MemUsageTracker::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.txs_by_id.is_empty()
    }

    pub fn get_entry(&self, id: &Id<Transaction>) -> Option<&TxMempoolEntry> {
        self.txs_by_id.get(id).map(|tx| tx.deref())
    }

    pub fn contains(&self, id: &Id<Transaction>) -> bool {
        self.txs_by_id.contains_key(id)
    }

    pub fn memory_usage(&self) -> usize {
        self.mem_tracker.get_usage()
    }

    pub fn assert_valid(&self) {
        #[cfg(test)]
        self.assert_valid_inner()
    }

    #[cfg(test)]
    fn assert_valid_inner(&self) {
        use mem_usage::MemoryUsage;
        fn map_size_deep<K, V: MemoryUsage, D>(map: &BTreeMap<K, Tracked<V, D>>) -> usize {
            let vals_size = map.values().map(|v| v.indirect_memory_usage()).sum::<usize>();
            map.indirect_memory_usage() + vals_size
        }

        let expected_size = map_size_deep(&self.txs_by_id)
            + self.txs_by_descendant_score.indirect_memory_usage()
            + self.txs_by_ancestor_score.indirect_memory_usage()
            + self.txs_by_creation_time.indirect_memory_usage()
            + self.spender_txs.indirect_memory_usage()
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
        entry: &TxMempoolEntry,
    ) -> Result<(), MempoolPolicyError> {
        for ancestor_id in entry.unconfirmed_ancestors(self).0 {
            self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
                tracker.modify(
                    txs_by_id.get_mut(&ancestor_id).expect("ancestor"),
                    |ancestor, _| -> Result<(), MempoolPolicyError> {
                        let total_fee = (ancestor.fees_with_descendants + entry.fee)
                            .ok_or(MempoolPolicyError::AncestorFeeUpdateOverflow)?;
                        ancestor.fees_with_descendants = total_fee;
                        ancestor.size_with_descendants = entry
                            .size()
                            .checked_add(ancestor.size_with_descendants.get())
                            .expect("non-zero size");
                        ancestor.count_with_descendants += 1;
                        Ok(())
                    },
                )
            })?;
        }
        Ok(())
    }

    fn update_ancestor_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for ancestor in entry.unconfirmed_ancestors(self).0 {
            self.mem_tracker.modify(&mut self.txs_by_id, |txs_by_id, tracker| {
                tracker.modify(
                    txs_by_id.get_mut(&ancestor).expect("ancestor"),
                    |ancestor, _| {
                        ancestor.fees_with_descendants = (ancestor.fees_with_descendants
                            - entry.fee)
                            .expect("fee with descendants");
                        let size_desc = ancestor.size_with_descendants.get() - entry.size().get();
                        ancestor.size_with_descendants =
                            NonZeroUsize::new(size_desc).expect("non-zero size");
                        ancestor.count_with_descendants -= 1;
                    },
                )
            })
        }
    }

    fn mark_outpoints_as_spent(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.spender_txs, |spender_txs, _| {
            spender_txs.extend(entry.tx_entry().requires().map(|dep| (dep, *entry.tx_id())));
        })
    }

    fn unspend_outpoints(&mut self, entry: &TxMempoolEntry) {
        self.mem_tracker.modify(&mut self.spender_txs, |spender_txs, _| {
            entry.tx_entry().requires().for_each(|dep| {
                let removed = spender_txs.remove(&dep);
                assert_eq!(removed, Some(*entry.tx_id()));
            });
        })
    }

    pub fn add_transaction(&mut self, entry: TxEntryWithFee) -> Result<(), MempoolPolicyError> {
        // Genesis transaction has no parent, hence the first filter_map
        let parents = entry
            .transaction()
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(outpoint) => outpoint.source_id().get_tx_id().cloned(),
                TxInput::Account(..)
                | TxInput::AccountCommand(..)
                | TxInput::OrderAccountCommand(..) => None,
            })
            .filter(|id| self.txs_by_id.contains_key(id))
            .collect::<BTreeSet<_>>();
        let ancestor_ids = TxMempoolEntry::unconfirmed_ancestors_from_parents(&parents, self)?;
        let ancestors = BTreeSet::from(ancestor_ids)
            .into_iter()
            .map(|id| self.get_entry(&id).expect("ancestors to exist"))
            .cloned()
            .collect();

        let entry = TxMempoolEntry::new(entry, parents, ancestors)?;
        self.add_tx_entry(entry)
    }

    pub fn add_tx_entry(&mut self, entry: TxMempoolEntry) -> Result<(), MempoolPolicyError> {
        self.append_to_parents(&entry);
        self.update_ancestor_state_for_add(&entry)?;
        self.mark_outpoints_as_spent(&entry);

        let tx_id = *entry.tx_id();
        let seq_no = self.next_seq_no;
        self.next_seq_no += 1;

        self.add_to_descendant_score_index(&entry);
        self.add_to_ancestor_score_index(&entry);
        self.mem_tracker.modify(
            &mut self.txs_by_creation_time,
            |txs_by_creation_time, _tracker| {
                txs_by_creation_time.insert((entry.creation_time(), tx_id));
            },
        );

        self.mem_tracker.modify(&mut self.txs_by_seq_no, |m, _| m.insert(seq_no, tx_id));
        self.mem_tracker.modify(&mut self.seq_nos_by_tx, |m, _| m.insert(tx_id, seq_no));

        let entry = self.mem_tracker.track(entry);
        let prev = self.mem_tracker.modify(&mut self.txs_by_id, |m, _| m.insert(tx_id, entry));
        assert!(prev.is_none(), "Entry already in store");
        Ok(())
    }

    fn add_to_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_ancestors(entry);
        self.mem_tracker.modify(
            &mut self.txs_by_descendant_score,
            |by_desc_score, _tracker| {
                by_desc_score.insert((entry.descendant_score(), *entry.tx_id()));
            },
        );
    }

    fn add_to_ancestor_score_index(&mut self, entry: &TxMempoolEntry) {
        // TODO in the normal case of a new transaction arriving, there can't be any children
        // because such children would be orphans.
        // When we implement disconnecting a block, we'll need to clean up the mess we're leaving
        // here.
        self.mem_tracker
            .modify(&mut self.txs_by_ancestor_score, |by_anc_score, _tracker| {
                by_anc_score.insert((entry.ancestor_score(), *entry.tx_id()));
            });
    }

    fn refresh_ancestors(&mut self, entry: &TxMempoolEntry) {
        // Since the ancestors of `entry` have had their descendant score modified, their ordering
        // in txs_by_descendant_score may no longer be correct. We thus remove all ancestors and
        // reinsert them, taking the new, updated fees into account
        let ancestors = entry.unconfirmed_ancestors(self);
        self.mem_tracker.modify(&mut self.txs_by_descendant_score, |by_ds, _tracker| {
            by_ds.retain(|(_score, e)| !ancestors.contains(e));
            for ancestor_id in ancestors.0 {
                let ancestor =
                    self.txs_by_id.get(&ancestor_id).expect("Inconsistent mempool state");
                by_ds.insert((ancestor.descendant_score(), ancestor_id));
            }
        });
    }

    /// refresh descendants with new ancestor scores
    fn refresh_descendants(&mut self, entry: &TxMempoolEntry) {
        let descendants = entry.unconfirmed_descendants(self);
        self.mem_tracker.modify(&mut self.txs_by_ancestor_score, |by_as, _tracker| {
            by_as.retain(|(_score, e)| !descendants.contains(e));
            for descendant_id in descendants.0 {
                let descendant =
                    self.txs_by_id.get(&descendant_id).expect("Inconsistent mempool state");
                by_as.insert((descendant.ancestor_score(), descendant_id));
            }
        })
    }

    fn update_descendant_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for descendant_id in entry.unconfirmed_descendants(self).0 {
            self.mem_tracker.modify(&mut self.txs_by_id, |by_id, tracker| {
                tracker.modify(
                    by_id.get_mut(&descendant_id).expect("descendant"),
                    |descendant, _| {
                        descendant.fees_with_ancestors = (descendant.fees_with_ancestors
                            - entry.fee)
                            .expect("fee with descendants");
                        let size_anc = descendant.size_with_ancestors.get() - entry.size().get();
                        descendant.size_with_ancestors =
                            NonZeroUsize::new(size_anc).expect("non-zero size");
                        descendant.count_with_ancestors -= 1;
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
        log::info!("remove_tx: {}", tx_id.to_hash());
        let entry = self.mem_tracker.modify(&mut self.txs_by_id, |by_id, _| by_id.remove(tx_id));

        if let Some(entry) = entry {
            let entry = self.mem_tracker.release(entry);
            self.update_ancestor_state_for_drop(&entry);
            if reason == MempoolRemovalReason::Block {
                self.update_descendant_state_for_drop(&entry)
            }
            self.drop_tx(&entry);
            Some(entry)
        } else {
            assert!(!self.txs_by_descendant_score.iter().any(|(_, id)| id == tx_id));
            assert!(!self.spender_txs.iter().any(|(_, id)| *id == *tx_id));
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
        self.unspend_outpoints(entry);
    }

    fn remove_from_ancestor_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_descendants(entry);
        self.mem_tracker.modify(&mut self.txs_by_ancestor_score, |by_as, _tracker| {
            by_as.remove(&(entry.ancestor_score(), *entry.tx_id()));
        })
    }

    fn remove_from_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_ancestors(entry);
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

    pub fn find_conflicting_tx(&self, dep: &TxDependency) -> Option<&Id<Transaction>> {
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
}

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

#[derive(Debug, Eq, Clone)]
pub struct TxMempoolEntry {
    entry: TxEntry,
    fee: Fee,
    parents: BTreeSet<Id<Transaction>>,
    children: BTreeSet<Id<Transaction>>,
    count_with_descendants: usize,
    count_with_ancestors: usize,
    fees_with_descendants: Fee,
    fees_with_ancestors: Fee,
    size_with_descendants: NonZeroUsize,
    size_with_ancestors: NonZeroUsize,
}

impl TxMempoolEntry {
    pub fn new(
        entry: TxEntryWithFee,
        parents: BTreeSet<Id<Transaction>>,
        ancestors: BTreeSet<TxMempoolEntry>,
    ) -> Result<TxMempoolEntry, MempoolPolicyError> {
        let fee = entry.fee();
        let entry = entry.into_tx_entry();
        let size = entry.size();
        let size_with_ancestors = size
            .checked_add(ancestors.iter().map(|x| x.size().get()).sum())
            .expect("Sizes should not overflow");
        let ancestor_fees = ancestors
            .iter()
            .map(TxMempoolEntry::fee)
            .sum::<Option<_>>()
            .ok_or(MempoolPolicyError::AncestorFeeOverflow)?;
        let fees_with_ancestors =
            (fee + ancestor_fees).ok_or(MempoolPolicyError::AncestorFeeOverflow)?;
        Ok(Self {
            size_with_ancestors,
            count_with_ancestors: 1 + ancestors.len(),
            size_with_descendants: size,
            entry,
            fee,
            parents,
            children: BTreeSet::default(),
            count_with_descendants: 1,
            fees_with_descendants: fee,
            fees_with_ancestors,
        })
    }

    #[cfg(test)]
    pub fn new_from_data(
        tx: SignedTransaction,
        fee: Fee,
        parents: BTreeSet<Id<Transaction>>,
        ancestors: BTreeSet<TxMempoolEntry>,
        creation_time: Time,
    ) -> Result<TxMempoolEntry, MempoolPolicyError> {
        use crate::tx_origin::LocalTxOrigin;
        let origin = LocalTxOrigin::Mempool.into();
        let options = crate::TxOptions::default_for(origin);
        let entry = TxEntry::new(tx, creation_time, origin, options);
        Self::new(TxEntryWithFee::new(entry, fee), parents, ancestors)
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
        log::debug!("ancestor score for {:?}", self.tx_id());
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
        std::cmp::min(a, b).into()
    }

    pub fn tx_id(&self) -> &Id<Transaction> {
        self.entry.tx_id()
    }

    pub fn tx_entry(&self) -> &TxEntry {
        &self.entry
    }

    pub fn size(&self) -> NonZeroUsize {
        // TODO(Roy) this should follow Bitcoin's GetTxSize, which weighs in sigops, etc.
        self.entry.size()
    }

    pub fn creation_time(&self) -> Time {
        self.entry.creation_time()
    }

    pub fn parents(&self) -> impl Iterator<Item = &Id<Transaction>> {
        self.parents.iter()
    }

    pub fn children(&self) -> impl Iterator<Item = &Id<Transaction>> {
        self.children.iter()
    }

    fn get_children_mut(&mut self) -> &mut BTreeSet<Id<Transaction>> {
        &mut self.children
    }

    fn get_parents_mut(&mut self) -> &mut BTreeSet<Id<Transaction>> {
        &mut self.parents
    }

    pub fn is_replaceable(&self, store: &MempoolStore) -> bool {
        self.entry.transaction().is_replaceable()
            || self.unconfirmed_ancestors(store).0.iter().any(|ancestor| {
                store.get_entry(ancestor).expect("entry").entry.transaction().is_replaceable()
            })
    }

    pub fn unconfirmed_ancestors(&self, store: &MempoolStore) -> Ancestors {
        let mut visited = Ancestors(BTreeSet::new());
        self.unconfirmed_ancestors_inner(&mut visited, store);
        visited
    }

    pub fn unconfirmed_ancestors_from_parents(
        parents: &BTreeSet<Id<Transaction>>,
        store: &MempoolStore,
    ) -> Result<Ancestors, MempoolPolicyError> {
        let mut ancestors = parents.clone().into();
        for parent in parents {
            let parent = store.get_entry(parent).ok_or(MempoolPolicyError::GetParentError)?;
            parent.unconfirmed_ancestors_inner(&mut ancestors, store);
        }
        Ok(ancestors)
    }

    fn unconfirmed_ancestors_inner(&self, visited: &mut Ancestors, store: &MempoolStore) {
        // TODO: change this from recursive to iterative
        for parent in self.parents.iter() {
            if visited.insert(*parent) {
                store
                    .get_entry(parent)
                    .expect("entry")
                    .unconfirmed_ancestors_inner(visited, store);
            }
        }
    }

    pub fn depth_postorder_descendants<'a>(
        &'a self,
        store: &'a MempoolStore,
    ) -> impl Iterator<Item = &'a TxMempoolEntry> {
        let children_fn = |entry: &&'a TxMempoolEntry| {
            entry.children.iter().map(|id| store.txs_by_id[id].deref())
        };
        utils::graph_traversals::dag_depth_postorder(self, children_fn)
    }

    pub fn unconfirmed_descendants(&self, store: &MempoolStore) -> Descendants {
        let mut visited = Descendants(BTreeSet::new());
        self.unconfirmed_descendants_inner(&mut visited, store);
        visited
    }

    fn unconfirmed_descendants_inner(&self, visited: &mut Descendants, store: &MempoolStore) {
        for child in self.children.iter() {
            if visited.insert(*child) {
                store
                    .get_entry(child)
                    .expect("entry")
                    .unconfirmed_descendants_inner(visited, store);
            }
        }
    }
}

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
