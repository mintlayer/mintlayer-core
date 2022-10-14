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

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use common::chain::signed_transaction::SignedTransaction;
use common::chain::tokens::OutputValue;
use common::chain::transaction::Transaction;
use common::chain::OutPoint;
use common::primitives::amount::Amount;
use common::primitives::Id;
use common::primitives::Idable;
use serialization::Encode;

use logging::log;

use utils::newtype;

use crate::error::Error;
use crate::error::TxValidationError;

use super::Ancestors;
use super::Conflicts;
use super::Descendants;
use super::Time;

newtype! {
    #[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
    pub(super) struct DescendantScore(Amount);
}

newtype! {
    #[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
    pub(super) struct AncestorScore(Amount);
}

#[derive(Debug)]
pub struct MempoolStore {
    // This is the "main" data structure storing Mempool entries. All other structures in the
    // MempoolStore contain ids (hashes) of entries, sorted according to some order of interest.
    pub(super) txs_by_id: BTreeMap<Id<Transaction>, TxMempoolEntry>,

    // Mempool entries sorted by descendant score.
    // We keep this index so that when the mempool grows full, we know which transactions are the
    // most economically reasonable to evict. When an entry is removed from the mempool for
    // fullness reasons, it must be removed together with all of its descendants (as these descendants
    // would no longer be valid to mine). Entries with a lower descendant score will be evicted
    // first.
    // The descendant score of an entry is defined as:
    //  max(fee/size of entry's tx, fee/size with all descendants).
    //  TODO if we wish to follow Bitcoin Bore, "size" is not simply the encoded size, but
    // rather a value that takes into account witness and sigop data (see CTxMemPoolEntry::GetTxSize).
    pub(super) txs_by_descendant_score: BTreeMap<DescendantScore, BTreeSet<Id<Transaction>>>,

    // Mempool entries sorted by ancestor score.
    // This is used to select the most economically attractive transactions for block production.
    // The ancestor score of an entry is defined as
    //  min(score/size of entry's tx, score/size with all ancestors).
    pub(super) txs_by_ancestor_score: BTreeMap<AncestorScore, BTreeSet<Id<Transaction>>>,

    // Entries that have remained in the mempool for a long time (see DEFAULT_MEMPOOL_EXPIRY) are
    // evicted. To efficiently know which entries to evict, we store the mempool entries sorted by
    // their creation time, from earliest to latest.
    pub(super) txs_by_creation_time: BTreeMap<Time, BTreeSet<Id<Transaction>>>,

    // TODO add txs_by_ancestor_score index, which will be used by the block production subsystem
    // to select the best transactions for the next block
    //
    // We keep the information of which outpoints are spent by entries currently in the mempool.
    // This allows us to recognize conflicts (double-spends) and handle them
    pub(super) spender_txs: BTreeMap<OutPoint, Id<Transaction>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum MempoolRemovalReason {
    Block,
    Expiry,
    SizeLimit,
    Replaced,
}

impl MempoolStore {
    pub(super) fn new() -> Self {
        Self {
            txs_by_descendant_score: BTreeMap::new(),
            txs_by_ancestor_score: BTreeMap::new(),
            txs_by_id: BTreeMap::new(),
            txs_by_creation_time: BTreeMap::new(),
            spender_txs: BTreeMap::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.txs_by_id.is_empty()
    }

    // Checks whether the outpoint is to be created by an unconfirmed tx
    pub(super) fn contains_outpoint(&self, outpoint: &OutPoint) -> bool {
        outpoint.tx_id().get_tx_id().is_some()
            && matches!(self.txs_by_id.get(outpoint.tx_id().get_tx_id().expect("Not a block reward outpoint")),
            Some(entry) if entry.tx.transaction().outputs().len() > outpoint.output_index() as usize)
    }

    pub(super) fn get_unconfirmed_outpoint_value(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Amount, TxValidationError> {
        let tx_id = *outpoint.tx_id().get_tx_id().expect("Not coinbase");
        let err = || TxValidationError::OutPointNotFound {
            outpoint: outpoint.clone(),
            tx_id,
        };
        self.txs_by_id
            .get(&tx_id)
            .ok_or_else(err)
            .and_then(|entry| {
                entry
                    .tx
                    .transaction()
                    .outputs()
                    .get(outpoint.output_index() as usize)
                    .ok_or_else(err)
            })
            .map(|output| match output.value() {
                OutputValue::Coin(coin) => *coin,
                OutputValue::Token(_) => Amount::from_atoms(0),
            })
    }

    pub(super) fn get_entry(&self, id: &Id<Transaction>) -> Option<&TxMempoolEntry> {
        self.txs_by_id.get(id)
    }

    pub(super) fn assert_valid(&self) {
        #[cfg(test)]
        self.assert_valid_inner()
    }

    #[cfg(test)]
    fn assert_valid_inner(&self) {
        let entries = self.txs_by_descendant_score.values().flatten().collect::<Vec<_>>();
        for id in self.txs_by_id.keys() {
            assert_eq!(
                entries.iter().filter(|entry_id| ***entry_id == *id).count(),
                1
            )
        }
        for entry in self.txs_by_id.values() {
            for child in &entry.children {
                assert!(self.txs_by_id.get(child).expect("child").parents.contains(&entry.tx_id()))
            }
        }
    }

    fn append_to_parents(&mut self, entry: &TxMempoolEntry) {
        for parent in entry.unconfirmed_parents() {
            self.txs_by_id
                .get_mut(parent)
                .expect("append_to_parents")
                .get_children_mut()
                .insert(entry.tx_id());
        }
    }

    fn remove_from_parents(&mut self, entry: &TxMempoolEntry) {
        for parent in entry.unconfirmed_parents() {
            self.txs_by_id
                .get_mut(parent)
                .expect("remove_from_parents")
                .get_children_mut()
                .remove(&entry.tx_id());
        }
    }

    fn remove_from_children(&mut self, entry: &TxMempoolEntry) {
        for child in entry.unconfirmed_children() {
            self.txs_by_id
                .get_mut(child)
                .expect("remove_from_children")
                .get_parents_mut()
                .remove(&entry.tx_id());
        }
    }

    fn update_ancestor_state_for_add(&mut self, entry: &TxMempoolEntry) -> Result<(), Error> {
        for ancestor in entry.unconfirmed_ancestors(self).0 {
            let ancestor = self.txs_by_id.get_mut(&ancestor).expect("ancestor");
            ancestor.fees_with_descendants = (ancestor.fees_with_descendants + entry.fee)
                .ok_or(TxValidationError::AncestorFeeUpdateOverflow)?;
            ancestor.size_with_descendants += entry.size();
            ancestor.count_with_descendants += 1;
        }
        Ok(())
    }

    fn update_ancestor_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for ancestor in entry.unconfirmed_ancestors(self).0 {
            let ancestor = self.txs_by_id.get_mut(&ancestor).expect("ancestor");
            ancestor.fees_with_descendants =
                (ancestor.fees_with_descendants - entry.fee).expect("fee with descendants");
            ancestor.size_with_descendants -= entry.size();
            ancestor.count_with_descendants -= 1;
        }
    }

    fn mark_outpoints_as_spent(&mut self, entry: &TxMempoolEntry) {
        let id = entry.tx_id();
        for outpoint in entry.tx.transaction().inputs().iter().map(|input| input.outpoint()) {
            self.spender_txs.insert(outpoint.clone(), id);
        }
    }

    fn unspend_outpoints(&mut self, entry: &TxMempoolEntry) {
        self.spender_txs.retain(|_, id| *id != entry.tx_id())
    }

    pub(super) fn add_tx(&mut self, entry: TxMempoolEntry) -> Result<(), Error> {
        self.append_to_parents(&entry);
        self.update_ancestor_state_for_add(&entry)?;
        self.mark_outpoints_as_spent(&entry);

        let creation_time = entry.creation_time;
        let tx_id = entry.tx_id();

        self.txs_by_id.insert(tx_id, entry.clone());

        self.add_to_descendant_score_index(&entry);
        self.add_to_ancestor_score_index(&entry);
        self.txs_by_creation_time.entry(creation_time).or_default().insert(tx_id);
        Ok(())
    }

    fn add_to_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_ancestors(entry);
        self.txs_by_descendant_score
            .entry(entry.descendant_score())
            .or_default()
            .insert(entry.tx_id());
    }

    fn add_to_ancestor_score_index(&mut self, entry: &TxMempoolEntry) {
        // TODO in the normal case of a new transaction arriving, there can't be any children
        // because such children would be orphans.
        // When we implement disconnecting a block, we'll need to clean up the mess we're leaving
        // here.
        self.txs_by_ancestor_score
            .entry(entry.ancestor_score())
            .or_default()
            .insert(entry.tx_id());
    }

    fn refresh_ancestors(&mut self, entry: &TxMempoolEntry) {
        // Since the ancestors of `entry` have had their descendant score modified, their ordering
        // in txs_by_descendant_score may no longer be correct. We thus remove all ancestors and
        // reinsert them, taking the new, updated fees into account
        let ancestors = entry.unconfirmed_ancestors(self);
        for entries in self.txs_by_descendant_score.values_mut() {
            entries.retain(|id| !ancestors.contains(id))
        }
        for ancestor_id in ancestors.0 {
            let ancestor = self.txs_by_id.get(&ancestor_id).expect("Inconsistent mempool state");
            self.txs_by_descendant_score
                .entry(ancestor.descendant_score())
                .or_default()
                .insert(ancestor_id);
        }

        self.txs_by_descendant_score.retain(|_score, txs| !txs.is_empty());
    }

    fn refresh_descendants(&mut self, entry: &TxMempoolEntry) {
        let descendants = entry.unconfirmed_descendants(self);
        for entries in self.txs_by_ancestor_score.values_mut() {
            entries.retain(|id| !descendants.contains(id))
        }
        for descendant_id in descendants.0 {
            let descendant =
                self.txs_by_id.get(&descendant_id).expect("Inconsistent mempool state");
            self.txs_by_ancestor_score
                .entry(descendant.ancestor_score())
                .or_default()
                .insert(descendant_id);
        }

        self.txs_by_descendant_score.retain(|_score, txs| !txs.is_empty());
    }

    fn update_descendant_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for descendant in entry.unconfirmed_descendants(self).0 {
            let descendant = self.txs_by_id.get_mut(&descendant).expect("descendant");
            descendant.fees_with_ancestors =
                (descendant.fees_with_ancestors - entry.fee).expect("fee with descendants");
            descendant.size_with_ancestors -= entry.size();
            descendant.count_with_ancestors -= 1;
        }
    }

    pub(super) fn remove_tx(&mut self, tx_id: &Id<Transaction>, reason: MempoolRemovalReason) {
        log::info!("remove_tx: {}", tx_id.get());
        if let Some(entry) = self.txs_by_id.remove(tx_id) {
            self.update_ancestor_state_for_drop(&entry);
            if reason == MempoolRemovalReason::Block {
                self.update_descendant_state_for_drop(&entry)
            }
            self.drop_tx(&entry);
        } else {
            assert!(!self.txs_by_descendant_score.values().flatten().any(|id| *id == *tx_id));
            assert!(!self.spender_txs.iter().any(|(_, id)| *id == *tx_id));
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
        self.unspend_outpoints(entry)
    }

    fn remove_from_ancestor_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_descendants(entry);
        self.txs_by_ancestor_score.entry(entry.ancestor_score()).and_modify(|entries| {
            entries.remove(&entry.tx_id());
        });
        if self
            .txs_by_ancestor_score
            .get(&entry.ancestor_score())
            .expect("key must exist")
            .is_empty()
        {
            self.txs_by_ancestor_score.remove(&entry.ancestor_score());
        }
    }

    fn remove_from_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_ancestors(entry);
        self.txs_by_descendant_score
            .entry(entry.descendant_score())
            .and_modify(|entries| {
                entries.remove(&entry.tx_id());
            });
        if self
            .txs_by_descendant_score
            .get(&entry.descendant_score())
            .expect("key must exist")
            .is_empty()
        {
            self.txs_by_descendant_score.remove(&entry.descendant_score());
        }
    }

    fn remove_from_creation_time_index(&mut self, entry: &TxMempoolEntry) {
        self.txs_by_creation_time.entry(entry.creation_time).and_modify(|entries| {
            entries.remove(&entry.tx_id());
        });
        if self
            .txs_by_creation_time
            .get(&entry.creation_time())
            .expect("key must exist")
            .is_empty()
        {
            self.txs_by_creation_time.remove(&entry.creation_time());
        }
    }

    pub(super) fn drop_conflicts(&mut self, conflicts: Conflicts) {
        for conflict in conflicts.0 {
            self.remove_tx(&conflict, MempoolRemovalReason::Replaced)
        }
    }

    pub(super) fn drop_tx_and_descendants(
        &mut self,
        tx_id: Id<Transaction>,
        reason: MempoolRemovalReason,
    ) {
        if let Some(entry) = self.txs_by_id.get(&tx_id).cloned() {
            let descendants = entry.unconfirmed_descendants(self);
            log::trace!(
                "Dropping tx {} which has {} descendants",
                tx_id.get(),
                descendants.len()
            );
            self.remove_tx(&entry.tx.transaction().get_id(), reason);
            for descendant_id in descendants.0 {
                // It may be that this descendant has several ancestors and has already been removed
                if let Some(descendant) = self.txs_by_id.get(&descendant_id).cloned() {
                    self.remove_tx(&descendant.tx.transaction().get_id(), reason)
                }
            }
        }
    }

    pub(super) fn find_conflicting_tx(&self, outpoint: &OutPoint) -> Option<Id<Transaction>> {
        self.spender_txs.get(outpoint).cloned()
    }
}

#[derive(Debug, Eq, Clone)]
pub(super) struct TxMempoolEntry {
    pub(super) tx: SignedTransaction,
    pub(super) fee: Amount,
    parents: BTreeSet<Id<Transaction>>,
    children: BTreeSet<Id<Transaction>>,
    count_with_descendants: usize,
    count_with_ancestors: usize,
    fees_with_descendants: Amount,
    fees_with_ancestors: Amount,
    size_with_descendants: usize,
    size_with_ancestors: usize,
    creation_time: Time,
}

impl TxMempoolEntry {
    pub(super) fn new(
        tx: SignedTransaction,
        fee: Amount,
        parents: BTreeSet<Id<Transaction>>,
        ancestors: BTreeSet<TxMempoolEntry>,
        creation_time: Time,
    ) -> Result<TxMempoolEntry, TxValidationError> {
        let size_with_ancestors: usize =
            ancestors.iter().map(|ancestor| ancestor.tx().encoded_size()).sum::<usize>()
                + tx.encoded_size();
        let ancestor_fees = ancestors
            .iter()
            .map(|ancestor| ancestor.fee())
            .sum::<Option<_>>()
            .ok_or(TxValidationError::AncestorFeeOverflow)?;
        let fees_with_ancestors =
            (fee + ancestor_fees).ok_or(TxValidationError::AncestorFeeOverflow)?;
        Ok(Self {
            size_with_ancestors,
            count_with_ancestors: 1 + ancestors.len(),
            size_with_descendants: tx.encoded_size(),
            tx,
            fee,
            parents,
            children: BTreeSet::default(),
            count_with_descendants: 1,
            creation_time,
            fees_with_descendants: fee,
            fees_with_ancestors,
        })
    }

    pub(super) fn tx(&self) -> &SignedTransaction {
        &self.tx
    }

    pub(super) fn fee(&self) -> Amount {
        self.fee
    }

    pub(super) fn count_with_descendants(&self) -> usize {
        self.count_with_descendants
    }

    #[cfg(test)]
    pub(super) fn fees_with_descendants(&self) -> Amount {
        self.fees_with_descendants
    }

    #[cfg(test)]
    pub(super) fn fees_with_ancestors(&self) -> Amount {
        self.fees_with_ancestors
    }

    pub(super) fn descendant_score(&self) -> DescendantScore {
        std::cmp::max(
            (self.fees_with_descendants
                / u128::try_from(self.size_with_descendants).expect("conversion"))
            .expect("nonzero tx_size"),
            (self.fee / u128::try_from(self.tx.encoded_size()).expect("conversion"))
                .expect("nonzero tx size"),
        )
        .into()
    }

    pub(super) fn ancestor_score(&self) -> AncestorScore {
        log::debug!("ancestor score for {:?}", self.tx_id());
        log::debug!(
            "fees with ancestors: {:?}, size_with_ancestors: {}, fee: {:?}, size: {}",
            self.fees_with_ancestors,
            self.size_with_ancestors,
            self.fee,
            self.tx.encoded_size()
        );
        std::cmp::min(
            (self.fees_with_ancestors
                / u128::try_from(self.size_with_ancestors).expect("conversion"))
            .expect("nonzero tx_size"),
            (self.fee / u128::try_from(self.tx.encoded_size()).expect("conversion"))
                .expect("nonzero tx size"),
        )
        .into()
    }

    pub(super) fn tx_id(&self) -> Id<Transaction> {
        self.tx.transaction().get_id()
    }

    pub(super) fn size(&self) -> usize {
        // TODO(Roy) this should follow Bitcoin's GetTxSize, which weighs in sigops, etc.
        self.tx.encoded_size()
    }

    pub(super) fn creation_time(&self) -> Time {
        self.creation_time
    }

    fn unconfirmed_parents(&self) -> impl Iterator<Item = &Id<Transaction>> {
        self.parents.iter()
    }

    fn unconfirmed_children(&self) -> impl Iterator<Item = &Id<Transaction>> {
        self.children.iter()
    }

    fn get_children_mut(&mut self) -> &mut BTreeSet<Id<Transaction>> {
        &mut self.children
    }

    fn get_parents_mut(&mut self) -> &mut BTreeSet<Id<Transaction>> {
        &mut self.parents
    }

    pub(super) fn is_replaceable(&self, store: &MempoolStore) -> bool {
        self.tx.transaction().is_replaceable()
            || self.unconfirmed_ancestors(store).0.iter().any(|ancestor| {
                store.get_entry(ancestor).expect("entry").tx.transaction().is_replaceable()
            })
    }

    pub(super) fn unconfirmed_ancestors(&self, store: &MempoolStore) -> Ancestors {
        let mut visited = Ancestors(BTreeSet::new());
        self.unconfirmed_ancestors_inner(&mut visited, store);
        visited
    }

    pub(super) fn unconfirmed_ancestors_from_parents(
        parents: BTreeSet<Id<Transaction>>,
        store: &MempoolStore,
    ) -> Result<Ancestors, TxValidationError> {
        let mut ancestors = BTreeSet::new();
        for parent in parents {
            ancestors.insert(parent);
            let parent = store.get_entry(&parent).ok_or(TxValidationError::GetParentError)?;
            let parent_ancestors = parent.unconfirmed_ancestors(store).0;
            ancestors.extend(parent_ancestors);
        }
        Ok(ancestors.into())
    }

    fn unconfirmed_ancestors_inner(&self, visited: &mut Ancestors, store: &MempoolStore) {
        for parent in self.parents.iter() {
            if visited.insert(*parent) {
                store
                    .get_entry(parent)
                    .expect("entry")
                    .unconfirmed_ancestors_inner(visited, store);
            }
        }
    }

    pub(super) fn unconfirmed_descendants(&self, store: &MempoolStore) -> Descendants {
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
        Some(other.tx_id().cmp(&self.tx_id()))
    }
}

impl PartialEq for TxMempoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.tx_id() == other.tx_id()
    }
}

impl Ord for TxMempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.tx_id().cmp(&self.tx_id())
    }
}
