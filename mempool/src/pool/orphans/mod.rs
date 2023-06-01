// Copyright (c) 2023 RBB S.r.l
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

use std::collections::{BTreeMap, BTreeSet};

use common::{
    chain::{OutPointSourceId, Transaction, UtxoOutPoint},
    primitives::Id,
};
use crypto::random::{make_pseudo_rng, Rng};
use logging::log;
use utils::{const_value::ConstValue, ensure};

use super::{OrphanPoolError, Time, TxEntry};
use crate::config;
pub use detect::is_orphan_error;

mod detect;

/// Max number of transactions the orphan pool data structure can handle
pub const ORPHAN_POOL_SIZE_HARD_LIMIT: usize = 50_000;

type InternalIdIntType = u16;
static_assertions::const_assert!(ORPHAN_POOL_SIZE_HARD_LIMIT < InternalIdIntType::MAX as usize);

/// Id used internally in orphan pool to identify/index transactions
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
struct InternalId(InternalIdIntType);

impl InternalId {
    const MAX: Self = Self(InternalIdIntType::MAX);

    fn new(n: usize) -> Self {
        assert!(
            n < ORPHAN_POOL_SIZE_HARD_LIMIT,
            "Orphan pool hard limit exceeded ({n}, max {ORPHAN_POOL_SIZE_HARD_LIMIT})",
        );
        Self(n as InternalIdIntType)
    }

    fn get(&self) -> usize {
        self.0 as usize
    }
}

/// Various indices and lookup maps over orphan transaction entries
#[derive(Debug)]
struct TxOrphanPoolMaps {
    /// Translation from the transaction ID to internal ID
    by_tx_id: BTreeMap<Id<Transaction>, InternalId>,

    /// Transactions indexed by the insertion time. Useful for removing stale transactions
    by_insertion_time: BTreeSet<(Time, InternalId)>,

    /// Transactions indexed by the previous output they spend
    ///
    /// TODO: Extend this to accounts too
    by_input: BTreeSet<(UtxoOutPoint, InternalId)>,
}

impl TxOrphanPoolMaps {
    fn new() -> Self {
        Self {
            by_tx_id: BTreeMap::new(),
            by_insertion_time: BTreeSet::new(),
            by_input: BTreeSet::new(),
        }
    }

    fn insert(&mut self, entry: &TxEntry, iid: InternalId) {
        let prev_id = self.by_tx_id.insert(*entry.tx_id(), iid);
        assert!(prev_id.is_none(), "Tx entry already in tx ID map");

        let inserted = self.by_insertion_time.insert((entry.creation_time(), iid));
        assert!(inserted, "Tx entry already in insertion time map");

        self.by_input.extend(entry.utxo_outpoints().map(|outpt| (outpt.clone(), iid)));
    }

    fn remove(&mut self, entry: &TxEntry) {
        let iid = self.by_tx_id.remove(entry.tx_id()).expect("entry to be in TX ID map");

        let removed = self.by_insertion_time.remove(&(entry.creation_time(), iid));
        assert!(removed, "Tx entry not present in the insertion time map");

        entry.utxo_outpoints().for_each(|outpt| {
            let removed = self.by_input.remove(&(outpt.clone(), iid));
            assert!(removed, "Transaction outpoint entry expected to be present");
        })
    }
}

/// Mempool transactions for which not all parents are known
#[derive(Debug)]
pub struct TxOrphanPool {
    /// Transactions in the orphan pool, indexed into by the internal ID
    transactions: Vec<TxEntry>,

    /// Maps used to index the set of transactions by various criteria
    maps: TxOrphanPoolMaps,

    /// Maximum orphan pool size in the number of transactions
    transaction_count_limit: ConstValue<usize>,
}

impl TxOrphanPool {
    pub fn new() -> Self {
        let transaction_count_limit = config::DEFAULT_ORPHAN_POOL_CAPACITY;
        Self {
            // We add 1 to the capacity because in normal operation, a transaction is added and
            // then the limit is enforced so the vector may temporarily exceed the limit by one.
            transactions: Vec::with_capacity(transaction_count_limit + 1),
            maps: TxOrphanPoolMaps::new(),
            transaction_count_limit: transaction_count_limit.into(),
        }
    }

    fn get_at(&self, id: InternalId) -> &TxEntry {
        self.transactions.get(id.get()).expect("entry to exist")
    }

    pub fn get(&self, id: &Id<Transaction>) -> Option<&TxEntry> {
        self.maps.by_tx_id.get(id).map(|iid| self.get_at(*iid))
    }

    pub fn contains(&self, id: &Id<Transaction>) -> bool {
        self.maps.by_tx_id.contains_key(id)
    }

    /// Get IDs of children of given transaction that are as candidates to be promoted to mempool.
    ///
    /// By ready, we mean it has no remaining dependencies in orphan pool. That means they can be
    /// considered for verification and, if the verification passes, moved to mempool.
    pub fn ready_children_of(
        &self,
        tx_id: Id<Transaction>,
    ) -> impl Iterator<Item = Id<Transaction>> + '_ {
        let source = OutPointSourceId::Transaction(tx_id);
        let lower_bound = (UtxoOutPoint::new(source.clone(), 0), InternalId(0));
        let upper_bound = (UtxoOutPoint::new(source, u32::MAX), InternalId::MAX);
        self.maps
            .by_input
            .range(lower_bound..=upper_bound)
            .filter_map(|(_, iid)| self.is_ready(*iid).then(|| *self.get_at(*iid).tx_id()))
    }

    /// Check no dependencies of given transaction are still in orphan pool so it can be considered
    /// as a candidate to move out.
    fn is_ready(&self, iid: InternalId) -> bool {
        let entry = self.get_at(iid);
        !entry.utxo_outpoints().any(|outpoint| match outpoint.tx_id() {
            OutPointSourceId::Transaction(tx_id) => self.maps.by_tx_id.contains_key(&tx_id),
            OutPointSourceId::BlockReward(_) => false,
        })
    }

    /// Number of transactions in the orphan pool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Convert into transaction entries (in arbitrary order)
    pub fn into_transactions(self) -> impl Iterator<Item = TxEntry> {
        self.transactions.into_iter()
    }

    /// Insert a transaction entry
    pub fn insert(&mut self, entry: TxEntry) -> Result<(), OrphanPoolError> {
        let tx_id = *entry.tx_id();
        ensure!(!self.contains(&tx_id), OrphanPoolError::Duplicate);

        self.maps.insert(&entry, InternalId::new(self.len()));
        self.transactions.push(entry);

        if self.enforce_max_size(ORPHAN_POOL_SIZE_HARD_LIMIT) > 0 {
            log::warn!("Orphan pool size hard limit hit");
            ensure!(self.contains(&tx_id), OrphanPoolError::Full);
        }

        Ok(())
    }

    /// Insert a transaction entry and make sure the pool size does not grow too large
    pub fn insert_and_enforce_limits(
        &mut self,
        entry: TxEntry,
        cur_time: Time,
    ) -> Result<(), OrphanPoolError> {
        let tx_id = *entry.tx_id();

        self.insert(entry)?;
        self.enforce_limits(cur_time);
        ensure!(self.contains(&tx_id), OrphanPoolError::Full);

        Ok(())
    }

    /// Remove given transaction
    pub fn remove(&mut self, id: Id<Transaction>) -> Option<TxEntry> {
        self.maps.by_tx_id.get(&id).copied().map(|iid| self.remove_at(iid))
    }

    /// Remove transaction by its internal ID
    fn remove_at(&mut self, iid: InternalId) -> TxEntry {
        let entry = self.transactions.swap_remove(iid.get());
        self.maps.remove(&entry);

        // The above swap_remove may have moved an entry from the back of the vector to the
        // original position of the transaction we just removed. Maps have to be updated.
        if let Some(moved_entry) = self.transactions.get(iid.get()) {
            self.maps.remove(moved_entry);
            self.maps.insert(moved_entry, iid);
        }

        entry
    }

    /// Enforce expiration and transaction count limits. Returns the number of erased transactions.
    fn enforce_limits(&mut self, cur_time: Time) -> usize {
        let n_expired = self.remove_expired(cur_time);
        let n_evicted = self.enforce_max_size(*self.transaction_count_limit);
        n_expired + n_evicted
    }

    /// Remove expired items (older than `cur_time - expiration_interval`)
    fn remove_expired(&mut self, cur_time: Time) -> usize {
        // Remove all expired txns
        let expiry = cur_time.saturating_sub(config::DEFAULT_ORPHAN_TX_EXPIRY_INTERVAL);

        let mut n_expired = 0;
        while let Some(entry) = self.maps.by_insertion_time.first().filter(|(t, _)| *t < expiry) {
            self.remove_at(entry.1);
            n_expired += 1;
        }

        if n_expired > 0 {
            log::info!("Removed {n_expired} expired transactions from the orphan pool");
        }

        n_expired
    }

    /// Evict transactions at random until the specified cap is reached
    fn enforce_max_size(&mut self, max_size: usize) -> usize {
        let mut rng = make_pseudo_rng();

        let mut n_evicted = 0;
        while self.len() > max_size {
            self.remove_at(InternalId::new(rng.gen_range(0..self.len())));
            n_evicted += 1;
        }

        if n_evicted > 0 {
            log::info!("Evicted {n_evicted} transactions from the orphan pool to limit its size");
        }

        n_evicted
    }
}

#[cfg(test)]
mod test;
