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

use common::{chain::Transaction, primitives::Id};
use logging::log;
use mempool_types::TxStatus;
use randomness::{make_pseudo_rng, Rng};
use utils::{const_value::ConstValue, ensure};

use super::{OrphanPoolError, Time, TxDependency};
use crate::{config, tx_origin::RemoteTxOrigin};
pub use detect::OrphanType;

mod detect;

/// Specialize [super::TxEntry] for use in orphan pool. Only allow entries coming from remote peers.
type TxEntry = super::TxEntry<RemoteTxOrigin>;

/// Max number of transactions the orphan pool data structure can handle
pub const ORPHAN_POOL_SIZE_HARD_LIMIT: usize = 50_000;

type InternalIdIntType = u16;
static_assertions::const_assert!(ORPHAN_POOL_SIZE_HARD_LIMIT < InternalIdIntType::MAX as usize);

/// Id used internally in orphan pool to identify/index transactions
#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Clone, Copy)]
struct InternalId(InternalIdIntType);

impl InternalId {
    const ZERO: Self = Self(0);
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

    /// Transactions indexed by their dependencies
    by_deps: BTreeSet<(TxDependency, InternalId)>,

    /// Transactions indexed by the origin
    by_origin: BTreeSet<(RemoteTxOrigin, InternalId)>,
}

impl TxOrphanPoolMaps {
    fn new() -> Self {
        Self {
            by_tx_id: BTreeMap::new(),
            by_insertion_time: BTreeSet::new(),
            by_deps: BTreeSet::new(),
            by_origin: BTreeSet::new(),
        }
    }

    fn insert(&mut self, entry: &TxEntry, iid: InternalId) {
        let prev_id = self.by_tx_id.insert(*entry.tx_id(), iid);
        assert!(prev_id.is_none(), "Tx entry already in tx ID map");

        let inserted = self.by_insertion_time.insert((entry.creation_time(), iid));
        assert!(inserted, "Tx entry already in insertion time map");

        let inserted = self.by_origin.insert((entry.origin(), iid));
        assert!(inserted, "Tx entry already in the origin map");

        self.by_deps.extend(entry.requires().map(|dep| (dep, iid)));
    }

    fn remove(&mut self, entry: &TxEntry) {
        let iid = self.by_tx_id.remove(entry.tx_id()).expect("entry to be in TX ID map");

        let removed = self.by_insertion_time.remove(&(entry.creation_time(), iid));
        assert!(removed, "Tx entry not present in the insertion time map");

        let removed = self.by_origin.remove(&(entry.origin(), iid));
        assert!(removed, "Tx entry not present in the origin map");

        entry.requires().for_each(|dep| {
            self.by_deps.remove(&(dep, iid));
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

    pub fn entry(&mut self, id: &Id<Transaction>) -> Option<PoolEntry<'_>> {
        self.maps.by_tx_id.get(id).copied().map(|iid| PoolEntry::new(self, iid))
    }

    /// Get IDs of children of given transaction that are as candidates to be promoted to mempool.
    pub fn children_of<'a, R: crate::tx_origin::IsOrigin>(
        &'a self,
        entry: &'a super::TxEntry<R>,
    ) -> impl Iterator<Item = &'a TxEntry> + 'a {
        entry.provides().flat_map(move |dep| {
            self.maps
                .by_deps
                .range((dep.clone(), InternalId::ZERO)..=(dep, InternalId::MAX))
                .map(|(_, iid)| self.get_at(*iid))
        })
    }

    /// Number of transactions in the orphan pool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Insert a transaction entry
    pub fn insert(&mut self, entry: TxEntry) -> Result<TxStatus, OrphanPoolError> {
        let tx_id = *entry.tx_id();
        if self.contains(&tx_id) {
            return Ok(TxStatus::InOrphanPoolDuplicate);
        }

        self.maps.insert(&entry, InternalId::new(self.len()));
        self.transactions.push(entry);

        if self.enforce_max_size(ORPHAN_POOL_SIZE_HARD_LIMIT) > 0 {
            log::warn!("Orphan pool size hard limit hit");
            ensure!(self.contains(&tx_id), OrphanPoolError::Full);
        }

        Ok(TxStatus::InOrphanPool)
    }

    /// Insert a transaction entry and make sure the pool size does not grow too large
    pub fn insert_and_enforce_limits(
        &mut self,
        entry: TxEntry,
        cur_time: Time,
    ) -> Result<TxStatus, OrphanPoolError> {
        let tx_id = *entry.tx_id();

        let status = self.insert(entry)?;
        self.enforce_limits(cur_time);
        ensure!(self.contains(&tx_id), OrphanPoolError::Full);

        Ok(status)
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
        let expiry = cur_time.saturating_duration_sub(config::DEFAULT_ORPHAN_TX_EXPIRY_INTERVAL);

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

    /// Remove orphans for given originator
    pub fn remove_by_origin(&mut self, origin: RemoteTxOrigin) -> usize {
        let mut n_removed = 0;

        while let Some(iid) = self.pick_by_origin(origin) {
            let _ = self.remove_at(iid);
            n_removed += 1;
        }

        n_removed
    }

    /// Pick one orphan from given origin
    fn pick_by_origin(&self, origin: RemoteTxOrigin) -> Option<InternalId> {
        self.maps
            .by_origin
            .range((origin, InternalId::ZERO)..=(origin, InternalId::MAX))
            .map(|(_origin, iid)| *iid)
            .next()
    }
}

/// Entry-like access to orphans in the pool (somewhat similar to `btree_map::OccupiedEntry`)
pub struct PoolEntry<'p> {
    pool: &'p mut TxOrphanPool,
    iid: InternalId,
}

impl<'p> PoolEntry<'p> {
    fn new(pool: &'p mut TxOrphanPool, iid: InternalId) -> Self {
        Self { pool, iid }
    }

    /// Get a reference to the entry in the orphan pool
    pub fn get(&'p self) -> &'p TxEntry {
        self.pool.transactions.get(self.iid.get()).expect("entry to exist")
    }

    /// Check no dependencies of given transaction are still in orphan pool so it can be considered
    /// as a candidate to move out.
    pub fn is_ready(&self) -> bool {
        let entry = self.get();
        !entry.requires().any(|dep| match dep {
            // Always consider account deps. TODO: can be optimized in the future
            TxDependency::DelegationAccount(_)
            | TxDependency::TokenSupplyAccount(_)
            | TxDependency::OrderAccount(_)
            | TxDependency::OrderV1Account(_) => false,
            TxDependency::TxOutput(tx_id, _) => self.pool.maps.by_tx_id.contains_key(&tx_id),
        })
    }

    /// Take the entry, removing it from the orphan pool
    pub fn take(self) -> TxEntry {
        self.pool.remove_at(self.iid)
    }
}

#[cfg(test)]
mod test;
