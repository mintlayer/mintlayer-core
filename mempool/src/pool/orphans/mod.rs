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
use utils::{const_value::ConstValue, ensure};

use super::{OrphanPoolError, Time};
use crate::{
    config,
    pool::dependency::TxRequiredDependency,
    tx_origin::{RemoteTxOrigin, TxOrigin},
};
pub use detect::OrphanType;

mod detect;

/// The transaction entry type used in the orphan pool. Entries are stored with their unified
/// origin. By default only remote-origin entries are admitted; local-origin entries may be
/// parked too when `AllowLocalOrphans` is enabled (see `MempoolConfig`).
type TxEntry = super::TxEntry;

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

    /// Transactions indexed by their required dependencies
    by_deps: BTreeSet<(TxRequiredDependency, InternalId)>,

    /// Transactions indexed by their origin
    by_origin: BTreeSet<(TxOrigin, InternalId)>,

    /// Number of stored entries with a local origin
    local_count: usize,

    /// Occupancy accounting per origin (entry count and total encoded size)
    origin_stats: BTreeMap<TxOrigin, OriginStat>,
}

/// Occupancy of the pool attributable to a single origin
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct OriginStat {
    count: usize,
    size: usize,
    /// Whether the origin is an outbound (node-selected) peer, recorded from the entry's
    /// options at insertion time. All entries of one origin share the class.
    outbound: bool,
}

impl TxOrphanPoolMaps {
    fn new() -> Self {
        Self {
            by_tx_id: BTreeMap::new(),
            by_insertion_time: BTreeSet::new(),
            by_deps: BTreeSet::new(),
            by_origin: BTreeSet::new(),
            local_count: 0,
            origin_stats: BTreeMap::new(),
        }
    }

    fn insert(&mut self, entry: &TxEntry, iid: InternalId) {
        let prev_id = self.by_tx_id.insert(*entry.tx_id(), iid);
        assert!(prev_id.is_none(), "Tx entry already in tx ID map");

        let inserted = self.by_insertion_time.insert((entry.creation_time(), iid));
        assert!(inserted, "Tx entry already in insertion time map");

        let origin = entry.origin();
        let inserted = self.by_origin.insert((origin, iid));
        assert!(inserted, "Tx entry already in the origin map");

        if matches!(origin, TxOrigin::Local(_)) {
            self.local_count += 1;
        }

        let stat = self.origin_stats.entry(origin).or_default();
        let outbound = entry.options().origin_peer_is_outbound();
        if stat.count > 0 {
            // A peer's connection class is fixed for the connection's lifetime; a flip here
            // would silently change the whole origin's eviction tier. The assertion is a
            // debug-build backstop: in release builds the first recorded class stays
            // authoritative.
            debug_assert_eq!(stat.outbound, outbound, "origin changed connection class");
        } else {
            stat.outbound = outbound;
        }
        stat.count += 1;
        stat.size += entry.size().get();

        self.by_deps.extend(entry.required_deps().map(|dep| (dep, iid)));
    }

    fn remove(&mut self, entry: &TxEntry) {
        let iid = self.by_tx_id.remove(entry.tx_id()).expect("entry to be in TX ID map");

        let removed = self.by_insertion_time.remove(&(entry.creation_time(), iid));
        assert!(removed, "Tx entry not present in the insertion time map");

        let removed = self.by_origin.remove(&(entry.origin(), iid));
        assert!(removed, "Tx entry not present in the origin map");

        if matches!(entry.origin(), TxOrigin::Local(_)) {
            self.local_count -= 1;
        }

        let stat = self.origin_stats.get_mut(&entry.origin()).expect("origin stat to be present");
        stat.count -= 1;
        stat.size -= entry.size().get();

        // Purge exhausted entries so teardown leaves no per-origin accounting residue;
        // a lingering zero-count key would make `tracked_origin_count` drift upward and
        // keep the origin's memory in the map indefinitely.
        if stat.count == 0 {
            debug_assert_eq!(stat.size, 0);
            self.origin_stats.remove(&entry.origin());
        }

        entry.required_deps().for_each(|dep| {
            self.by_deps.remove(&(dep, iid));
        });
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

    /// Number of entries a local origin is guaranteed to keep when the pool makes room
    local_transaction_count_limit: ConstValue<usize>,

    /// Number of entries a single remote peer is guaranteed to keep when the pool makes room
    /// (inbound tier)
    remote_per_peer_limit: ConstValue<usize>,

    /// Number of entries a single outbound (node-selected) remote peer is guaranteed to keep
    outbound_remote_per_peer_limit: ConstValue<usize>,
}

impl TxOrphanPool {
    /// Only this crate constructs the pool (from validated `MempoolConfig` values), so the
    /// constructor stays crate-private. Zero capacities are rejected by
    /// `MempoolConfig::validate` at startup; the assertion below is a debug-build backstop
    /// only and must not be relied on in release builds.
    pub(crate) fn new(
        local_orphan_pool_capacity: usize,
        remote_orphan_pool_capacity_per_peer: usize,
        outbound_remote_orphan_pool_capacity_per_peer: usize,
    ) -> Self {
        let transaction_count_limit = config::DEFAULT_ORPHAN_POOL_CAPACITY;
        debug_assert!(
            local_orphan_pool_capacity > 0
                && remote_orphan_pool_capacity_per_peer > 0
                && outbound_remote_orphan_pool_capacity_per_peer > 0,
            "orphan capacities must be nonzero (validated at the config layer)"
        );
        Self {
            // Headroom so pushes do not reallocate on every entry; the vector may temporarily
            // exceed the soft limit when entries are inserted directly.
            transactions: Vec::with_capacity(transaction_count_limit + 1),
            maps: TxOrphanPoolMaps::new(),
            transaction_count_limit: transaction_count_limit.into(),
            local_transaction_count_limit: local_orphan_pool_capacity.into(),
            remote_per_peer_limit: remote_orphan_pool_capacity_per_peer.into(),
            outbound_remote_per_peer_limit: outbound_remote_orphan_pool_capacity_per_peer.into(),
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
        let utxo_deps = self
            .maps
            .by_deps
            .range(
                (
                    TxRequiredDependency::TxOutput(*entry.tx_id(), 0),
                    InternalId::ZERO,
                )
                    ..=(
                        TxRequiredDependency::TxOutput(*entry.tx_id(), u32::MAX),
                        InternalId::MAX,
                    ),
            )
            .map(|(_, iid)| self.get_at(*iid));
        let non_utxo_deps = entry.provided_non_utxo_deps().flat_map(move |provided_dep| {
            let required_dep = provided_dep.into_requirement();
            self.maps
                .by_deps
                .range((required_dep.clone(), InternalId::ZERO)..=(required_dep, InternalId::MAX))
                .map(|(_, iid)| self.get_at(*iid))
        });

        utxo_deps.chain(non_utxo_deps)
    }

    /// Number of transactions in the orphan pool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Insert a transaction entry
    ///
    /// Crate-private: the production entry point for orphan admission is
    /// [`crate::pool::Mempool::try_add_orphan`], which runs the per-peer admission policy
    /// (`check_orphan_pool_policy`) before any insert. This method enforces only the
    /// aggregate hard limit, so bypassing the policy here would admit orphans outside the
    /// per-peer quota and shield them from eviction with their reservation.
    pub(crate) fn insert(&mut self, entry: TxEntry) -> Result<TxStatus, OrphanPoolError> {
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
    ///
    /// A resubmission of an already-parked transaction stays idempotent even when the pool is
    /// full. Otherwise expired entries are dropped first and room is made by evicting only
    /// from origins that exceed their reservation; a still-full pool rejects the newcomer
    /// with [`OrphanPoolError::Full`] instead of displacing another peer's protected entries.
    ///
    /// This enforces the aggregate cap (and expiry); the per-peer remote quota lives in
    /// `TxFinalizer::check_orphan_pool_policy` (`pool/mod.rs`), which every production
    /// caller runs before inserting.
    pub(crate) fn insert_and_enforce_limits(
        &mut self,
        entry: TxEntry,
        cur_time: Time,
    ) -> Result<TxStatus, OrphanPoolError> {
        let tx_id = *entry.tx_id();

        // Sweep expired entries before anything else so that resubmissions of stale entries
        // cannot keep them alive by perpetually short-circuiting on the duplicate check.
        // On the production path the caller has already swept for the policy check, so this
        // pass is a no-op there; it matters for direct callers (unit tests).
        self.remove_expired(cur_time);
        if self.contains(&tx_id) {
            return Ok(TxStatus::InOrphanPoolDuplicate);
        }

        if self.len() >= *self.transaction_count_limit
            && !self.evict_over_reservation(*self.transaction_count_limit)
        {
            return Err(OrphanPoolError::Full);
        }

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
    pub(crate) fn remove_expired(&mut self, cur_time: Time) -> usize {
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

    /// The number of entries an origin of this class is guaranteed to keep when the pool
    /// makes room for newcomers. Outbound (node-selected) peers get the larger share;
    /// whether an origin is outbound is recorded at insertion time from the entry's
    /// options.
    ///
    /// Note the reservation matches the admission quota only for remote origins. Local
    /// admission (`check_orphan_pool_policy`) caps all local origins in aggregate, while
    /// the reservation here protects each distinct local origin key separately, so up to
    /// one reservation per local variant can be kept in aggregate. This is latent today:
    /// the admission cap bounds the total, leaving the aggregate at or below the local
    /// capacity in every reachable state.
    fn origin_reservation(&self, origin: &TxOrigin) -> usize {
        match origin {
            TxOrigin::Local(_) => *self.local_transaction_count_limit,
            TxOrigin::Remote(_) => {
                let outbound = self.maps.origin_stats.get(origin).map_or(false, |s| s.outbound);
                if outbound {
                    *self.outbound_remote_per_peer_limit
                } else {
                    *self.remote_per_peer_limit
                }
            }
        }
    }

    /// The oldest entry of the origin holding the largest number of entries beyond its
    /// reservation. `None` if every origin is within its reservation.
    fn pick_over_reservation(&self) -> Option<InternalId> {
        let mut candidate = None;
        for (origin, stat) in self.maps.origin_stats.iter() {
            let excess = stat.count.saturating_sub(self.origin_reservation(origin));
            if excess > 0 && candidate.map_or(true, |(_, best)| excess > best) {
                candidate = Some((origin, excess));
            }
        }
        let (origin, _) = candidate?;
        self.oldest_of_origin(origin.clone())
    }

    fn oldest_of_origin(&self, origin: TxOrigin) -> Option<InternalId> {
        self.maps
            .by_origin
            .range((origin.clone(), InternalId::ZERO)..=(origin, InternalId::MAX))
            .map(|(_origin, iid)| *iid)
            .min_by_key(|iid| self.get_at(*iid).creation_time())
    }

    /// Make room for a newcomer by evicting only from origins beyond their reservation.
    ///
    /// Complexity is O(evictions × (origins + entries-of-origin)): each eviction rescans
    /// `origin_stats` and range-scans the chosen origin's entries. This is acceptable at
    /// the configured aggregate cap (100 by default) and the production path only reaches
    /// eviction as defense-in-depth, since admission rejects before evicting.
    /// Returns false if the pool is still full, in which case no protected entry was touched.
    fn evict_over_reservation(&mut self, max_size: usize) -> bool {
        while self.len() >= max_size {
            match self.pick_over_reservation() {
                Some(iid) => {
                    self.remove_at(iid);
                }
                None => return false,
            }
        }
        true
    }

    /// Evict transactions until the specified cap is reached
    ///
    /// Origins beyond their reservation are evicted first (largest excess, oldest entry);
    /// otherwise the oldest entry in the pool is evicted. The reservation preference is a
    /// safety net for direct inserts; the admission path never lets a remote origin exceed
    /// its reservation (see [`Self::insert_and_enforce_limits`]).
    fn enforce_max_size(&mut self, max_size: usize) -> usize {
        let mut n_evicted = 0;
        while self.len() > max_size {
            let iid = self
                .pick_over_reservation()
                .or_else(|| self.maps.by_insertion_time.iter().next().map(|(_, iid)| *iid))
                .expect("pool is not empty");
            self.remove_at(iid);
            n_evicted += 1;
        }

        if n_evicted > 0 {
            log::info!("Evicted {n_evicted} transactions from the orphan pool to limit its size");
        }

        n_evicted
    }

    /// Remove orphans for given originator
    pub fn remove_by_origin(&mut self, origin: RemoteTxOrigin) -> usize {
        self.remove_by_origin_impl(TxOrigin::Remote(origin))
    }

    fn remove_by_origin_impl(&mut self, origin: TxOrigin) -> usize {
        let mut n_removed = 0;

        while let Some(iid) = self.pick_by_origin(origin) {
            let _ = self.remove_at(iid);
            n_removed += 1;
        }

        n_removed
    }

    /// Pick one orphan from given origin
    fn pick_by_origin(&self, origin: TxOrigin) -> Option<InternalId> {
        self.maps
            .by_origin
            .range((origin, InternalId::ZERO)..=(origin, InternalId::MAX))
            .map(|(_origin, iid)| *iid)
            .next()
    }

    pub fn get_all_transaction_ids(&self) -> Vec<Id<Transaction>> {
        self.transactions.iter().map(|entry| *entry.tx_id()).collect()
    }

    /// Number of local-origin transactions in the orphan pool
    pub fn local_len(&self) -> usize {
        self.maps.local_count
    }

    /// Number of stored transactions with the given origin
    pub fn origin_len(&self, origin: TxOrigin) -> usize {
        self.maps.origin_stats.get(&origin).map_or(0, |s| s.count)
    }

    /// Total encoded size of stored transactions with the given origin
    #[cfg(test)]
    pub fn origin_size(&self, origin: TxOrigin) -> usize {
        self.maps.origin_stats.get(&origin).map_or(0, |s| s.size)
    }

    /// Number of distinct origins currently tracked by the accounting map
    #[cfg(test)]
    pub fn tracked_origin_count(&self) -> usize {
        self.maps.origin_stats.len()
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
    ///
    /// Note: this function is allowed to produce false positives - if true is returned but the tx
    /// is still an orphan, the tx will be returned to the orphan pool.
    pub fn is_ready(&self) -> bool {
        let entry = self.get();
        !entry.required_deps().any(|dep| match dep {
            TxRequiredDependency::TxOutput(tx_id, _) => {
                self.pool.maps.by_tx_id.contains_key(&tx_id)
            }

            // Always consider account deps.
            // Note: simply checking whether any of the orphan txs' provided dependencies are
            // required by this tx (like we do in the utxo case) won't work because there can be
            // multiple potential parents for it in the orphan pool; if one of the parents becomes
            // non-orphan and the other stays in the orphan pool, it will prevent the child from
            // entering the normal mempool even though in reality it's no longer an orphan.
            TxRequiredDependency::DelegationSpending(_, _)
            | TxRequiredDependency::TokenAccountManagement(_, _)
            | TxRequiredDependency::PoolCreation(_)
            | TxRequiredDependency::DelegationCreation(_)
            | TxRequiredDependency::TokenCreation(_)
            | TxRequiredDependency::OrderCreation(_) => false,
        })
    }

    /// Take the entry, removing it from the orphan pool
    pub fn take(self) -> TxEntry {
        self.pool.remove_at(self.iid)
    }
}

#[cfg(test)]
mod test;
