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

//! Chain-aware repush planning and mempool reconciliation.
//!
//! This module contains the pure decision logic used by the controller's
//! periodic reconcile-and-rebroadcast pass:
//!
//! - [`topological_order`] orders pending transactions so that parents are
//!   always submitted before their children;
//! - [`RepushTracker`] keeps the per-transaction retry state (attempts,
//!   backoff, stuck flag);
//! - [`reconcile`] classifies pending transactions against their mempool
//!   presence into "submit now" and "dead, prune" sets.
//!
//! The imperative shell (RPC calls, wallet access) lives in `lib.rs`.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use common::chain::Transaction;
use common::primitives::Id;
use common::primitives::time::Time;

/// Backoff before the first retry of a failed submission.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(30);

/// Upper bound for the exponential backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Give up retrying (mark as stuck) after this many failed submission attempts.
pub const MAX_ATTEMPTS: u32 = 10;

/// Give up retrying (mark as stuck) once a transaction has been pending for this long.
pub const MAX_PENDING_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// A pending (unconfirmed) transaction with the information needed to plan its submission.
#[derive(Debug, Clone)]
pub struct PendingTx {
    pub id: Id<Transaction>,
    /// IDs of pending transactions whose outputs this transaction spends
    /// (block-reward and confirmed sources are not included).
    pub pending_parents: Vec<Id<Transaction>>,
    /// The account nonce of the transaction, if it has nonce-bearing inputs.
    /// Used as a tie-breaker for transactions without pending UTXO parents,
    /// since account nonces must be submitted consecutively.
    pub nonce: Option<u64>,
}

/// Per-transaction retry state.
#[derive(Debug, Clone, Copy)]
struct EntryState {
    attempts: u32,
    next_attempt: Time,
    first_seen: Time,
    stuck: bool,
    /// Set when the node itself observed a submission (i.e. a submission
    /// failed with a node rejection response, not with a delivery failure).
    node_observed: bool,
}

/// Tracks submission attempts of pending transactions.
#[derive(Debug, Default)]
pub struct RepushTracker {
    entries: BTreeMap<Id<Transaction>, EntryState>,
}

/// The result of a failed submission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureVerdict {
    /// Retry after the returned delay.
    Retry(Time),
    /// The retry budget is exhausted; the transaction is skipped until it is
    /// abandoned manually or the wallet restarts.
    Stuck,
}

impl RepushTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_stuck(&self, tx_id: &Id<Transaction>) -> bool {
        self.entries.get(tx_id).is_some_and(|state| state.stuck)
    }

    /// Whether the node itself has observed at least one submission of this
    /// transaction (a submission that failed with a node rejection response).
    /// Delivery failures (transport errors, timeouts) do not count: the node
    /// may never have seen the transaction at all.
    pub fn node_observed(&self, tx_id: &Id<Transaction>) -> bool {
        self.entries.get(tx_id).is_some_and(|state| state.node_observed)
    }

    /// Drops state for transactions that are no longer pending, so that the
    /// tracker does not accumulate entries for confirmed/pruned transactions.
    pub fn retain_where(&mut self, mut keep: impl FnMut(&Id<Transaction>) -> bool) {
        self.entries.retain(|id, _| keep(id));
    }

    /// Whether the transaction should be (re)submitted now. Transactions that
    /// were never attempted are always due.
    pub fn is_due(&self, tx_id: &Id<Transaction>, now: Time) -> bool {
        !self.is_stuck(tx_id)
            && self.entries.get(tx_id).is_none_or(|state| state.next_attempt <= now)
    }

    /// A successful (or idempotent) submission; the retry state is reset, so a
    /// transaction that later drops out of the mempool gets a fresh budget.
    /// Note: this also resets the "attempted" flag, meaning a transaction that
    /// was successfully submitted before and then dropped from the mempool is
    /// treated as resubmittable, not as rejected.
    pub fn on_success(&mut self, tx_id: &Id<Transaction>, now: Time) {
        self.entries.insert(
            *tx_id,
            EntryState {
                attempts: 0,
                next_attempt: now,
                first_seen: now,
                stuck: false,
                node_observed: false,
            },
        );
    }

    /// The node received the submission and rejected it; counts against the
    /// retry budget and marks the transaction as node-observed.
    pub fn on_rejected(&mut self, tx_id: &Id<Transaction>, now: Time) -> FailureVerdict {
        let entry = self.entries.entry(*tx_id).or_insert(EntryState {
            attempts: 0,
            next_attempt: now,
            first_seen: now,
            stuck: false,
            node_observed: false,
        });

        entry.attempts += 1;
        entry.node_observed = true;

        if entry.attempts >= MAX_ATTEMPTS || now.saturating_sub(entry.first_seen) >= MAX_PENDING_AGE
        {
            entry.stuck = true;
            return FailureVerdict::Stuck;
        }

        let backoff = INITIAL_BACKOFF
            .checked_mul(2u32.saturating_pow(entry.attempts.saturating_sub(1)))
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF);

        entry.next_attempt = now.saturating_duration_add(backoff);

        FailureVerdict::Retry(entry.next_attempt)
    }

    /// The submission could not be delivered (transport error, timeout, node
    /// unavailable). This does not count against the rejection budget and does
    /// not mark the transaction as node-observed, since the node may never
    /// have seen it. Only the age limit can turn such a transaction stuck.
    pub fn on_delivery_failure(&mut self, tx_id: &Id<Transaction>, now: Time) -> FailureVerdict {
        let entry = self.entries.entry(*tx_id).or_insert(EntryState {
            attempts: 0,
            next_attempt: now,
            first_seen: now,
            stuck: false,
            node_observed: false,
        });

        if now.saturating_sub(entry.first_seen) >= MAX_PENDING_AGE {
            entry.stuck = true;
            return FailureVerdict::Stuck;
        }

        entry.next_attempt = now.saturating_duration_add(INITIAL_BACKOFF);

        FailureVerdict::Retry(entry.next_attempt)
    }

    /// Forget a transaction entirely (e.g. it was pruned or confirmed).
    pub fn forget(&mut self, tx_id: &Id<Transaction>) {
        self.entries.remove(tx_id);
    }
}

/// Ordering key used to break ties between transactions without pending
/// parents: nonce-bearing transactions first (in nonce order), then by
/// transaction ID.
fn tie_break_key(
    by_id: &BTreeMap<Id<Transaction>, &PendingTx>,
    id: &Id<Transaction>,
) -> (u64, Id<Transaction>) {
    let nonce = by_id.get(id).and_then(|tx| tx.nonce).unwrap_or(u64::MAX);
    (nonce, *id)
}

/// Order the pending transactions so that every transaction comes after all of
/// its pending parents (connected through [`PendingTx::pending_parents`]).
/// Cycles (which should not occur for valid transaction graphs) are broken
/// deterministically by the tie-break key, so this function always terminates
/// and returns all given transactions.
pub fn topological_order(pending: &[PendingTx]) -> Vec<Id<Transaction>> {
    let by_id: BTreeMap<Id<Transaction>, &PendingTx> =
        pending.iter().map(|tx| (tx.id, tx)).collect();

    let mut remaining_parents: BTreeMap<Id<Transaction>, usize> = pending
        .iter()
        .map(|tx| {
            let count =
                tx.pending_parents.iter().filter(|parent| by_id.contains_key(parent)).count();
            (tx.id, count)
        })
        .collect();

    // Children by parent ID, for decreasing the parent counters.
    let mut children: BTreeMap<Id<Transaction>, Vec<Id<Transaction>>> = BTreeMap::new();
    for tx in pending {
        for parent in &tx.pending_parents {
            if by_id.contains_key(parent) {
                children.entry(*parent).or_default().push(tx.id);
            }
        }
    }

    let mut ready: Vec<Id<Transaction>> = remaining_parents
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(id, _)| *id)
        .collect();

    let mut ordered = Vec::with_capacity(pending.len());
    while !ready.is_empty() {
        // Deterministic order within a batch of ready transactions.
        ready.sort_by_key(|id| tie_break_key(&by_id, id));

        for id in std::mem::take(&mut ready) {
            ordered.push(id);
            if let Some(tx_children) = children.get(&id) {
                for child in tx_children {
                    let count = remaining_parents
                        .get_mut(child)
                        .expect("child registered in remaining_parents");
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.push(*child);
                    }
                }
            }
        }
    }

    // Anything left is part of a cycle; append it in tie-break order so that we
    // neither lose transactions nor loop forever.
    if ordered.len() < pending.len() {
        logging::log::warn!(
            "dependency cycle among pending transactions; appending {} transaction(s) \
             in tie-break order, children may be submitted before their parents",
            pending.len() - ordered.len(),
        );
        let mut leftovers: Vec<Id<Transaction>> =
            remaining_parents.into_keys().filter(|id| !ordered.contains(id)).collect();
        leftovers.sort_by_key(|id| tie_break_key(&by_id, id));
        ordered.extend(leftovers);
    }

    ordered
}

/// The outcome of a reconciliation pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Transactions to (re)submit, in topological order.
    pub to_submit: Vec<Id<Transaction>>,
    /// Transactions deterministically rejected by the node (present parent +
    /// missing child), plus their pending descendants. They must be pruned.
    pub to_prune: Vec<Id<Transaction>>,
}

/// Classify pending transactions against their mempool presence.
///
/// - A transaction present in the mempool is alive and left alone.
/// - A transaction missing from the mempool while its parent is present there
///   is considered deterministically rejected, but it is only marked for
///   pruning if the node has actually observed a submission attempt of it
///   ([`RepushTracker::node_observed`]); mempool absence alone is not proof of
///   rejection, since the transaction may never have been broadcast. Pruned
///   transactions take all of their pending descendants with them.
/// - Any other missing transaction is a candidate for (re)submission; stuck
///   transactions are skipped.
///
/// `presence` should contain an entry for every transaction in `pending`; if
/// it does not (e.g. duplicate ids in the input data), the affected
/// transactions are skipped and a default (empty) outcome is returned for the
/// malformed part of the input instead of panicking.
pub fn reconcile(
    pending: &[PendingTx],
    presence: &BTreeMap<Id<Transaction>, bool>,
    tracker: &RepushTracker,
) -> ReconcileOutcome {
    if pending.len() != presence.len() {
        logging::log::error!(
            "presence map ({} entries) does not cover all pending transactions ({}); \
             skipping this reconcile pass",
            presence.len(),
            pending.len(),
        );
        return ReconcileOutcome::default();
    }

    let mut outcome = ReconcileOutcome::default();

    for tx in pending {
        let Some(present) = presence.get(&tx.id).copied() else {
            logging::log::warn!("presence missing for transaction {:x}; skipping it", tx.id);
            continue;
        };

        if present {
            continue;
        }

        let parent_present = tx
            .pending_parents
            .iter()
            .any(|parent| presence.get(parent).copied().unwrap_or(false));

        if parent_present && tracker.node_observed(&tx.id) {
            // The node saw the transaction, had everything needed to connect it
            // and still does not have it: deterministically rejected.
            outcome.to_prune.push(tx.id);
        } else if !tracker.is_stuck(&tx.id) {
            outcome.to_submit.push(tx.id);
        }
    }

    // Pruned transactions take their pending descendants with them.
    let children: BTreeMap<Id<Transaction>, Vec<Id<Transaction>>> = {
        let mut children: BTreeMap<Id<Transaction>, Vec<Id<Transaction>>> = BTreeMap::new();
        for tx in pending {
            for parent in &tx.pending_parents {
                children.entry(*parent).or_default().push(tx.id);
            }
        }
        children
    };

    let mut pruned: HashSet<Id<Transaction>> = outcome.to_prune.iter().copied().collect();
    let mut queue: Vec<Id<Transaction>> = std::mem::take(&mut outcome.to_prune);
    while let Some(pruned_id) = queue.pop() {
        if let Some(tx_children) = children.get(&pruned_id) {
            for child in tx_children {
                if pruned.insert(*child) {
                    queue.push(*child);
                }
            }
        }
    }
    outcome.to_prune = pruned.iter().copied().collect();
    outcome.to_prune.sort();

    outcome.to_submit.retain(|id| !pruned.contains(id));
    outcome.to_submit = topological_order(
        &pending
            .iter()
            .filter(|tx| outcome.to_submit.contains(&tx.id))
            .cloned()
            .collect::<Vec<_>>(),
    );

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::primitives::H256;

    fn test_id(n: u64) -> Id<Transaction> {
        H256::from_low_u64_be(n).into()
    }

    fn pt(id: u64, parents: Vec<u64>) -> PendingTx {
        PendingTx {
            id: test_id(id),
            pending_parents: parents.into_iter().map(test_id).collect(),
            nonce: None,
        }
    }

    fn now() -> Time {
        Time::from_secs_since_epoch(1_000_000)
    }

    #[test]
    fn topological_order_parents_first() {
        // 1 -> 2 -> 4; 1 -> 3 -> 4
        let pending = vec![pt(4, vec![2, 3]), pt(2, vec![1]), pt(3, vec![1]), pt(1, vec![])];
        let ordered = topological_order(&pending);
        assert_eq!(
            ordered,
            vec![test_id(1), test_id(2), test_id(3), test_id(4)]
        );
    }

    #[test]
    fn topological_order_terminates_on_cycle() {
        // 1 -> 2 -> 1: a cycle; the function must terminate and return everything
        let pending = vec![pt(1, vec![2]), pt(2, vec![1]), pt(3, vec![])];
        let ordered = topological_order(&pending);
        assert_eq!(ordered.len(), 3);
        assert!(ordered.contains(&test_id(3)));
    }

    #[test]
    fn tracker_backoff_and_stuck() {
        let mut tracker = RepushTracker::new();
        let id = test_id(1);
        let t = now();

        assert!(tracker.is_due(&id, t));

        match tracker.on_rejected(&id, t) {
            FailureVerdict::Retry(next) => {
                assert_eq!(next.saturating_sub(t), INITIAL_BACKOFF);
                assert!(!tracker.is_due(&id, t));
                assert!(tracker.is_due(&id, t.saturating_duration_add(INITIAL_BACKOFF)));
            }
            FailureVerdict::Stuck => panic!("must not be stuck on first failure"),
        }

        // Exhaust the budget
        let mut t = t;
        for _ in 1..MAX_ATTEMPTS {
            t = t.saturating_duration_add(MAX_BACKOFF);
            tracker.on_rejected(&id, t);
        }
        assert_eq!(tracker.on_rejected(&id, t), FailureVerdict::Stuck);
        assert!(tracker.is_stuck(&id));
        assert!(!tracker.is_due(&id, t));
    }

    #[test]
    fn tracker_success_resets() {
        let mut tracker = RepushTracker::new();
        let id = test_id(1);
        let t = now();

        tracker.on_rejected(&id, t);
        tracker.on_success(&id, t);
        assert!(tracker.is_due(&id, t));
        assert!(!tracker.is_stuck(&id));

        // After a success the budget is fresh again
        for i in 0..(MAX_ATTEMPTS - 1) {
            let t = t.saturating_duration_add(Duration::from_secs(i as u64 + 1));
            tracker.on_rejected(&id, t);
        }
        assert!(!tracker.is_stuck(&id));
    }

    #[test]
    fn reconcile_submits_all_missing_without_present_parents() {
        let pending = vec![pt(1, vec![]), pt(2, vec![1]), pt(3, vec![])];
        let presence: BTreeMap<_, _> = (1..=3).map(|i| (test_id(i), false)).collect();
        let tracker = RepushTracker::new();

        let outcome = reconcile(&pending, &presence, &tracker);
        assert_eq!(outcome.to_prune, Vec::<Id<Transaction>>::new());
        // 1 and 3 are ready immediately; 2 becomes ready after 1
        assert_eq!(outcome.to_submit, vec![test_id(1), test_id(3), test_id(2)]);
    }

    #[test]
    fn reconcile_prunes_deterministically_rejected_subtree() {
        // 1 present; 2 missing (deterministically rejected: its parent is present and the
        // node has observed a submission attempt of 2); 3 (child of 2) missing -> pruned
        // together with 2; 4 unrelated missing -> submit.
        let pending = vec![pt(1, vec![]), pt(2, vec![1]), pt(3, vec![2]), pt(4, vec![])];
        let presence: BTreeMap<_, _> = (1..=4).map(|i| (test_id(i), i == 1)).collect();

        let mut tracker = RepushTracker::new();
        tracker.on_rejected(&test_id(2), now()); // the node rejected one submission of 2

        let outcome = reconcile(&pending, &presence, &tracker);
        assert_eq!(outcome.to_prune, vec![test_id(2), test_id(3)]);
        assert_eq!(outcome.to_submit, vec![test_id(4)]);
    }

    #[test]
    fn reconcile_does_not_prune_never_attempted_transactions() {
        // 1 present; 2 missing with parent present, but the node has never seen a
        // submission of 2 (e.g. its first broadcast failed with a transport error):
        // it must be (re)submitted, not pruned.
        let pending = vec![pt(1, vec![]), pt(2, vec![1]), pt(3, vec![2])];
        let presence: BTreeMap<_, _> = (1..=3).map(|i| (test_id(i), i == 1)).collect();
        let tracker = RepushTracker::new();

        let outcome = reconcile(&pending, &presence, &tracker);
        assert_eq!(outcome.to_submit, vec![test_id(2), test_id(3)]);
        assert!(outcome.to_prune.is_empty());
    }

    #[test]
    fn reconcile_resubmits_previously_successful_dropped_transaction() {
        // 1 present; 2 missing, attempted before but its last submission SUCCEEDED
        // (on_success resets the attempted flag): it was dropped by churn and must
        // be resubmitted, not pruned.
        let pending = vec![pt(1, vec![]), pt(2, vec![1])];
        let presence: BTreeMap<_, _> = (1..=2).map(|i| (test_id(i), i == 1)).collect();

        let mut tracker = RepushTracker::new();
        tracker.on_rejected(&test_id(2), now());
        tracker.on_success(&test_id(2), now());

        let outcome = reconcile(&pending, &presence, &tracker);
        assert_eq!(outcome.to_submit, vec![test_id(2)]);
        assert!(outcome.to_prune.is_empty());
    }

    #[test]
    fn delivery_failures_do_not_burn_rejection_budget() {
        let mut tracker = RepushTracker::new();
        let id = test_id(1);
        let mut t = now();

        for _ in 0..MAX_ATTEMPTS {
            t = t.saturating_duration_add(INITIAL_BACKOFF);
            assert_eq!(
                tracker.on_delivery_failure(&id, t),
                FailureVerdict::Retry(t.saturating_duration_add(INITIAL_BACKOFF))
            );
        }

        // None of the delivery failures counted against the budget, so the first
        // rejection still has retries left instead of being stuck.
        assert!(!tracker.is_stuck(&id));
        assert!(!tracker.node_observed(&id));
        assert!(matches!(
            tracker.on_rejected(&id, t),
            FailureVerdict::Retry(_)
        ));
    }

    #[test]
    fn reconcile_does_not_prune_delivery_failed_transactions() {
        // 1 present; 2 missing with parent present, and 2 has failed submission
        // attempts, but every failure was a delivery failure (the node never saw
        // it): it must be (re)submitted, not pruned.
        let pending = vec![pt(1, vec![]), pt(2, vec![1])];
        let presence: BTreeMap<_, _> = (1..=2).map(|i| (test_id(i), i == 1)).collect();

        let mut tracker = RepushTracker::new();
        tracker.on_delivery_failure(&test_id(2), now());

        let outcome = reconcile(&pending, &presence, &tracker);
        assert_eq!(outcome.to_submit, vec![test_id(2)]);
        assert!(outcome.to_prune.is_empty());
    }

    #[test]
    fn reconcile_skips_stuck() {
        let pending = vec![pt(1, vec![])];
        let presence: BTreeMap<_, _> = (1..=1).map(|i| (test_id(i), false)).collect();

        let mut tracker = RepushTracker::new();
        let id = test_id(1);
        let t = now();
        for _ in 0..MAX_ATTEMPTS {
            tracker.on_rejected(&id, t);
        }

        let outcome = reconcile(&pending, &presence, &tracker);
        assert!(outcome.to_submit.is_empty());
        assert!(outcome.to_prune.is_empty());
    }

    #[test]
    fn reconcile_present_transactions_left_alone() {
        let pending = vec![pt(1, vec![]), pt(2, vec![1])];
        let presence: BTreeMap<_, _> = (1..=2).map(|i| (test_id(i), true)).collect();
        let tracker = RepushTracker::new();

        let outcome = reconcile(&pending, &presence, &tracker);
        assert!(outcome.to_submit.is_empty());
        assert!(outcome.to_prune.is_empty());
    }
}
