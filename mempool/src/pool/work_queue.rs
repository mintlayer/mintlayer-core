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

//! Per-peer work processing schedule queue and related tools.

use std::collections::{btree_map, BTreeMap, BTreeSet};

use crypto::random::{self, Rng, SliceRandom};
use p2p_types::PeerId;

/// Per-peer work schedule queue
#[derive(Eq, PartialEq, Clone, Debug)]
struct PeerQueue<W> {
    queue: BTreeSet<W>,
}

impl<W: Ord> PeerQueue<W> {
    fn new(item: W) -> Self {
        let queue = BTreeSet::from_iter([item]);
        Self { queue }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn insert(&mut self, item: W) -> bool {
        self.queue.insert(item)
    }

    /// Perform a work unit from this queue
    fn perform<R>(&mut self, mut handler: impl FnMut(W) -> Option<R>) -> Option<R> {
        loop {
            if let Some(ret) = handler(self.queue.pop_first()?) {
                break Some(ret);
            }
        }
    }
}

/// Work queue for scheduling orphan transaction processing.
///
/// Submitting a transaction could trigger a cascade of orphans in need of processing to figure out
/// if they can be included in the mempool. After submitting a transaction, instead of processing
/// the all the orphan descendants in one go, we schedule the children to be processed later by
/// putting them in this queue. This is to ensure some degree of fairness with respect to the
/// amount of computation dedicated to requests from individual peers, mitigating some forms of DoS
/// attacks.
///
/// ### Scheduling fairness
///
/// To ensure a peer does not starve other peers, the schedule is issued in rounds. Each round, one
/// work unit is processed for each peer that has work to do. A new round is issued whenever all
/// the peers with work have been already served in the current round.
///
/// Within a round, peers are served in random order.
///
/// ### Internal states
///
/// Work queue can be in one of the following states with respect to each peer. The states are:
///
/// * `Absent`: Peer does not have an entry in the queue (i.e. no work in this or future rounds).
///   * Transitions to `Scheduled` on `insert`
///   * Stays `Absent` in all other events
/// * `Scheduled`: Peer has work to do in this round
///   * By invariant, new round is only issued when there are no `Scheduled` peers.
///   * Stays `Scheduled` on `insert`
///   * Transitions to `Waiting` when it's been served in this round and has more work to do
///   * Transitions to `Done` when it's been served in this round and has NO more work to do
///   * Transitions to `Disconnected` when the peer disconnects
/// * `Waiting`: Peer is waiting for the next round (has already been served in this round).
///   * Transitions to `Scheduled` on new round
///   * Stays `Waiting` on `insert` (with its queue extended with the extra work)
///   * Transitions to `Absent` when the peer disconnects
/// * `Done`: Peer is done for this round and does NOT have more work to do.
///   * Transitions to `Absent` on new round
///   * Transitions to `Waiting` on `insert`
/// * `Dsconnected`: A peer disconnected but is still hanging around in the scheduled set.
///   * This is a temporary state when peer has disconnected and it's queue has been removed but is
///     still hanging around in the scheduled set. Removing it from the scheduled set immediately
///     requires a linear scan, so for efficiency reasons, it's done lazily when we pick the next
///     peer to process work for.
///   * Transitions to `Absent` when it's entry in the schedule set is processed.
///
/// Note: Peer IDs that end up in the `Absent` by disconnecting will be stuck there because peer
/// IDs are effectively not reused.
///
/// The states are encoded implicitly by the data structure and can be detected like this:
///
/// ```ignore
/// match (scheduled.contains(peer), work_queue.get(peer).map(|q| q.is_empty())) {
///     (false, None) => "Absent",
///     (false, Some(false)) => "Waiting",
///     (false, Some(true)) => "Done",
///     (true, None) => "Disconnected",
///     (true, Some(false)) => "Scheduled",
///     (true, Some(true)) => panic!("Data structure invariant violated"),
/// }
/// ```
///
/// The panic should never happen as a data structure invariant. Intuitively, it specifies that if
/// a peer is scheduled in the scheduled set, it must have a work item to do.
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct WorkQueue<W> {
    /// Per-peer set of work items to do
    work_queue: BTreeMap<PeerId, PeerQueue<W>>,

    /// Peers that have not been served in this round yet
    ///
    /// This item is not strictly necessary, all the information is already contained in the work
    /// queue. However, it is useful for picking the next peer to perform work for quickly with
    /// uniform probability.
    scheduled: Vec<PeerId>,
}

impl<W: Ord> WorkQueue<W> {
    /// New empty work queue
    pub fn new() -> Self {
        Self {
            work_queue: BTreeMap::new(),
            scheduled: Vec::new(),
        }
    }

    /// Check if the work queue is empty
    pub fn is_empty(&self) -> bool {
        self.scheduled.is_empty()
    }

    /// Insert a new work item. Return true if it has been inserted (there may be duplicates).
    pub fn insert(&mut self, peer: PeerId, item: W) -> bool {
        // If the peer already has an entry in the map, we schedule the item into the future. If
        // the peer does not have an entry in the map, it means it has not yet been served in this
        // round so we create a new queue for the peer with the item scheduled in this round.
        match self.work_queue.entry(peer) {
            btree_map::Entry::Occupied(mut e) => e.get_mut().insert(item),
            btree_map::Entry::Vacant(e) => {
                // We insert the peer into the scheduled vec. Due to various lifetime and
                // mutability issues, it's slightly awkward. We first push it at the end and then
                // swap it with a random other element in the vec.
                self.scheduled.push(peer);
                let pos = random::make_pseudo_rng().gen_range(0..self.scheduled.len());
                let last = self.scheduled.len() - 1;
                self.scheduled.swap(pos, last);

                // Insert a queue for this peer
                e.insert(PeerQueue::new(item));

                true
            }
        }
    }

    /// Perform a unit of work, picking the next peer from the scheduled set.
    ///
    /// The actual work is done by the provided handler function, the schedule queue is only
    /// concerned with picking the next peer and work item to be processed.
    ///
    /// The handler controls whether it's done with this peer by returning an [Option] value:
    /// * `None`: This work item was looked at but does not qualify as work so it is trivially
    ///   dismissed by the handler. Another work item is picked immediately.
    /// * `Some(ret)`: This work item has been processed successfully. The peer will be scheduled
    ///   again in the next round at soonest. A return value may be provided.
    ///
    /// The function returns the value returned by the handler or `None` if no work items for the
    /// peer picked have been successfully processed this time.
    pub fn perform<R>(&mut self, mut handler: impl FnMut(PeerId, W) -> Option<R>) -> Option<R> {
        // Pick a peer from the scheduled set
        loop {
            let peer = self.scheduled.pop()?;

            // Only consider peers that actually have work to do
            match self.work_queue.entry(peer) {
                btree_map::Entry::Vacant(_) => {
                    self.advance_round();
                }
                btree_map::Entry::Occupied(mut peer_queue_entry) => {
                    let peer_queue = peer_queue_entry.get_mut();
                    assert!(!peer_queue.is_empty());

                    // Perform the work from the queue
                    let result = peer_queue.perform(move |work| handler(peer, work));

                    self.advance_round();

                    break result;
                }
            }
        }
    }

    /// Remove peer and it's work items
    pub fn remove_peer(&mut self, peer: PeerId) -> bool {
        self.work_queue.remove(&peer).is_some()
    }

    /// Advance to the next round if the current one is over.
    fn advance_round(&mut self) {
        if self.scheduled.is_empty() {
            // Put all peers that still have work into the scheduled set
            self.work_queue.retain(|peer, pq| {
                let has_work = !pq.is_empty();
                if has_work {
                    self.scheduled.push(*peer);
                }
                has_work
            });

            // Place the scheduled set in random order
            self.scheduled.shuffle(&mut random::make_pseudo_rng());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use logging::log;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    impl<W: Ord> WorkQueue<W> {
        fn check_integrity(&self) {
            let scheduled_set: BTreeSet<_> = self.scheduled.iter().copied().collect();

            assert_eq!(
                scheduled_set.len(),
                self.scheduled.len(),
                "Scheduled peers not unique",
            );

            for peer_q in scheduled_set.iter().filter_map(|peer| self.work_queue.get(peer)) {
                assert!(!peer_q.is_empty(), "Scheduled peer has no work");
            }
        }
    }

    fn random_peer_queue(rng: &mut impl Rng) -> PeerQueue<u16> {
        let mut pq = PeerQueue::new(rng.gen());
        let n_items = rng.gen_range(0..100);
        pq.queue.extend((0..n_items).map(|_| rng.gen::<u16>()));
        pq
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn peer_queue_perform_one(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut pq = random_peer_queue(&mut rng);
        let first = *pq.queue.first().unwrap();
        let len_before = pq.queue.len();

        let mut num_iters = 0;
        let result = pq.perform(|w| {
            num_iters += 1;
            assert_eq!(w, first);
            Some("foo")
        });

        assert_eq!(result, Some("foo"));
        assert_eq!(num_iters, 1);
        assert_eq!(pq.queue.len(), len_before - 1);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn peer_queue_perform_fail(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut pq = random_peer_queue(&mut rng);
        let len_before = pq.queue.len();

        let mut num_iters = 0;
        let result: Option<&str> = pq.perform(|_| {
            num_iters += 1;
            None
        });

        assert_eq!(result, None);
        assert_eq!(num_iters, len_before);
        assert!(pq.is_empty());
    }

    #[derive(Debug)]
    struct PeerIdSupply {
        active: Vec<PeerId>,
        next: u64,
    }

    impl PeerIdSupply {
        fn new() -> Self {
            let active = Vec::new();
            let next = 1u64;
            Self { active, next }
        }

        fn gen(&mut self, rng: &mut impl Rng, extra: usize) -> PeerId {
            self.active
                .get(rng.gen_range(0..(self.active.len() + extra)))
                .copied()
                .unwrap_or({
                    let peer = PeerId::from_u64(self.next);
                    self.active.push(peer);
                    self.next += 1;
                    peer
                })
        }

        fn disconnect(&mut self, peer: PeerId) {
            self.active
                .iter()
                .position(|p| *p == peer)
                .map(|pos| self.active.swap_remove(pos));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn simulation(#[case] seed: Seed) {
        logging::init_logging::<&str>(None);
        let mut rng = make_seedable_rng(seed);
        let mut peer_supply = PeerIdSupply::new();

        let mut wq = WorkQueue::<u64>::new();
        assert!(wq.is_empty());
        wq.check_integrity();

        // Work items are represented just by 64-bit tickets
        let mut next_item = 0u64;
        let mut processed = BTreeSet::new();

        for _ in 0..500 {
            match rng.gen_range(1..=6) {
                1..=3 => {
                    let peer = peer_supply.gen(&mut rng, 2);
                    log::debug!("Inserting into peer{peer}'s queue: {next_item:03}");

                    wq.insert(peer, next_item);
                    next_item += 1;
                }
                4..=5 => {
                    log::debug!("Scheduled: {:?}", wq.scheduled);

                    match wq.perform(|peer, work| Some((peer, work))) {
                        Some((peer, work)) => {
                            log::debug!("Performed peer{peer}'s work: {work:03}");
                            assert!(processed.insert(work), "Item {work} processed twice");
                        }
                        None => log::debug!("No more work to do"),
                    }
                }
                6..=6 => {
                    let peer = peer_supply.gen(&mut rng, 1);
                    log::debug!("Removing peer{peer}");

                    // Mark peer's work set as processed
                    wq.work_queue.get(&peer).map(|q| processed.extend(q.queue.iter().copied()));

                    wq.remove_peer(peer);
                    peer_supply.disconnect(peer);
                }
                _ => unreachable!("out of generated range"),
            }
            wq.check_integrity();
        }

        // Finish the processing of the queue
        let mut iter = 0;
        while let Some(work) = wq.perform(|_peer, work| Some(work)) {
            assert!(processed.insert(work), "Item {work} processed twice");
            assert!(
                iter < next_item,
                "Processing takes more iterations than items to process"
            );
            iter += 1;
        }

        // Check all items have been processed (or marked as processed upon a peer removal)
        assert_eq!(
            processed.len(),
            next_item as usize,
            "Not all items processed"
        );
        assert_eq!(
            processed.last().copied(),
            next_item.checked_sub(1),
            "Items out of thin air"
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn scheduling_fairness_full_queues(#[case] seed: Seed) {
        // Minimum number of work items in each peer's queue at the start
        const MIN_WORK: usize = 100;

        logging::init_logging::<&str>(None);
        let mut rng = make_seedable_rng(seed);
        let num_peers: usize = rng.gen_range(2..=8);
        let peer1 = PeerId::from_u64(1);
        let mut next_item = 0u64;

        let mut wq = WorkQueue::new();

        // Pre-populate the queue with at least MIN_ELEMS for each peer. We also fill the queue in
        // the peer-by-peer order and later observe if work for peers is interleaved.
        for peer in 1..=num_peers {
            for _ in 0..rng.gen_range(MIN_WORK..(MIN_WORK + 100)) {
                wq.insert(PeerId::from_u64(peer as u64), next_item);
                next_item += 1;
                wq.check_integrity();
            }
        }

        // Keep track of the order in which peers are served
        let mut peer_trace = Vec::new();

        for _ in 0..(MIN_WORK * num_peers) {
            // Peer 1 is a designated adversary trying to fill the queue at a high rate.
            // Despite this, it should not get any larger slice of time than other peers.
            for _ in 0..rng.gen_range(0..4) {
                wq.insert(peer1, next_item);
                next_item += 1;
            }

            // Perform a unit of work
            let peer = wq.perform(|peer, _work| Some(peer)).unwrap();
            log::trace!("Served peer{peer}");
            peer_trace.push(peer);
            wq.check_integrity();
        }

        // Helper to inspect the trace
        let inspect_trace = |n: usize| {
            let window_size = n * num_peers;
            let work_range = (n - 1)..=(n + 1);

            // Initialize the per-peer amount of work with the window at the start of the trace
            let mut work_per_peer =
                BTreeMap::from_iter((1..=num_peers).map(|n| (PeerId::from_u64(n as u64), 0)));
            for peer in &peer_trace[0..window_size] {
                *work_per_peer.get_mut(peer).unwrap() += 1;
            }

            // Check the per-peer work at the start of the trace is within expected bounds
            for (peer, num_work_units) in work_per_peer.iter() {
                assert!(
                    work_range.contains(num_work_units),
                    "peer{peer} out of range"
                );
            }

            // Slide the window along the trace, checking the work is within bounds as we go
            for (peer_out, peer_in) in peer_trace.iter().zip(peer_trace[window_size..].iter()) {
                *work_per_peer.get_mut(peer_out).unwrap() -= 1;
                *work_per_peer.get_mut(peer_in).unwrap() += 1;
                assert!(
                    work_range.contains(&work_per_peer[peer_out]),
                    "peer{peer_out} out of range",
                );
                assert!(
                    work_range.contains(&work_per_peer[peer_in]),
                    "peer{peer_in} out of range"
                );
            }
        };

        // Trace windows of size 2 * num_peers should have each peer scheduled 1 to 3 times
        inspect_trace(2);

        // Trace windows of size 4 * num_peers should have each peer scheduled 4 to 6 times
        inspect_trace(4);

        // Trace windows of size 10 * num_peers should have each peer scheduled 9 to 11 times
        inspect_trace(10);
    }
}
