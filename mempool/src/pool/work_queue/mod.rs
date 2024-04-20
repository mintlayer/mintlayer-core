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

use p2p_types::PeerId;
use randomness::{self, Rng, SliceRandom};

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
/// all the orphan descendants in one go, we schedule the children to be processed later by putting
/// them in this queue. This is to ensure some degree of fairness with respect to the amount of
/// computation dedicated to requests from individual peers, mitigating some forms of DoS attacks.
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
/// * `Disconnected`: A peer disconnected but is still hanging around in the scheduled set.
///   * This is a temporary state when peer has disconnected and it's queue has been removed but is
///     still hanging around in the scheduled set. Removing it from the scheduled set immediately
///     requires a linear scan, so for efficiency reasons, it's done lazily when we pick the next
///     peer to process work for.
///   * Transitions to `Absent` when it's entry in the schedule set is processed.
///
/// Note: Peer IDs that end up in the `Absent` state by disconnecting will be stuck there because
/// peer IDs are effectively not reused.
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
                let pos = randomness::make_pseudo_rng().gen_range(0..self.scheduled.len());
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
            self.scheduled.shuffle(&mut randomness::make_pseudo_rng());
        }
    }

    #[cfg(test)]
    pub fn total_len(&self) -> usize {
        self.work_queue.values().map(|q| q.queue.len()).sum()
    }
}

#[cfg(test)]
mod test;
