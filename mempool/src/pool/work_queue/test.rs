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
    let result = pq.pick(|w| {
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
    let result: Option<&str> = pq.pick(|_| {
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

                match wq.pick(|peer, work| Some((peer, work))) {
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
                if let Some(peer_queue) = wq.work_queue.get(&peer) {
                    processed.extend(peer_queue.queue.iter().copied());
                }

                wq.remove_peer(peer);
                peer_supply.disconnect(peer);
            }
            _ => unreachable!("out of generated range"),
        }
        wq.check_integrity();
    }

    // Finish the processing of the queue
    let mut iter = 0;
    while let Some(work) = wq.pick(|_peer, work| Some(work)) {
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
        let peer = wq.pick(|peer, _work| Some(peer)).unwrap();
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
