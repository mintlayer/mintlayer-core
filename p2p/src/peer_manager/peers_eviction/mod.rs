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

use std::{collections::BTreeMap, hash::Hasher, time::Duration};

use crypto::random::Rng;

use crate::{net::types::PeerRole, types::peer_id::PeerId};

use super::{address_groups::AddressGroup, peer_context::PeerContext, OUTBOUND_BLOCK_RELAY_COUNT};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct NetGroupKeyed(u64);

const PRESERVED_COUNT_ADDRESS_GROUP: usize = 4;
const PRESERVED_COUNT_PING: usize = 8;
const PRESERVED_COUNT_NEW_BLOCKS: usize = 8;
const PRESERVED_COUNT_NEW_TRANSACTIONS: usize = 4;

#[cfg(test)]
const PRESERVED_COUNT_TOTAL: usize = PRESERVED_COUNT_ADDRESS_GROUP
    + PRESERVED_COUNT_PING
    + PRESERVED_COUNT_NEW_BLOCKS
    + PRESERVED_COUNT_NEW_TRANSACTIONS;

/// A copy of `PeerContext` with fields relevant to the eviction logic
///
/// See `select_for_eviction` for more details.
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct EvictionCandidate {
    peer_id: PeerId,

    age: Duration,

    /// Deterministically randomized address group ID
    net_group_keyed: NetGroupKeyed,

    /// Minimum ping time in microseconds (or i64::MAX if not known yet)
    ping_min: i64,

    /// Inbound or Outbound
    peer_role: PeerRole,

    last_tip_block_time: Option<Duration>,

    last_tx_time: Option<Duration>,
}

pub struct RandomState(u64, u64);

impl RandomState {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        Self(rng.gen(), rng.gen())
    }

    fn get_hash<A: std::hash::Hash>(&self, value: &A) -> u64 {
        let mut hasher = siphasher::sip::SipHasher::new_with_keys(self.0, self.1);
        value.hash(&mut hasher);
        hasher.finish()
    }
}

impl EvictionCandidate {
    pub fn new(peer: &PeerContext, random_state: &RandomState, now: Duration) -> Self {
        EvictionCandidate {
            age: now.saturating_sub(peer.created_at),
            peer_id: peer.info.peer_id,
            net_group_keyed: NetGroupKeyed(random_state.get_hash(
                &AddressGroup::from_peer_address(&peer.address.as_peer_address()),
            )),
            ping_min: peer.ping_min.map_or(i64::MAX, |val| val.as_micros() as i64),
            peer_role: peer.peer_role,
            last_tip_block_time: peer.last_tip_block_time,
            last_tx_time: peer.last_tx_time,
        }
    }
}

// Only consider inbound connections for eviction (attackers have no control over outbound connections)
fn filter_peer_role(
    mut candidates: Vec<EvictionCandidate>,
    peer_role: PeerRole,
) -> Vec<EvictionCandidate> {
    candidates.retain(|peer| peer.peer_role == peer_role);
    candidates
}

fn filter_old_peers(
    mut candidates: Vec<EvictionCandidate>,
    age: Duration,
) -> Vec<EvictionCandidate> {
    candidates.retain(|peer| peer.age >= age);
    candidates
}

// Deterministically select peers to preserve by netgroup.
// An attacker cannot predict which netgroups will be preserved.
fn filter_address_group(
    mut candidates: Vec<EvictionCandidate>,
    count: usize,
) -> Vec<EvictionCandidate> {
    candidates.sort_unstable_by_key(|peer| peer.net_group_keyed);
    candidates.truncate(candidates.len().saturating_sub(count));
    candidates
}

// Preserve the nodes with the lowest minimum ping time.
// An attacker cannot manipulate this metric without physically moving nodes closer to the target.
fn filter_fast_ping(
    mut candidates: Vec<EvictionCandidate>,
    count: usize,
) -> Vec<EvictionCandidate> {
    candidates.sort_unstable_by_key(|peer| -peer.ping_min);
    candidates.truncate(candidates.len().saturating_sub(count));
    candidates
}

// Preserve the last nodes that sent us new blocks
fn filter_by_last_tip_block_time(
    mut candidates: Vec<EvictionCandidate>,
    count: usize,
) -> Vec<EvictionCandidate> {
    candidates.sort_unstable_by_key(|peer| peer.last_tip_block_time);
    candidates.truncate(candidates.len().saturating_sub(count));
    candidates
}

// Preserve the last nodes that sent us new transactions
fn filter_by_last_transaction_time(
    mut candidates: Vec<EvictionCandidate>,
    count: usize,
) -> Vec<EvictionCandidate> {
    candidates.sort_unstable_by_key(|peer| peer.last_tx_time);
    candidates.truncate(candidates.len().saturating_sub(count));
    candidates
}

fn find_group_most_connections(candidates: Vec<EvictionCandidate>) -> Option<PeerId> {
    if candidates.is_empty() {
        return None;
    }

    // Identify the network group with the most connections
    let counts = candidates.iter().fold(BTreeMap::<NetGroupKeyed, usize>::new(), |mut acc, c| {
        *acc.entry(c.net_group_keyed).or_insert(0) += 1;
        acc
    });
    let selected_group: NetGroupKeyed =
        *counts.iter().max_by_key(|(_group_id, count)| *count).expect("must exist").0;

    // Evict the youngest peer (with max `peer_id`) in the selected group
    let peer_id = candidates
        .iter()
        .filter(|c| c.net_group_keyed == selected_group)
        .max_by_key(|peer| peer.peer_id)
        .expect("must exist")
        .peer_id;

    Some(peer_id)
}

/// Based on `SelectNodeToEvict` from Bitcoin Core:
///
/// Select an inbound peer to evict after filtering out (preserving) peers having
/// distinct, difficult-to-forge characteristics. The preservation logic picks out
/// fixed numbers of desirable peers per various criteria.
/// If any eviction candidates remain, the selection logic chooses a peer to evict.
#[must_use]
pub fn select_for_eviction_inbound(candidates: Vec<EvictionCandidate>) -> Option<PeerId> {
    // TODO: Preserve connections from whitelisted IPs

    let candidates = filter_peer_role(candidates, PeerRole::Inbound);
    let candidates = filter_address_group(candidates, PRESERVED_COUNT_ADDRESS_GROUP);
    let candidates = filter_fast_ping(candidates, PRESERVED_COUNT_PING);
    let candidates = filter_by_last_tip_block_time(candidates, PRESERVED_COUNT_NEW_BLOCKS);
    let candidates = filter_by_last_transaction_time(candidates, PRESERVED_COUNT_NEW_TRANSACTIONS);

    find_group_most_connections(candidates)
}

#[must_use]
pub fn select_for_eviction_block_relay(candidates: Vec<EvictionCandidate>) -> Option<PeerId> {
    let candidates = filter_peer_role(candidates, PeerRole::OutboundBlockRelay);

    // Give peers some time to have a chance to send blocks
    let mut candidates = filter_old_peers(candidates, Duration::from_secs(120));
    if candidates.len() < OUTBOUND_BLOCK_RELAY_COUNT {
        return None;
    }

    // Starting from the youngest, disconnect the first peer that never sent a new blockchain tip
    candidates.sort_by_key(|peer| peer.age);
    for peer in candidates.iter() {
        if peer.last_tip_block_time.is_none() {
            return Some(peer.peer_id);
        }
    }

    // Disconnect the peer who sent a new blockchain tip a long time ago
    candidates.sort_by_key(|peer| peer.last_tip_block_time);
    candidates.first().map(|peer| peer.peer_id)
}

#[cfg(test)]
mod tests;
