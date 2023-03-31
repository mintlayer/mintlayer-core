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

use std::{collections::BTreeMap, hash::Hasher};

use crypto::random::Rng;

use crate::{
    net::{default_backend::transport::TransportAddress, types::Role},
    types::peer_id::PeerId,
};

use super::{address_groups::AddressGroup, peer_context::PeerContext};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct NetGroupKeyed(u64);

/// A copy of `PeerContext` with fields relevant to the eviction logic
#[derive(Debug, PartialEq, Eq)]
pub struct EvictionCandidate {
    peer_id: PeerId,

    /// Deterministically randomized address group ID
    net_group_keyed: NetGroupKeyed,

    /// Minimum ping time in microseconds (or i64::MAX if not yet known yet)
    ping_min: i64,

    /// Inbound or Outbound
    role: Role,
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
    pub fn new<A: TransportAddress>(peer: &PeerContext<A>, random_state: &RandomState) -> Self {
        EvictionCandidate {
            peer_id: peer.info.peer_id,
            net_group_keyed: NetGroupKeyed(random_state.get_hash(
                &AddressGroup::from_peer_address(&peer.address.as_peer_address()),
            )),
            ping_min: peer.ping_min.map_or(i64::MAX, |val| val.as_micros() as i64),
            role: peer.role,
        }
    }
}

// Only consider inbound connections for eviction (attackers have no control over outbound connections)
fn filter_inbound(mut candidates: Vec<EvictionCandidate>) -> Vec<EvictionCandidate> {
    candidates.retain(|peer| peer.role == Role::Inbound);
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
pub fn select_for_eviction(candidates: Vec<EvictionCandidate>) -> Option<PeerId> {
    // TODO: Preserve connections from whitelisted IPs

    let candidates = filter_inbound(candidates);
    let candidates = filter_address_group(candidates, 4);
    let candidates = filter_fast_ping(candidates, 8);

    // TODO: Preserve 4 nodes that most recently sent us novel transactions accepted into our mempool.
    // TODO: Preserve up to 8 peers that have sent us novel blocks.

    find_group_most_connections(candidates)
}

#[cfg(test)]
mod tests;
