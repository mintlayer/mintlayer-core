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

use common::primitives::time::Time;
use crypto::random::Rng;
use utils::make_config_setting;

use crate::{net::types::PeerRole, types::peer_id::PeerId};

use super::{address_groups::AddressGroup, peer_context::PeerContext, PeerManagerConfig};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct NetGroupKeyed(u64);

make_config_setting!(PreservedInboundCountAddressGroup, usize, 4);
make_config_setting!(PreservedInboundCountPing, usize, 8);
make_config_setting!(PreservedInboundCountNewBlocks, usize, 8);
make_config_setting!(PreservedInboundCountNewTransactions, usize, 4);

make_config_setting!(
    OutboundBlockRelayConnectionMinAge,
    Duration,
    Duration::from_secs(120)
);
make_config_setting!(
    OutboundFullRelayConnectionMinAge,
    Duration,
    Duration::from_secs(120)
);

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

    last_tip_block_time: Option<Time>,

    last_tx_time: Option<Time>,
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
    pub fn new(peer: &PeerContext, random_state: &RandomState, now: Time) -> Self {
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
pub fn select_for_eviction_inbound(
    candidates: Vec<EvictionCandidate>,
    config: &PeerManagerConfig,
) -> Option<PeerId> {
    // TODO: Preserve connections from whitelisted IPs

    debug_assert!(candidates.iter().all(|c| c.peer_role == PeerRole::Inbound));

    let candidates =
        filter_address_group(candidates, *config.preserved_inbound_count_address_group);
    let candidates = filter_fast_ping(candidates, *config.preserved_inbound_count_ping);
    let candidates =
        filter_by_last_tip_block_time(candidates, *config.preserved_inbound_count_new_blocks);
    let candidates = filter_by_last_transaction_time(
        candidates,
        *config.preserved_inbound_count_new_transactions,
    );

    find_group_most_connections(candidates)
}

#[must_use]
pub fn select_for_eviction_block_relay(
    candidates: Vec<EvictionCandidate>,
    config: &PeerManagerConfig,
) -> Option<PeerId> {
    select_for_eviction_outbound(
        candidates,
        PeerRole::OutboundBlockRelay,
        *config.outbound_block_relay_connection_min_age,
        *config.outbound_block_relay_count,
    )
}

#[must_use]
pub fn select_for_eviction_full_relay(
    candidates: Vec<EvictionCandidate>,
    config: &PeerManagerConfig,
) -> Option<PeerId> {
    // TODO: in bitcoin they protect full relay peers from eviction if there are no other
    // connection to their network (counting outbound-full-relay and manual peers). We should
    // probably do the same.
    // See the TODO section of https://github.com/mintlayer/mintlayer-core/issues/832
    select_for_eviction_outbound(
        candidates,
        PeerRole::OutboundFullRelay,
        *config.outbound_full_relay_connection_min_age,
        *config.outbound_full_relay_count,
    )
}

fn select_for_eviction_outbound(
    candidates: Vec<EvictionCandidate>,
    peer_role: PeerRole,
    min_age: Duration,
    max_count: usize,
) -> Option<PeerId> {
    debug_assert!(candidates.iter().all(|c| c.peer_role == peer_role));

    // Give peers some time to have a chance to send blocks.
    // TODO: in bitcoin, in addition to checking MINIMUM_CONNECT_TIME, they also check whether
    // there are blocks in-flight with this peer; we should consider doing it too.
    // See the TODO section of https://github.com/mintlayer/mintlayer-core/issues/832
    let mut candidates = filter_old_peers(candidates, min_age);
    if candidates.len() <= max_count {
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
