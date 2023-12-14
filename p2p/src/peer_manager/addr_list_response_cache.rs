// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    time::Duration,
};

use common::primitives::time::Time;
use crypto::random::{make_pseudo_rng, Rng};
use p2p_types::socket_address::SocketAddress;

use super::{peer_context::PeerContext, peerdb::salt::Salt};

use crate::types::peer_address::PeerAddress;

/// A cache for addresses to return in an AddrListResponse. Its purpose is to make it harder
/// for an attacker to scrape the addresses in PeerDb, which in turn will make it harder
/// to learn the topology of the p2p network.
///
/// The idea is to remember the addresses in the first AddrListResponse and return the same list
/// to all peers until its expiration time is reached. This way, even if the attacker connects
/// to the node multiple times, it won't learn any additional addresses from this.
/// There is a caveat though - if the node has multiple listening addresses, this straightforward
/// approach will allow the attacker to identify them as belonging to the same node. So instead
/// of one address list we cache multiple lists indexed by an id that is produced by hashing
/// the local address.
pub struct AddrListResponseCache {
    cache: BTreeMap<CacheId, CacheEntry>,
    salt: Salt,
}

impl AddrListResponseCache {
    pub fn new(salt: Salt) -> Self {
        Self {
            cache: BTreeMap::new(),
            salt,
        }
    }

    pub fn get_or_create<F>(&mut self, peer_ctx: &PeerContext, now: Time, create: F) -> &Addresses
    where
        F: FnOnce() -> Addresses,
    {
        use std::collections::btree_map::Entry;

        let id = self.calc_id(peer_ctx);

        let cache_entry = match self.cache.entry(id) {
            Entry::Vacant(entry) => entry.insert(CacheEntry {
                addresses: create(),
                expiration_time: Self::new_expiration_time_from_now(now),
            }),
            Entry::Occupied(mut entry) => {
                if entry.get().expiration_time <= now {
                    *entry.get_mut() = CacheEntry {
                        addresses: create(),
                        expiration_time: Self::new_expiration_time_from_now(now),
                    };
                }
                entry.into_mut()
            }
        };

        &cache_entry.addresses
    }

    fn calc_id(&self, peer_ctx: &PeerContext) -> CacheId {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let bind_addr = peer_ctx.bind_address.socket_addr();

        self.salt.hash(&mut hasher);
        bind_addr.ip().hash(&mut hasher);

        // Note: for outbound connections, the local port shouldn't be included in the hash,
        // because it's randomly generated for each connection.
        // However, we don't expect outbound peers here, because addr list requests from them
        // are never handled.
        debug_assert!(!peer_ctx.peer_role.is_outbound());
        bind_addr.port().hash(&mut hasher);

        get_network(peer_ctx.peer_address).hash(&mut hasher);

        hasher.finish()
    }

    fn new_expiration_time_from_now(now: Time) -> Time {
        let min_secs = EXPIRATION_INTERVAL_MIN.as_secs();
        let max_secs = EXPIRATION_INTERVAL_MAX.as_secs();
        let secs = make_pseudo_rng().gen_range(min_secs..=max_secs);
        (now + Duration::from_secs(secs)).expect("Unexpected time overflow")
    }
}

// Note: in bitcoin they use 24h interval (+-3h), which seems too big.
const EXPIRATION_INTERVAL_MEAN_SECS: u64 = 60 * 60;
pub const EXPIRATION_INTERVAL_MIN: Duration =
    Duration::from_secs(EXPIRATION_INTERVAL_MEAN_SECS * 9 / 10);
pub const EXPIRATION_INTERVAL_MAX: Duration =
    Duration::from_secs(EXPIRATION_INTERVAL_MEAN_SECS * 11 / 10);

type CacheId = u64;
type Addresses = Vec<PeerAddress>;

struct CacheEntry {
    addresses: Addresses,
    expiration_time: Time,
}

#[derive(Hash)]
enum Network {
    IpV4,
    IpV6,
}

fn get_network(addr: SocketAddress) -> Network {
    match addr.socket_addr().ip() {
        std::net::IpAddr::V4(_) => Network::IpV4,
        std::net::IpAddr::V6(addr_v6) => {
            // TODO: in bitcoin, they also handle a bunch of other IPv6 address types that can
            // be translated to IPv4, see CNetAddr::HasLinkedIPv4. Probably, we need to handle
            // them too.
            if addr_v6.to_ipv4().is_some() {
                Network::IpV4
            } else {
                Network::IpV6
            }
        }
    }
}
