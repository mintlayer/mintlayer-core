// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen

//! Peer database
//!
//! The peer database recognizes three peer types:
//! - active peers
//! - idle peers
//! - reserved peers (not implemented)
//!
//! Active peers are those peers that the [`crate::swarm::PeerManager`] has an active connection with
//! whereas idle peers are the peers that are known to `PeerDb` but are not part of our swarm.
//! Idle peers are discovered through various peer discovery mechanisms and they are used by
//! [`crate::swarm::PeerManager::heartbeat()`] to establish new outbound connections if the actual
//! number of active connectios is less than the desired number of connections.
//!
//! TODO: reserved peers

use crate::net::{types, NetworkingService};
use logging::log;
use std::collections::{HashMap, HashSet};

// TODO: store active address
// TODO: store other discovered addresses
#[derive(Debug)]
pub struct PeerContext<T: NetworkingService> {
    /// Peer information
    pub _info: types::PeerInfo<T>,

    /// Peer score
    pub score: u32,
}

/// Peer address information
enum PeerAddrInfo<T: NetworkingService> {
    Raw {
        /// Hashset of IPv4 addresses
        ip4: HashSet<T::Address>,

        /// Hashset of IPv6 addresses
        ip6: HashSet<T::Address>,
    },
}

// TODO: improve how peers are stored, order by reputation?
pub struct PeerDb<T: NetworkingService> {
    /// Hashmap for peer information
    peers: HashMap<T::PeerId, PeerContext<T>>,

    /// Hashmap of discovered peers we don't have an active connection with
    discovered: HashMap<T::PeerId, PeerAddrInfo<T>>,

    /// Pending connections
    pending: HashMap<T::Address, PeerAddrInfo<T>>,

    /// Banned peers
    banned: HashSet<T::PeerId>,
}

impl<T: NetworkingService> PeerDb<T> {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            discovered: HashMap::new(),
            pending: HashMap::new(),
            banned: HashSet::new(),
        }
    }

    /// Get the number of idle (available) peers
    pub fn idle_peer_count(&self) -> usize {
        self.discovered.len()
    }

    /// Get socket address of the next best peer (TODO: in terms of peer score)
    pub fn best_peer_addr(&mut self) -> Option<T::Address> {
        // TODO: improve peer selection
        let key = match self.discovered.keys().next() {
            Some(key) => *key,
            None => return None,
        };

        // TODO: find a better way to store the addresses
        let peer_info = self.discovered.remove(&key).expect("peer to exist");
        let addr = match peer_info {
            PeerAddrInfo::Raw { ref ip4, ref ip6 } => {
                assert!(!(ip4.is_empty() && ip6.is_empty()));

                if ip6.is_empty() {
                    ip4.iter().next().expect("ip4 empty").clone()
                } else {
                    ip6.iter().next().expect("ip6 empty").clone()
                }
            }
        };

        self.pending.insert(addr.clone(), peer_info);
        Some(addr)
    }

    /// Check is the peer ID banned
    pub fn is_id_banned(&self, peer_id: &T::PeerId) -> bool {
        self.banned.contains(peer_id)
    }

    /// Check is the address banned
    pub fn is_address_banned(&self, _address: &T::Address) -> bool {
        false // TODO: implement
    }

    /// Discover new peer addresses
    pub fn discover_peers(&mut self, peers: &[types::AddrInfo<T>]) {
        log::info!("discovered {} new peers", peers.len());

        for info in peers.iter() {
            // TODO: update peer stats
            if self.peers.contains_key(&info.id) {
                continue;
            }

            match self.discovered.entry(info.id).or_insert_with(|| PeerAddrInfo::Raw {
                ip4: HashSet::new(),
                ip6: HashSet::new(),
            }) {
                PeerAddrInfo::Raw { ip4, ip6 } => {
                    log::trace!("discovered ipv4 {:#?}, ipv6 {:#?}", ip4, ip6);

                    ip4.extend(info.ip4.clone());
                    ip6.extend(info.ip6.clone());
                }
            }
        }
    }

    /// Expire discovered peer addresses
    pub fn expire_peers(&mut self, _peers: &[types::AddrInfo<T>]) {
        // TODO: implement
    }

    /// Report outbound connection failure
    ///
    /// When [`crate::swarm::PeerManager::heartbeat()`] has initiated an outbound connection
    /// and the connection is refused, it's reported back to the `PeerDb` so it knows to update
    /// the peer information accordingly by forgetting the address and adjusting the peer score
    /// appropriately.
    pub fn report_outbound_failure(&mut self, _address: T::Address) {
        // TODO: implement
    }

    /// Register peer information to `PeerDb`
    pub fn register_peer_info(&mut self, _info: types::PeerInfo<T>) {
        // TODO: implement
    }

    /// Ban peer
    pub fn ban_peer(&mut self, peer_id: &T::PeerId) {
        self.banned.insert(*peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{self, libp2p::Libp2pService};
    use libp2p::PeerId;

    #[test]
    fn test_peer_discovered_libp2p() {
        let mut peerdb = PeerDb::new();

        let id_1: libp2p::PeerId = PeerId::random();
        let id_2: libp2p::PeerId = PeerId::random();
        let id_3: libp2p::PeerId = PeerId::random();

        // check that peer with `id` has the correct ipv4 and ipv6 addresses
        let check_peer =
            |discovered: &HashMap<
                <Libp2pService as NetworkingService>::PeerId,
                PeerAddrInfo<Libp2pService>,
            >,
             id: libp2p::PeerId,
             ip4: Vec<<Libp2pService as NetworkingService>::Address>,
             ip6: Vec<<Libp2pService as NetworkingService>::Address>| {
                let (p_ip4, p_ip6) = match discovered.get(&id).unwrap() {
                    PeerAddrInfo::Raw { ip4, ip6 } => (ip4, ip6),
                };

                assert_eq!(ip4.len(), p_ip4.len());
                assert_eq!(ip6.len(), p_ip6.len());

                for ip in ip4.iter() {
                    assert!(p_ip4.contains(ip));
                }

                for ip in ip6.iter() {
                    assert!(p_ip6.contains(ip));
                }
            };

        // first add two new peers, both with ipv4 and ipv6 address
        peerdb.discover_peers(&[
            net::types::AddrInfo {
                id: id_1,
                ip4: vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
                ip6: vec!["/ip6/::1/tcp/9091".parse().unwrap()],
            },
            net::types::AddrInfo {
                id: id_2,
                ip4: vec!["/ip4/127.0.0.1/tcp/9092".parse().unwrap()],
                ip6: vec!["/ip6/::1/tcp/9093".parse().unwrap()],
            },
        ]);

        assert_eq!(peerdb.peers.len(), 0);
        assert_eq!(peerdb.discovered.len(), 2);

        check_peer(
            &peerdb.discovered,
            id_1,
            vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
            vec!["/ip6/::1/tcp/9091".parse().unwrap()],
        );

        check_peer(
            &peerdb.discovered,
            id_2,
            vec!["/ip4/127.0.0.1/tcp/9092".parse().unwrap()],
            vec!["/ip6/::1/tcp/9093".parse().unwrap()],
        );

        // then discover one new peer and two additional ipv6 addresses for peer 1
        peerdb.discover_peers(&[
            net::types::AddrInfo {
                id: id_1,
                ip4: vec![],
                ip6: vec![
                    "/ip6/::1/tcp/9094".parse().unwrap(),
                    "/ip6/::1/tcp/9095".parse().unwrap(),
                ],
            },
            net::types::AddrInfo {
                id: id_3,
                ip4: vec!["/ip4/127.0.0.1/tcp/9096".parse().unwrap()],
                ip6: vec!["/ip6/::1/tcp/9097".parse().unwrap()],
            },
        ]);

        check_peer(
            &peerdb.discovered,
            id_1,
            vec!["/ip4/127.0.0.1/tcp/9090".parse().unwrap()],
            vec![
                "/ip6/::1/tcp/9091".parse().unwrap(),
                "/ip6/::1/tcp/9094".parse().unwrap(),
                "/ip6/::1/tcp/9095".parse().unwrap(),
            ],
        );

        check_peer(
            &peerdb.discovered,
            id_3,
            vec!["/ip4/127.0.0.1/tcp/9096".parse().unwrap()],
            vec!["/ip6/::1/tcp/9097".parse().unwrap()],
        );
    }
}
