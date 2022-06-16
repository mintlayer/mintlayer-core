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
//! TODO

use crate::net::{types, NetworkingService};
use logging::log;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// TODO: store active address
// TODO: store other discovered addresses
#[derive(Debug)]
pub struct PeerContext<T: NetworkingService> {
    pub _info: types::PeerInfo<T>,
}

/// Peer address information
enum PeerAddrInfo<T: NetworkingService> {
    Raw {
        /// Hashset of IPv4 addresses
        ip4: HashSet<Arc<T::Address>>,

        /// Hashset of IPv6 addresses
        ip6: HashSet<Arc<T::Address>>,
    },
}

pub struct PeerDb<T: NetworkingService> {
    /// Hashmap for peer information
    peers: HashMap<T::PeerId, PeerContext<T>>,

    /// Hashmap of discovered peers we don't have an active connection with
    discovered: HashMap<T::PeerId, PeerAddrInfo<T>>,
}

impl<T: NetworkingService> PeerDb<T> {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            discovered: HashMap::new(),
        }
    }

    /// Verify is the peer ID banned
    pub fn is_id_banned(&self, _peer_id: &T::PeerId) -> bool {
        false // TODO: implement
    }

    /// Verify is the address banned
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
    pub fn expire_peers(&mut self, _peers: &[types::AddrInfo<T>]) {}
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
             ip4: Vec<Arc<<Libp2pService as NetworkingService>::Address>>,
             ip6: Vec<Arc<<Libp2pService as NetworkingService>::Address>>| {
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
                ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
                ip6: vec![Arc::new("/ip6/::1/tcp/9091".parse().unwrap())],
            },
            net::types::AddrInfo {
                id: id_2,
                ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9092".parse().unwrap())],
                ip6: vec![Arc::new("/ip6/::1/tcp/9093".parse().unwrap())],
            },
        ]);

        assert_eq!(peerdb.peers.len(), 0);
        assert_eq!(peerdb.discovered.len(), 2);

        check_peer(
            &peerdb.discovered,
            id_1,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9091".parse().unwrap())],
        );

        check_peer(
            &peerdb.discovered,
            id_2,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9092".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9093".parse().unwrap())],
        );

        // then discover one new peer and two additional ipv6 addresses for peer 1
        peerdb.discover_peers(&[
            net::types::AddrInfo {
                id: id_1,
                ip4: vec![],
                ip6: vec![
                    Arc::new("/ip6/::1/tcp/9094".parse().unwrap()),
                    Arc::new("/ip6/::1/tcp/9095".parse().unwrap()),
                ],
            },
            net::types::AddrInfo {
                id: id_3,
                ip4: vec![Arc::new("/ip4/127.0.0.1/tcp/9096".parse().unwrap())],
                ip6: vec![Arc::new("/ip6/::1/tcp/9097".parse().unwrap())],
            },
        ]);

        check_peer(
            &peerdb.discovered,
            id_1,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9090".parse().unwrap())],
            vec![
                Arc::new("/ip6/::1/tcp/9091".parse().unwrap()),
                Arc::new("/ip6/::1/tcp/9094".parse().unwrap()),
                Arc::new("/ip6/::1/tcp/9095".parse().unwrap()),
            ],
        );

        check_peer(
            &peerdb.discovered,
            id_3,
            vec![Arc::new("/ip4/127.0.0.1/tcp/9096".parse().unwrap())],
            vec![Arc::new("/ip6/::1/tcp/9097".parse().unwrap())],
        );
    }
}
