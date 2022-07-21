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

use crate::{
    config,
    error::P2pError,
    net::{types, NetworkingService},
};
use logging::log;
use std::{
    collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
    sync::Arc,
};

#[derive(Debug)]
pub struct PeerContext<T: NetworkingService> {
    /// Peer information
    pub info: types::PeerInfo<T>,

    /// Peer's active address, if known
    pub address: Option<T::Address>,

    /// Set of available addresses
    pub addresses: HashSet<T::Address>,

    /// Peer score
    pub score: u32,
}

#[derive(Debug)]
pub enum BannedPeer<T: NetworkingService> {
    Known(PeerContext<T>),
    Discovered(VecDeque<T::Address>),
    Unknown,
}

#[derive(Debug)]
pub enum Peer<T: NetworkingService> {
    /// Active peer
    Active(PeerContext<T>),

    /// Idle peer (`types::PeerInfo<t>` received)
    Idle(PeerContext<T>),

    /// Active/known peer that has been banned
    Banned(BannedPeer<T>),

    /// Discovered peer (addresses have been received)
    Discovered(VecDeque<T::Address>),
}

// TODO: store available peers into a binary heap
pub struct PeerDb<T: NetworkingService> {
    /// P2P configuration
    p2p_config: Arc<config::P2pConfig>,

    /// Set of peers known to `PeerDb`
    peers: HashMap<T::PeerId, Peer<T>>,

    /// Set of available (idle) peers
    available: HashSet<T::PeerId>,

    /// Pending connections
    pending: HashMap<T::Address, T::PeerId>,

    /// Banned peers
    banned: HashSet<T::PeerId>,
}

impl<T: NetworkingService> PeerDb<T> {
    pub fn new(p2p_config: Arc<config::P2pConfig>) -> Self {
        Self {
            peers: Default::default(),
            available: Default::default(),
            pending: Default::default(),
            banned: Default::default(),
            p2p_config,
        }
    }

    /// Get the number of idle (available) peers
    pub fn idle_peer_count(&self) -> usize {
        self.available.len()
    }

    /// Get the number of active peers
    pub fn active_peer_count(&self) -> usize {
        self.peers
            .len()
            .saturating_sub(self.pending.len())
            .saturating_sub(self.available.len())
            .saturating_sub(self.banned.len())
    }

    pub fn active_peers(&self) -> Vec<(&T::PeerId, &PeerContext<T>)> {
        self.peers
            .iter()
            .filter_map(|(id, info)| match info {
                Peer::Active(inner) => Some((id, inner)),
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Get mutable reference to the peer store
    pub fn peers(&mut self) -> &mut HashMap<T::PeerId, Peer<T>> {
        &mut self.peers
    }

    /// Get mutable reference to the available peer store
    pub fn available(&mut self) -> &mut HashSet<T::PeerId> {
        &mut self.available
    }

    /// Get mutable reference to the pending peer store
    pub fn pending(&mut self) -> &mut HashMap<T::Address, T::PeerId> {
        &mut self.pending
    }

    /// Get mutable reference to the banned peer store
    pub fn banned(&mut self) -> &mut HashSet<T::PeerId> {
        &mut self.banned
    }

    /// Check is the peer ID banned
    pub fn is_id_banned(&self, peer_id: &T::PeerId) -> bool {
        self.banned.contains(peer_id)
    }

    /// Check is the address banned
    pub fn is_address_banned(&self, _address: &T::Address) -> bool {
        false // TODO: implement
    }

    /// Check if the peers is part of our active swarm
    pub fn is_active_peer(&self, peer_id: &T::PeerId) -> bool {
        std::matches!(self.peers.get(peer_id), Some(Peer::Active(_)))
    }

    /// Get socket address of the next best peer (TODO: in terms of peer score)
    // TODO: rewrite all of this
    pub fn best_peer_addr(&mut self) -> crate::Result<Option<T::Address>> {
        // TODO: improve peer selection
        let peer_id = match self.available.iter().next() {
            Some(peer_id) => *peer_id,
            None => return Ok(None),
        };

        match self.peers.get_mut(&peer_id) {
            Some(Peer::Idle(_info) | Peer::Active(_info)) => {
                // TODO: implement
                Ok(None)
            }
            Some(Peer::Banned(_info)) => {
                // TODO: implement
                Ok(None)
            }
            Some(Peer::Discovered(addr_info)) => addr_info.pop_front().map_or(Ok(None), |addr| {
                self.available.remove(&peer_id);
                self.pending.insert(addr.clone(), peer_id);
                Ok(Some(addr))
            }),
            None => Err(P2pError::DatabaseFailure),
        }
    }

    /// Discover new peer addresses
    pub fn peer_discovered(&mut self, info: &types::AddrInfo<T>) {
        match self.peers.entry(info.peer_id) {
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Peer::Discovered(addr_info) => {
                    // TODO: duplicates
                    addr_info.extend(info.ip6.clone());
                    addr_info.extend(info.ip4.clone());
                }
                Peer::Idle(_info) | Peer::Active(_info) => {
                    // TODO: update existing information of a known peer
                }
                Peer::Banned(_info) => {
                    // TODO: update existing information of a known peer
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(Peer::Discovered(VecDeque::from_iter(
                    info.ip6
                        .iter()
                        .cloned()
                        .chain(info.ip4.iter().cloned())
                        .collect::<Vec<_>>(),
                )));
                self.available.insert(info.peer_id);
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
    ///
    /// If the peer is known (either fully known or only discovered), its information
    /// is updated with the new received information. If the peer is unknown to `PeerDb`
    /// (new inbound connection from an unknown peer), a new entry is created for the peer.
    ///
    /// Finally the peer is marked as available so future connection attempts may try to
    /// dial this peer from the last known address.
    pub fn register_peer_info(&mut self, address: T::Address, info: types::PeerInfo<T>) {
        let peer_id = info.peer_id;

        let entry = match self.peers.remove(&peer_id) {
            Some(Peer::Discovered(addr_info)) => {
                self.available.insert(peer_id);
                Peer::Idle(PeerContext {
                    info,
                    score: 0,
                    address: Some(address.clone()),
                    addresses: HashSet::from_iter(addr_info),
                })
            }
            Some(Peer::Idle(peer_info)) => {
                self.available.insert(peer_id);
                Peer::Idle(PeerContext {
                    info,
                    score: peer_info.score,
                    address: Some(address.clone()),
                    addresses: peer_info.addresses,
                })
            }
            None => {
                self.available.insert(peer_id);
                Peer::Idle(PeerContext {
                    info,
                    score: 0,
                    address: Some(address.clone()),
                    addresses: HashSet::new(),
                })
            }
            Some(entry @ Peer::Active(_)) => entry,
            Some(entry @ Peer::Banned(_)) => entry,
        };

        self.peers.insert(peer_id, entry);
        self.pending.remove(&address);
    }

    /// Mark peer as connected
    ///
    /// After `PeerManager` has established either an inbound or an outbound connection,
    /// it informs the `PeerDb` about it which updates the peer information it has and
    /// marks the peer as unavailable for future dial attempts.
    pub fn peer_connected(&mut self, address: T::Address, info: types::PeerInfo<T>) {
        let peer_id = info.peer_id;

        let entry = match self.peers.remove(&peer_id) {
            Some(Peer::Discovered(addr_info)) => Peer::Active(PeerContext {
                info,
                score: 0,
                address: Some(address.clone()),
                addresses: HashSet::from_iter(addr_info),
            }),
            Some(Peer::Idle(peer_info)) => Peer::Active(PeerContext {
                info,
                score: peer_info.score,
                address: Some(address.clone()),
                addresses: peer_info.addresses,
            }),
            None => Peer::Active(PeerContext {
                info,
                score: 0,
                address: Some(address.clone()),
                addresses: HashSet::new(),
            }),
            Some(entry @ Peer::Active(_)) => entry,
            Some(entry @ Peer::Banned(_)) => entry,
        };

        self.peers.insert(peer_id, entry);
        self.available.remove(&peer_id);
        self.pending.remove(&address);
    }

    /// Handle peer disconnection event
    ///
    /// Close the connection to an active peer and change the peer state
    /// the `Peer::Idle` so it can be used again for connection later.
    pub fn peer_disconnected(&mut self, peer_id: &T::PeerId) {
        if let Some(entry) = self.peers.remove(peer_id) {
            let entry = match entry {
                Peer::Active(inner) => {
                    self.available.insert(*peer_id);
                    Peer::Idle(inner)
                }
                Peer::Discovered(inner) => Peer::Discovered(inner),
                Peer::Idle(inner) => Peer::Idle(inner),
                Peer::Banned(inner) => Peer::Banned(inner),
            };

            self.peers.insert(*peer_id, entry);
        }
    }

    /// Change peer state to `Peer::Banned` and and it to the list of banned peers
    pub fn ban_peer(&mut self, peer_id: &T::PeerId) {
        if let Some(entry) = self.peers.remove(peer_id) {
            let entry = match entry {
                Peer::Active(inner) | Peer::Idle(inner) => {
                    log::info!(
                        "ban known/idle peer {}, peer address {:?}",
                        peer_id,
                        inner.address
                    );
                    Peer::Banned(BannedPeer::Known(inner))
                }
                Peer::Discovered(inner) => {
                    log::info!(
                        "ban discovered peer {}, peer addresses {:?}",
                        peer_id,
                        inner
                    );
                    Peer::Banned(BannedPeer::Discovered(inner))
                }
                Peer::Banned(inner) => Peer::Banned(inner),
            };

            self.peers.insert(*peer_id, entry);
        }

        self.available.remove(peer_id);
        self.banned.insert(*peer_id);
    }

    /// Adjust peer score
    ///
    /// If the peer is known, update its existing peer score and if it is not
    /// known (either at all or fully), just use `score` to make the decision whether
    /// to ban the peer or not.
    ///
    /// If peer is banned, it is still kept in the peer storage but it is removed
    /// from the `available` storage so it won't be picked up again and its peer ID
    /// is recorded into the `banned` storage which keeps track of all banned peers.
    ///
    /// TODO: implement unbanning
    pub fn adjust_peer_score(&mut self, peer_id: &T::PeerId, score: u32) -> bool {
        let final_score = match self.peers.entry(*peer_id) {
            Entry::Vacant(entry) => {
                entry.insert(Peer::Banned(BannedPeer::Unknown));
                score
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Peer::Discovered(_) => score,
                Peer::Banned(inner) => match inner {
                    BannedPeer::Known(info) => {
                        info.score = info.score.saturating_add(score);
                        info.score
                    }
                    BannedPeer::Discovered(_) | BannedPeer::Unknown => score,
                },
                Peer::Idle(info) | Peer::Active(info) => {
                    info.score = info.score.saturating_add(score);
                    info.score
                }
            },
        };

        if final_score >= self.p2p_config.ban_threshold {
            self.ban_peer(peer_id);
            return true;
        }

        false
    }
}
