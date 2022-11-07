// Copyright (c) 2022 RBB S.r.l
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
//! number of active connection is less than the desired number of connections.
//!
//! TODO: reserved peers

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use logging::log;

use crate::{
    config,
    error::P2pError,
    net::{types, AsBannableAddress, NetworkingService},
};

const BAN_DURATION: Duration = Duration::from_secs(60 * 60 * 24);

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

impl<T: NetworkingService> BannedPeer<T> {
    pub fn address(&self) -> Option<&T::Address> {
        match self {
            BannedPeer::Known(c) => c.address.as_ref(),
            BannedPeer::Discovered(_) | BannedPeer::Unknown => None,
        }
    }
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

impl<T: NetworkingService> Peer<T> {
    pub fn address(&self) -> Option<&T::Address> {
        match self {
            Peer::Active(c) => c.address.as_ref(),
            Peer::Idle(c) => c.address.as_ref(),
            Peer::Banned(b) => b.address(),
            Peer::Discovered(_) => None,
        }
    }
}

// TODO: store available peers into a binary heap
// TODO: find a way to persist this data in some database for when the node is restarted
// (data of banned, discovered, and at-least-once used should be stored)
pub struct PeerDb<T: NetworkingService> {
    /// P2P configuration
    p2p_config: Arc<config::P2pConfig>,

    /// Set of peers known to `PeerDb`
    peers: HashMap<T::PeerId, Peer<T>>,

    /// Set of available (idle) peers
    available: HashSet<T::PeerId>,

    /// Pending connections
    pending: HashMap<T::Address, T::PeerId>,

    /// Banned addresses along with the duration of the ban.
    ///
    /// The duration represents the `UNIX_EPOCH + duration` time point, so the ban should end
    /// when `current_time > ban_duration`.
    banned: BTreeMap<T::BannableAddress, Duration>,
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
            .checked_sub(self.pending.len())
            .and_then(|acc| acc.checked_sub(self.available.len()))
            .and_then(|acc| acc.checked_sub(self.banned.len()))
            .expect("`PeerDb` state to be consistent")
    }

    pub fn active_peers(&self) -> Vec<(&T::PeerId, &PeerContext<T>)> {
        self.peers
            .iter()
            .filter_map(|(id, info)| match info {
                Peer::Active(inner) => Some((id, inner)),
                Peer::Idle(_) | Peer::Banned(_) | Peer::Discovered(_) => None,
            })
            .collect::<Vec<_>>()
    }

    /// Get reference to the peer store
    pub fn peers(&mut self) -> &HashMap<T::PeerId, Peer<T>> {
        &self.peers
    }

    /// Get reference to the available peer store
    pub fn available(&mut self) -> &HashSet<T::PeerId> {
        &self.available
    }

    /// Get reference to the pending peer store
    pub fn pending(&mut self) -> &HashMap<T::Address, T::PeerId> {
        &self.pending
    }

    /// Checks if the given address is banned.
    pub fn is_address_banned(&mut self, address: &T::BannableAddress) -> bool {
        if let Some(banned_till) = self.banned.get(address) {
            // Check if the ban has expired.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // This can fail only if `SystemTime::now()` returns the time before `UNIX_EPOCH`.
                .expect("Invalid system time");
            if now > *banned_till {
                self.banned.remove(address);
            } else {
                return true;
            }
        }

        false
    }

    /// Check if the peers is part of our active swarm
    pub fn is_active_peer(&self, peer_id: &T::PeerId) -> bool {
        std::matches!(self.peers.get(peer_id), Some(Peer::Active(_)))
    }

    /// Get socket address of the next best peer (TODO: in terms of peer score)
    // TODO: rewrite all of this
    pub fn take_best_peer_addr(&mut self) -> crate::Result<Option<T::Address>> {
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
                    info.ip6.iter().cloned().chain(info.ip4.iter().cloned()).collect::<Vec<_>>(),
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

    /// Changes the peer state to `Peer::Banned` and bans it for 24 hours.
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

        if let Some(address) =
            self.peers.get(peer_id).and_then(|p| p.address()).map(|a| a.as_bannable())
        {
            let ban_till = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                // This can fail only if `SystemTime::now()` returns the time before `UNIX_EPOCH`.
                .expect("Invalid system time")
                + BAN_DURATION;
            self.banned.insert(address, ban_till);
        } else {
            log::error!("Failed to get address for peer {}", peer_id);
        }
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

        if final_score >= *self.p2p_config.ban_threshold {
            self.ban_peer(peer_id);
            return true;
        }

        false
    }
}
