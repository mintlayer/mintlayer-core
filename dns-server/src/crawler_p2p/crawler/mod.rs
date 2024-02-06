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

//! # Mintlayer P2P network crawler
//!
//! To keep things simple, the server will try to keep connections open to all reachable nodes.
//! When a new outbound connection is made, a new DNS record is added (but only for nodes on default ports).
//! When the connection is closed, the DNS record is removed.
//! When a connection fails, the server increases the backoff time between connection attempts.
//! If the number of failed connection attempts exceeds the limit, the address is removed from the list.
//! Once-reachable and newer-reachable addresses have different connection failure limits
//! (equivalent to about 1 month and about 1 hour, respectively).
//!
//! The crawler is deterministic (and therefore can't do IO operations itself).
//! All input comes in the form of `Event` messages and all output comes in the form of `Command` messages.

pub mod address_data;

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use chainstate::ban_score::BanScore;
use common::{chain::ChainConfig, primitives::time::Time};
use crypto::random::{seq::IteratorRandom, Rng};
use logging::log;
use p2p::{
    error::P2pError,
    net::types::PeerInfo,
    peer_manager::{ADDR_RATE_BUCKET_SIZE, ADDR_RATE_INITIAL_SIZE, MAX_ADDR_RATE_PER_SECOND},
    types::{bannable_address::BannableAddress, peer_id::PeerId, socket_address::SocketAddress},
    utils::rate_limiter::RateLimiter,
};
use utils::make_config_setting;

use crate::crawler_p2p::crawler::address_data::{AddressStateTransitionTo, SoftwareInfo};

use self::address_data::{AddressData, AddressState, ConnectionInfo};

use super::crawler_manager::storage::AddressInfo;

/// How many outbound connection attempts can be made per heartbeat
const MAX_CONNECTS_PER_HEARTBEAT: usize = 25;

make_config_setting!(BanThreshold, u32, 100);
make_config_setting!(BanDuration, Duration, Duration::from_secs(60 * 60 * 24));

#[derive(Default, Clone)]
pub struct CrawlerConfig {
    pub ban_threshold: BanThreshold,
    pub ban_duration: BanDuration,
}

/// The `Crawler` is the component that communicates with Mintlayer peers using p2p,
/// and based on the results, commands the DNS server to add/remove ip addresses.
/// The `Crawler` emits events that communicate whether addresses were reached or,
/// are unreachable anymore.
pub struct Crawler {
    /// Current time. This value is advanced explicitly by the caller code.
    now: Time,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    /// Crawler config
    config: CrawlerConfig,

    /// Map of all known addresses (including currently unreachable); these addresses
    /// will be periodically tested, and reachable addresses will be handed
    /// to the DNS server to be returned to the user on DNS queries,
    /// and unreachable addresses will be removed from the DNS server
    addresses: BTreeMap<SocketAddress, AddressData>,

    /// Banned addresses.
    banned_addresses: BTreeMap<BannableAddress, Time>,

    /// Map of all currently connected outbound peers that we successfully
    /// reached and are still connected to (generally speaking,
    /// we don't have to stay connected to those peers, but this is an implementation detail)
    outbound_peers: BTreeMap<PeerId, Peer>,
}

struct Peer {
    address: SocketAddress,
    address_rate_limiter: RateLimiter,
    ban_score: u32,
}

pub enum CrawlerEvent {
    Timer {
        period: Duration,
    },
    NewAddress {
        address: SocketAddress,
        sender: PeerId,
    },
    Connected {
        address: SocketAddress,
        peer_info: PeerInfo,
    },
    Disconnected {
        peer_id: PeerId,
    },
    // Note: same as ConnectivityEvent::ConnectionError, this error is not supposed to be
    // bannable. An additional MisbehavedOnHandshake event will be generated if the peer misbehaves
    // during handshake.
    ConnectionError {
        address: SocketAddress,
        error: P2pError,
    },
    Misbehaved {
        peer_id: PeerId,
        error: P2pError,
    },
    MisbehavedOnHandshake {
        address: SocketAddress,
        error: P2pError,
    },
}

pub enum CrawlerCommand {
    Connect {
        address: SocketAddress,
    },
    Disconnect {
        peer_id: PeerId,
    },
    UpdateAddress {
        address: SocketAddress,
        old_state: AddressState,
        new_state: AddressState,
    },
    MarkAsBanned {
        address: BannableAddress,
        ban_until: Time,
    },
    RemoveBannedStatus {
        address: BannableAddress,
    },
}

impl Crawler {
    pub fn new(
        now: Time,
        chain_config: Arc<ChainConfig>,
        config: CrawlerConfig,
        loaded_addresses: BTreeMap<SocketAddress, AddressInfo>,
        loaded_banned_addresses: BTreeMap<BannableAddress, Time>,
        reserved_addresses: BTreeSet<SocketAddress>,
    ) -> Self {
        let addresses = {
            let mut addresses = loaded_addresses
                .iter()
                .map(|(addr, addr_info)| {
                    (
                        *addr,
                        AddressData {
                            state: AddressState::Disconnected {
                                fail_count: 0,
                                connection_info: Some(ConnectionInfo {
                                    peer_software_info: addr_info.software_info.clone(),
                                }),
                                disconnected_at: now,
                            },
                            reserved: false.into(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();

            for reserved_addr in reserved_addresses {
                match addresses.entry(reserved_addr) {
                    Entry::Occupied(mut e) => {
                        e.get_mut().reserved = true.into();
                    }
                    Entry::Vacant(e) => {
                        e.insert(AddressData {
                            state: AddressState::Disconnected {
                                fail_count: 0,
                                connection_info: None,
                                disconnected_at: now,
                            },
                            reserved: true.into(),
                        });
                    }
                }
            }

            addresses
        };

        Self {
            now,
            chain_config,
            config,
            addresses,
            banned_addresses: loaded_banned_addresses,
            outbound_peers: BTreeMap::new(),
        }
    }

    fn handle_connected(
        &mut self,
        address: SocketAddress,
        peer_info: PeerInfo,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        log::info!("connection opened, peer_id: {}", peer_info.peer_id);
        self.create_outbound_peer(peer_info.peer_id, address, peer_info, callback);
    }

    fn handle_connection_error(
        &mut self,
        address: SocketAddress,
        error: P2pError,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        log::debug!("connection to {} failed: {}", address.to_string(), error);

        let address_data = self
            .addresses
            .get_mut(&address)
            .expect("address must be known (handle_connection_error)");

        Self::change_address_state(
            self.now,
            &address,
            address_data,
            AddressStateTransitionTo::Disconnected,
            callback,
        );
    }

    fn handle_misbehavior_on_handshake(
        &mut self,
        address: SocketAddress,
        error: P2pError,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        log::debug!(
            "handling misbehavior on handshake for {}: {}",
            address.to_string(),
            error
        );

        self.handle_new_ban_score(&address, error.ban_score(), callback);
    }

    fn handle_misbehaved_peer(
        &mut self,
        peer_id: PeerId,
        error: P2pError,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        let ban_score = error.ban_score();

        if ban_score > 0 {
            log::debug!("handling misbehaved peer, peer_id: {peer_id}");

            let peer = self
                .outbound_peers
                .get_mut(&peer_id)
                .expect("peer must be known (handle_misbehaved_peer)");
            peer.ban_score = peer.ban_score.saturating_add(ban_score);

            log::info!(
                "Adjusting peer ban score for peer {peer_id}, adjustment: {ban_score}, new score: {}",
                peer.ban_score
            );

            let address = peer.address;
            let new_score = peer.ban_score;
            self.handle_new_ban_score(&address, new_score, callback);
        }
    }

    fn handle_new_ban_score(
        &mut self,
        address: &SocketAddress,
        new_ban_score: u32,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        let ban_until = (self.now + *self.config.ban_duration).expect("Unexpected ban duration");

        if new_ban_score >= *self.config.ban_threshold {
            let address = address.as_bannable();

            log::info!("Ban threshold for address {address} reached");

            self.disconnect_all(&address, callback);
            callback(CrawlerCommand::MarkAsBanned { address, ban_until });
            self.banned_addresses.insert(address, ban_until);
        }
    }

    fn disconnect_all(
        &mut self,
        address: &BannableAddress,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        let to_disconnect = self
            .outbound_peers
            .iter()
            .filter_map(|(peer_id, peer)| {
                if peer.address.as_bannable() == *address {
                    Some((*peer_id, peer.address))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (peer_id, peer_address) in to_disconnect {
            self.disconnect_peer(peer_id, &peer_address, callback);
        }
    }

    fn handle_disconnected(&mut self, peer_id: PeerId, callback: &mut impl FnMut(CrawlerCommand)) {
        log::debug!("connection closed, peer_id: {}", peer_id);
        self.remove_outbound_peer(peer_id, callback);
    }

    fn handle_new_address(&mut self, address: SocketAddress, sender: PeerId) {
        let peer = self.outbound_peers.get_mut(&sender).expect("must be connected peer");
        if !peer.address_rate_limiter.accept(self.now) {
            log::debug!(
                "address announcement is rate limited from peer {} ({})",
                sender,
                address.to_string()
            );
            return;
        }
        if let Entry::Vacant(vacant) = self.addresses.entry(address) {
            log::debug!("new address {} added", address.to_string());
            vacant.insert(AddressData {
                state: AddressState::Disconnected {
                    fail_count: 0,
                    connection_info: None,
                    disconnected_at: self.now,
                },
                reserved: false.into(),
            });
        }
    }

    /// Update address state.
    ///
    /// The only place where the address state can be updated.
    fn change_address_state(
        now: Time,
        address: &SocketAddress,
        address_data: &mut AddressData,
        transition: AddressStateTransitionTo,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        log::debug!(
            "change address {} state to {:?}",
            address.to_string(),
            transition
        );

        let old_state = address_data.state.clone();

        address_data.transition_to(transition, now);

        callback(CrawlerCommand::UpdateAddress {
            address: *address,
            old_state,
            new_state: address_data.state.clone(),
        });
    }

    /// Create new outbound peer
    fn create_outbound_peer(
        &mut self,
        peer_id: PeerId,
        address: SocketAddress,
        peer_info: PeerInfo,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        let address_rate_limiter = RateLimiter::new(
            self.now,
            MAX_ADDR_RATE_PER_SECOND,
            ADDR_RATE_INITIAL_SIZE,
            ADDR_RATE_BUCKET_SIZE,
        );

        let peer = Peer {
            address,
            address_rate_limiter,
            ban_score: 0,
        };

        let old_peer = self.outbound_peers.insert(peer_id, peer);
        assert!(old_peer.is_none());

        log::debug!(
            "Outbound peer inserted, address: {}, peer_id: {} (total peer count: {})",
            address.to_string(),
            peer_id,
            self.outbound_peers.len()
        );

        let peer_compatibility_check_result = peer_info.check_compatibility(&self.chain_config);

        match peer_compatibility_check_result {
            Ok(()) => {
                log::info!(
                    "New outbound peer created, address: {}, peer_id: {}",
                    address.to_string(),
                    peer_id
                );

                let address_data = self
                    .addresses
                    .get_mut(&address)
                    .expect("address must be known (create_outbound_peer)");

                Self::change_address_state(
                    self.now,
                    &address,
                    address_data,
                    AddressStateTransitionTo::Connected {
                        peer_software_info: SoftwareInfo {
                            user_agent: peer_info.user_agent,
                            version: peer_info.software_version,
                        },
                    },
                    callback,
                );
            }
            Err(err) => {
                log::info!(
                    "Rejecting incompatible peer {peer_id} with address {}: {}",
                    address.to_string(),
                    err.to_string(),
                );

                self.disconnect_peer(peer_id, &address, callback);
            }
        }
    }

    fn disconnect_peer(
        &mut self,
        peer_id: PeerId,
        address: &SocketAddress,
        callback: &mut impl FnMut(CrawlerCommand),
    ) {
        let address_data = self
            .addresses
            .get_mut(address)
            .expect("address must be known (disconnect_peer)");

        callback(CrawlerCommand::Disconnect { peer_id });

        Self::change_address_state(
            self.now,
            address,
            address_data,
            AddressStateTransitionTo::Disconnecting,
            callback,
        );
    }

    /// Remove existing outbound peer
    fn remove_outbound_peer(&mut self, peer_id: PeerId, callback: &mut impl FnMut(CrawlerCommand)) {
        let peer = self
            .outbound_peers
            .remove(&peer_id)
            .expect("peer must be known (remove_outbound_peer)");

        log::debug!(
            "Outbound peer removed, peer_id: {} (total peer count: {})",
            peer_id,
            self.outbound_peers.len()
        );

        let address_data = self
            .addresses
            .get_mut(&peer.address)
            .expect("address must be known (remove_outbound_peer)");

        Self::change_address_state(
            self.now,
            &peer.address,
            address_data,
            AddressStateTransitionTo::Disconnected,
            callback,
        );
    }

    /// Peer and address list maintenance.
    ///
    /// Select random addresses to connect to, delete old addresses from memory and DB.
    fn heartbeat(&mut self, callback: &mut impl FnMut(CrawlerCommand), rng: &mut impl Rng) {
        self.banned_addresses.retain(|address, banned_until| {
            let banned = self.now < *banned_until;

            if !banned {
                callback(CrawlerCommand::RemoveBannedStatus { address: *address });
            }

            banned
        });

        let connecting_addresses = self
            .addresses
            .iter_mut()
            .filter(|(address, address_data)| {
                address_data.connect_now(self.now)
                    && self.banned_addresses.get(&address.as_bannable()).is_none()
            })
            .choose_multiple(rng, MAX_CONNECTS_PER_HEARTBEAT);

        for (address, address_data) in connecting_addresses {
            Self::change_address_state(
                self.now,
                address,
                address_data,
                AddressStateTransitionTo::Connecting,
                callback,
            );

            callback(CrawlerCommand::Connect { address: *address });
        }

        self.addresses.retain(|_address, address_data| address_data.retain(self.now));
    }

    /// Process one input event and receive any number of output commands
    pub fn step(
        &mut self,
        event: CrawlerEvent,
        callback: &mut impl FnMut(CrawlerCommand),
        rng: &mut impl Rng,
    ) {
        match event {
            CrawlerEvent::Timer { period } => {
                assert!(
                    period <= Duration::from_secs(24 * 3600),
                    "time step is too big"
                );

                self.now = (self.now + period).expect("All local values of Time must be valid");

                self.heartbeat(callback, rng);
            }
            CrawlerEvent::NewAddress { address, sender } => {
                self.handle_new_address(address, sender);
            }
            CrawlerEvent::Connected { peer_info, address } => {
                self.handle_connected(address, peer_info, callback);
            }
            CrawlerEvent::Disconnected { peer_id } => {
                self.handle_disconnected(peer_id, callback);
            }
            CrawlerEvent::ConnectionError { address, error } => {
                self.handle_connection_error(address, error, callback);
            }
            CrawlerEvent::MisbehavedOnHandshake { address, error } => {
                self.handle_misbehavior_on_handshake(address, error, callback);
            }
            CrawlerEvent::Misbehaved { peer_id, error } => {
                self.handle_misbehaved_peer(peer_id, error, callback)
            }
        }
    }
}

#[cfg(test)]
mod tests;
