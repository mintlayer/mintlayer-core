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

use common::chain::ChainConfig;
use crypto::random::{seq::IteratorRandom, Rng};
use logging::log;
use p2p::{error::P2pError, net::types::PeerInfo, types::peer_id::PeerId};

use crate::crawler_p2p::crawler::address_data::AddressStateTransitionTo;

use self::address_data::{AddressData, AddressState};

/// How many outbound connection attempts can be made per heartbeat
const MAX_CONNECTS_PER_HEARTBEAT: usize = 25;

/// The `Crawler` is the component that communicates with Mintlayer peers using p2p,
/// and based on the results, commands the DNS server to add/remove ip addresses.
/// The `Crawler` emits events that communicate whether addresses were reached or,
/// are unreachable anymore.
pub struct Crawler<A> {
    /// Time of some monotonic timer, started from 0
    now: Duration,

    /// Chain config
    chain_config: Arc<ChainConfig>,

    /// Map of all known addresses (including currently unreachable); these addresses
    /// will be periodically tested, and reachable addresses will be handed
    /// to the DNS server to be returned to the user on DNS queries,
    /// and unreachable addresses will be removed from the DNS server
    addresses: BTreeMap<A, AddressData>,

    /// Map of all currently connected outbound peers that we successfully
    /// reached and are still connected to (generally speaking,
    /// we don't have to stay connected to those peers, but this is an implementation detail)
    outbound_peers: BTreeMap<PeerId, A>,
}

pub enum CrawlerEvent<A> {
    Timer { period: Duration },
    NewAddress { address: A },
    Connected { address: A, peer_info: PeerInfo },
    Disconnected { peer_id: PeerId },
    ConnectionError { address: A, error: P2pError },
}

pub enum CrawlerCommand<A> {
    Connect {
        address: A,
    },
    Disconnect {
        peer_id: PeerId,
    },
    UpdateAddress {
        address: A,
        old_state: AddressState,
        new_state: AddressState,
    },
}

impl<A: Ord + Clone + ToString> Crawler<A> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        loaded_addresses: BTreeSet<A>,
        added_addresses: BTreeSet<A>,
    ) -> Self {
        let now = Duration::ZERO;

        let addresses = loaded_addresses
            .union(&added_addresses)
            .map(|addr| {
                (
                    addr.clone(),
                    AddressData {
                        state: AddressState::Disconnected {
                            fail_count: 0,
                            was_reachable: loaded_addresses.contains(addr),
                            disconnected_at: now,
                        },
                        user_added: added_addresses.contains(addr).into(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        Self {
            now,
            chain_config,
            addresses,
            outbound_peers: BTreeMap::new(),
        }
    }

    fn handle_connected(
        &mut self,
        address: A,
        peer_info: PeerInfo,
        callback: &mut impl FnMut(CrawlerCommand<A>),
    ) {
        log::info!("connected open, peer_id: {}", peer_info.peer_id);
        self.create_outbound_peer(peer_info.peer_id, address, peer_info, callback);
    }

    fn handle_connection_error(
        &mut self,
        address: A,
        error: P2pError,
        callback: &mut impl FnMut(CrawlerCommand<A>),
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

    fn handle_disconnected(
        &mut self,
        peer_id: PeerId,
        callback: &mut impl FnMut(CrawlerCommand<A>),
    ) {
        log::debug!("connection closed, peer_id: {}", peer_id);
        self.remove_outbound_peer(peer_id, callback);
    }

    fn handle_new_address(&mut self, address: A) {
        if let Entry::Vacant(vacant) = self.addresses.entry(address.clone()) {
            log::debug!("new address {} added", address.to_string());
            vacant.insert(AddressData {
                state: AddressState::Disconnected {
                    fail_count: 0,
                    was_reachable: false,
                    disconnected_at: self.now,
                },
                user_added: false.into(),
            });
        }
    }

    /// Update address state.
    ///
    /// The only place where the address state can be updated.
    fn change_address_state(
        now: Duration,
        address: &A,
        address_data: &mut AddressData,
        transition: AddressStateTransitionTo,
        callback: &mut impl FnMut(CrawlerCommand<A>),
    ) {
        log::debug!(
            "change address {} state to {:?}",
            address.to_string(),
            transition
        );

        let old_state = address_data.state.clone();

        address_data.transition_to(transition, now);

        callback(CrawlerCommand::UpdateAddress {
            address: address.clone(),
            old_state,
            new_state: address_data.state.clone(),
        });
    }

    /// Create new outbound peer
    fn create_outbound_peer(
        &mut self,
        peer_id: PeerId,
        address: A,
        peer_info: PeerInfo,
        callback: &mut impl FnMut(CrawlerCommand<A>),
    ) {
        let old_peer = self.outbound_peers.insert(peer_id, address.clone());
        assert!(old_peer.is_none());

        let is_compatible = peer_info.is_compatible(&self.chain_config);

        log::info!(
            "new outbound peer created, address: {}, peer_id: {}, compatible: {}",
            address.to_string(),
            peer_id,
            is_compatible
        );

        let address_data = self
            .addresses
            .get_mut(&address)
            .expect("address must be known (create_outbound_peer)");

        if is_compatible {
            Self::change_address_state(
                self.now,
                &address,
                address_data,
                AddressStateTransitionTo::Connected,
                callback,
            );
        } else {
            callback(CrawlerCommand::Disconnect { peer_id });

            Self::change_address_state(
                self.now,
                &address,
                address_data,
                AddressStateTransitionTo::Disconnecting,
                callback,
            );
        }
    }

    /// Remove existing outbound peer
    fn remove_outbound_peer(
        &mut self,
        peer_id: PeerId,
        callback: &mut impl FnMut(CrawlerCommand<A>),
    ) {
        log::debug!("outbound peer removed, peer_id: {}", peer_id);

        let address = self
            .outbound_peers
            .remove(&peer_id)
            .expect("peer must be known (remove_outbound_peer)");

        let address_data = self
            .addresses
            .get_mut(&address)
            .expect("address must be known (remove_outbound_peer)");

        Self::change_address_state(
            self.now,
            &address,
            address_data,
            AddressStateTransitionTo::Disconnected,
            callback,
        );
    }

    /// Peer and address list maintenance.
    ///
    /// Select random addresses to connect to, delete old addresses from memory and DB.
    fn heartbeat(&mut self, callback: &mut impl FnMut(CrawlerCommand<A>), rng: &mut impl Rng) {
        let connecting_addresses = self
            .addresses
            .iter_mut()
            .filter(|(_address, address_data)| address_data.connect_now(self.now))
            .choose_multiple(rng, MAX_CONNECTS_PER_HEARTBEAT);

        for (address, address_data) in connecting_addresses {
            Self::change_address_state(
                self.now,
                address,
                address_data,
                AddressStateTransitionTo::Connecting,
                callback,
            );

            callback(CrawlerCommand::Connect {
                address: address.clone(),
            });
        }

        self.addresses.retain(|_address, address_data| address_data.retain(self.now));
    }

    /// Process one input event and receive any number of output commands
    pub fn step(
        &mut self,
        event: CrawlerEvent<A>,
        callback: &mut impl FnMut(CrawlerCommand<A>),
        rng: &mut impl Rng,
    ) {
        match event {
            CrawlerEvent::Timer { period } => {
                assert!(
                    period <= Duration::from_secs(24 * 3600),
                    "time step is too big"
                );

                self.now += period;

                self.heartbeat(callback, rng);
            }
            CrawlerEvent::NewAddress { address } => {
                self.handle_new_address(address);
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
        }
    }
}

#[cfg(test)]
mod tests;
