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
//! The peer database stores:
//! - all outbound peer addresses
//! - banned addresses
//!
//! Connected peers are those peers that the [`crate::peer_manager::PeerManager`] has an active
//! connection with. Available addresses are discovered through various peer discovery mechanisms and they are
//! used by [`crate::peer_manager::PeerManager::heartbeat()`] to establish new outbound connections
//! if the actual number of active connection is less than the desired number of connections.

pub mod address_data;
pub mod storage;
pub mod storage_impl;
mod storage_load;

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use common::time_getter::TimeGetter;
use crypto::random::{make_pseudo_rng, seq::IteratorRandom};
use logging::log;
use tokio::time::Instant;

use crate::{config, error::P2pError, net::AsBannableAddress};

use self::{
    address_data::{AddressData, AddressStateTransitionTo},
    storage::{PeerDbStorage, PeerDbStorageWrite},
    storage_load::LoadedStorage,
};

use super::MAX_OUTBOUND_CONNECTIONS;

pub struct PeerDb<A, B, S> {
    /// P2P configuration
    p2p_config: Arc<config::P2pConfig>,

    /// Map of all outbound peer addresses
    addresses: BTreeMap<A, AddressData>,

    /// Set of addresses that have the `user_flag` set.
    /// Used as an optimization to not iterate over the entire `addresses` map.
    /// Every listed address must exist in the `addresses` map.
    added_nodes: BTreeSet<A>,

    /// Banned addresses along with the duration of the ban.
    ///
    /// The duration represents the `UNIX_EPOCH + duration` time point, so the ban should end
    /// when `current_time > ban_duration`.
    banned_addresses: BTreeMap<B, Duration>,

    time_getter: TimeGetter,

    storage: S,
}

impl<A, B, S> PeerDb<A, B, S>
where
    A: Ord + FromStr + ToString + Clone + AsBannableAddress<BannableAddress = B>,
    B: Ord + FromStr + ToString,
    S: PeerDbStorage,
{
    pub fn new(
        p2p_config: Arc<config::P2pConfig>,
        time_getter: TimeGetter,
        storage: S,
    ) -> crate::Result<Self> {
        // Node won't start if DB loading fails!
        let loaded_storage = LoadedStorage::<A, B>::load_storage(&storage)?;

        let added_nodes = p2p_config
            .added_nodes
            .iter()
            .map(|addr| {
                addr.parse::<A>().map_err(|_err| {
                    P2pError::InvalidConfigurationValue(format!("Invalid address: {addr}"))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        let now = Instant::now();
        let addresses = loaded_storage
            .known_addresses
            .union(&added_nodes)
            .map(|addr| {
                (
                    addr.clone(),
                    AddressData::new(
                        loaded_storage.known_addresses.contains(addr),
                        added_nodes.contains(addr),
                        now,
                    ),
                )
            })
            .collect();

        Ok(Self {
            addresses,
            banned_addresses: loaded_storage.banned_addresses,
            added_nodes,
            p2p_config,
            time_getter,
            storage,
        })
    }

    /// Iterator of all known addresses.
    ///
    /// Result could be shared with remote peers over network.
    pub fn known_addresses(&self) -> impl Iterator<Item = &A> {
        self.addresses.keys()
    }

    /// Selects peer addresses for outbound connections (except user-added)
    pub fn select_new_outbound_addresses(
        &self,
        pending_outbound: &BTreeSet<A>,
        connected_outbound_count: usize,
    ) -> Vec<A> {
        let now = Instant::now();
        let count = MAX_OUTBOUND_CONNECTIONS
            .saturating_sub(pending_outbound.len())
            .saturating_sub(connected_outbound_count);

        // TODO: Ignore banned addresses
        // TODO: Allow only one connection per IP address
        self.addresses
            .iter()
            .filter_map(|(addr, address_data)| {
                if address_data.connect_now(now)
                    && !pending_outbound.contains(addr)
                    && !address_data.user_added()
                {
                    Some(addr.clone())
                } else {
                    None
                }
            })
            .choose_multiple(&mut make_pseudo_rng(), count)
    }

    /// Selects user-added peer addresses for outbound connections
    pub fn select_user_added_outbound_addresses(&self, pending_outbound: &BTreeSet<A>) -> Vec<A> {
        let now = Instant::now();
        self.added_nodes
            .iter()
            .filter_map(|addr| {
                let address_data = self
                    .addresses
                    .get(addr)
                    .expect("added nodes must always be in the addresses map");
                if address_data.connect_now(now) && !pending_outbound.contains(addr) {
                    Some(addr.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Perform the PeerDb maintenance
    pub fn heartbeat(&mut self) {
        let now = Instant::now();
        self.addresses.retain(|_addr, address_data| address_data.retain(now));
    }

    /// Add new peer addresses
    pub fn peer_discovered(&mut self, address: A) {
        if let Entry::Vacant(entry) = self.addresses.entry(address.clone()) {
            log::debug!("new address discovered: {}", address.to_string());
            entry.insert(AddressData::new(false, false, Instant::now()));
        }
    }

    /// Report outbound connection failure
    ///
    /// When [`crate::peer_manager::PeerManager::heartbeat()`] has initiated an outbound connection
    /// and the connection is refused, it's reported back to the `PeerDb` so it marks the address as unreachable.
    pub fn report_outbound_failure(&mut self, address: A, _error: &P2pError) {
        self.change_address_state(address, AddressStateTransitionTo::ConnectionFailed);
    }

    /// Mark peer as connected
    ///
    /// After `PeerManager` has established either an inbound or an outbound connection,
    /// it informs the `PeerDb` about it.
    pub fn outbound_peer_connected(&mut self, address: A) {
        self.change_address_state(address, AddressStateTransitionTo::Connected);
    }

    /// Handle peer disconnection event
    ///
    /// Close the connection to an active peer.
    pub fn outbound_peer_disconnected(&mut self, address: A) {
        self.change_address_state(address, AddressStateTransitionTo::Disconnected);
    }

    pub fn change_address_state(&mut self, address: A, transition: AddressStateTransitionTo) {
        if let Some(address_data) = self.addresses.get_mut(&address) {
            let is_persistent_old = address_data.is_persistent();

            address_data.transition_to(transition, Instant::now());

            let is_persistent_new = address_data.is_persistent();

            match (is_persistent_old, is_persistent_new) {
                (false, true) => {
                    storage::update_db(&self.storage, |tx| {
                        tx.add_known_address(&address.to_string())
                    })
                    .expect("adding address expected to succeed (peer_connected)");
                }
                (true, false) => {
                    storage::update_db(&self.storage, |tx| {
                        tx.del_known_address(&address.to_string())
                    })
                    .expect("adding address expected to succeed (peer_connected)");
                }
                _ => {}
            }
        }
    }

    /// Checks if the given address is banned
    pub fn is_address_banned(&mut self, address: &B) -> bool {
        if let Some(banned_till) = self.banned_addresses.get(address) {
            // Check if the ban has expired
            let now = self.time_getter.get_time();
            if now <= *banned_till {
                return true;
            }

            self.banned_addresses.remove(address);

            storage::update_db(&self.storage, |tx| {
                tx.del_banned_address(&address.to_string())
            })
            .expect("removing banned address is expected to succeed (is_address_banned)");
        }

        false
    }

    /// Changes the address state to banned
    pub fn ban_peer(&mut self, address: &A) {
        let bannable_address = address.as_bannable();
        let ban_till = self.time_getter.get_time() + *self.p2p_config.ban_duration;

        storage::update_db(&self.storage, |tx| {
            tx.add_banned_address(&bannable_address.to_string(), ban_till)
        })
        .expect("adding banned address is expected to succeed (ban_peer)");

        self.banned_addresses.insert(bannable_address, ban_till);
    }
}

#[cfg(test)]
mod tests;
