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
//! - connected peers
//! - available (discovered) addresses
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
    sync::Arc,
    time::Duration,
};

use common::time_getter::TimeGetter;
use crypto::random::{make_pseudo_rng, seq::IteratorRandom};

use crate::{
    config,
    error::{ConversionError, P2pError},
    net::{types::Role, AsBannableAddress, NetworkingService},
};

use self::{
    address_data::AddressData,
    storage::{PeerDbStorage, PeerDbStorageWrite},
    storage_load::LoadedStorage,
};

use super::MAX_OUTBOUND_CONNECTIONS;

pub struct PeerDb<T: NetworkingService, S> {
    /// P2P configuration
    p2p_config: Arc<config::P2pConfig>,

    /// Set of currently connected addresses (outbound)
    connected_outbound: BTreeSet<T::Address>,

    /// Set of currently connected addresses (inbound)
    connected_inbound: BTreeSet<T::Address>,

    /// Set of currently connecting outbound addresses
    pending_outbound: BTreeSet<T::Address>,

    /// Map of all known addresses
    addresses: BTreeMap<T::Address, AddressData>,

    /// Banned addresses along with the duration of the ban.
    ///
    /// The duration represents the `UNIX_EPOCH + duration` time point, so the ban should end
    /// when `current_time > ban_duration`.
    banned_addresses: BTreeMap<T::BannableAddress, Duration>,

    time_getter: TimeGetter,

    storage: S,
}

impl<T: NetworkingService, S: PeerDbStorage> PeerDb<T, S> {
    pub fn new(
        p2p_config: Arc<config::P2pConfig>,
        time_getter: TimeGetter,
        storage: S,
    ) -> crate::Result<Self> {
        // Node won't start if DB loading fails!
        let loaded_storage =
            LoadedStorage::<T::Address, T::BannableAddress>::load_storage(&storage)?;

        let added_nodes = p2p_config
            .added_nodes
            .iter()
            .map(|addr| {
                addr.parse::<T::Address>().map_err(|_err| {
                    P2pError::ConversionError(ConversionError::InvalidAddress(addr.clone()))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;

        let addresses = loaded_storage
            .known_addresses
            .union(&added_nodes)
            .map(|addr| {
                (
                    addr.clone(),
                    AddressData {
                        was_reachable: loaded_storage.known_addresses.contains(addr),
                        user_added: added_nodes.contains(addr).into(),
                        fail_count: 0,
                    },
                )
            })
            .collect();

        Ok(Self {
            connected_outbound: Default::default(),
            connected_inbound: Default::default(),
            pending_outbound: Default::default(),
            addresses,
            banned_addresses: loaded_storage.banned_addresses,
            p2p_config,
            time_getter,
            storage,
        })
    }

    /// Checks if the given address is already connected.
    pub fn is_address_connected(&self, address: &T::Address) -> bool {
        self.connected_inbound.contains(address) || self.connected_outbound.contains(address)
    }

    /// Selects requested count of peer addresses from the DB randomly.
    ///
    /// Result could be shared with remote peers over network.
    pub fn random_known_addresses(&self, count: usize) -> Vec<T::Address> {
        self.addresses.keys().cloned().choose_multiple(&mut make_pseudo_rng(), count)
    }

    /// Selects peer addresses for outbound connections
    pub fn select_new_outbound_addresses(&self) -> Vec<T::Address> {
        let count = MAX_OUTBOUND_CONNECTIONS
            .saturating_sub(self.pending_outbound.len())
            .saturating_sub(self.connected_outbound.len());

        self.addresses
            .keys()
            .filter(|addr| {
                !self.pending_outbound.contains(addr) && !self.connected_outbound.contains(addr)
            })
            .cloned()
            .choose_multiple(&mut make_pseudo_rng(), count)
    }

    /// Checks if the given address is banned
    pub fn is_address_banned(&mut self, address: &T::BannableAddress) -> bool {
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

    /// Add new peer addresses
    pub fn peer_discovered(&mut self, address: &T::Address) {
        if let Entry::Vacant(entry) = self.addresses.entry(address.clone()) {
            entry.insert(AddressData {
                was_reachable: false,
                user_added: false.into(),
                fail_count: 0,
            });
        }
    }

    /// Report outbound connection failure
    ///
    /// When [`crate::peer_manager::PeerManager::heartbeat()`] has initiated an outbound connection
    /// and the connection is refused, it's reported back to the `PeerDb` so it marks the address as unreachable.
    pub fn report_outbound_failure(&mut self, address: T::Address) {
        // TODO: implement
        let removed = self.pending_outbound.remove(&address);
        assert!(removed);

        if let Some(address) = self.addresses.get_mut(&address) {
            address.fail_count += 1;
        }
    }

    pub fn outbound_connection_initiated(&mut self, address: T::Address) {
        let inserted = self.pending_outbound.insert(address);
        assert!(inserted);
    }

    /// Mark peer as connected
    ///
    /// After `PeerManager` has established either an inbound or an outbound connection,
    /// it informs the `PeerDb` about it.
    pub fn peer_connected(&mut self, address: T::Address, role: Role) {
        match role {
            Role::Inbound => {
                let inserted = self.connected_inbound.insert(address);
                assert!(inserted);
            }
            Role::Outbound => {
                let inserted = self.connected_outbound.insert(address.clone());
                assert!(inserted);

                let removed = self.pending_outbound.remove(&address);
                assert!(removed);

                if let Some(address_data) = self.addresses.get_mut(&address) {
                    if !address_data.was_reachable {
                        address_data.was_reachable = true;

                        storage::update_db(&self.storage, |tx| {
                            tx.add_known_address(&address.to_string())
                        })
                        .expect("adding address expected to succeed (peer_connected)");
                    }
                }
            }
        }
    }

    /// Handle peer disconnection event
    ///
    /// Close the connection to an active peer.
    pub fn peer_disconnected(&mut self, address: T::Address, role: Role) {
        match role {
            Role::Inbound => {
                let removed = self.connected_inbound.remove(&address);
                assert!(removed);
            }
            Role::Outbound => {
                let removed = self.connected_outbound.remove(&address);
                assert!(removed);
            }
        }
    }

    /// Changes the address state to banned
    pub fn ban_peer(&mut self, address: &T::Address) {
        let bannable_address = address.as_bannable();
        let ban_till = self.time_getter.get_time() + *self.p2p_config.ban_duration;

        storage::update_db(&self.storage, |tx| {
            tx.add_banned_address(&bannable_address.to_string(), ban_till)
        })
        .expect("adding banned address is expected to succeed (ban_peer)");

        self.banned_addresses.insert(bannable_address, ban_till);
    }

    #[cfg(feature = "testing_utils")]
    pub fn get_storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }
}
