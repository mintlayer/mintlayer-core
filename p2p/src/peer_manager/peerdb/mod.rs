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
    sync::Arc,
    time::Duration,
};

use common::{chain::ChainConfig, time_getter::TimeGetter};
use crypto::random::{make_pseudo_rng, seq::IteratorRandom, SliceRandom};
use itertools::Itertools;
use logging::log;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};

use crate::{config, error::P2pError};

use self::{
    address_data::{AddressData, AddressStateTransitionTo},
    storage::{PeerDbStorage, PeerDbStorageWrite},
    storage_load::LoadedStorage,
};

use super::{address_groups::AddressGroup, ip_or_socket_address_to_peer_address};

pub struct PeerDb<S> {
    /// P2P configuration
    p2p_config: Arc<config::P2pConfig>,

    /// Map of all outbound peer addresses
    addresses: BTreeMap<SocketAddress, AddressData>,

    /// Set of addresses that have the `reserved` flag set.
    /// Used as an optimization to not iterate over the entire `addresses` map.
    /// Every listed address must exist in the `addresses` map.
    reserved_nodes: BTreeSet<SocketAddress>,

    /// Banned addresses along with the duration of the ban.
    ///
    /// The duration represents the `UNIX_EPOCH + duration` time point, so the ban should end
    /// when `current_time > ban_duration`.
    banned_addresses: BTreeMap<BannableAddress, Duration>,

    anchor_addresses: BTreeSet<SocketAddress>,

    time_getter: TimeGetter,

    storage: S,
}

impl<S: PeerDbStorage> PeerDb<S> {
    pub fn new(
        chain_config: &ChainConfig,
        p2p_config: Arc<config::P2pConfig>,
        time_getter: TimeGetter,
        storage: S,
    ) -> crate::Result<Self> {
        // Node won't start if DB loading fails!
        let LoadedStorage {
            known_addresses,
            banned_addresses,
            anchor_addresses,
        } = LoadedStorage::load_storage(&storage)?;

        let boot_nodes = p2p_config
            .boot_nodes
            .iter()
            .map(|addr| ip_or_socket_address_to_peer_address(addr, chain_config))
            .collect::<BTreeSet<_>>();
        let reserved_nodes = p2p_config
            .reserved_nodes
            .iter()
            .map(|addr| ip_or_socket_address_to_peer_address(addr, chain_config))
            .collect::<BTreeSet<_>>();

        let now = time_getter.get_time();
        let addresses = known_addresses
            .iter()
            .chain(boot_nodes.iter())
            .chain(reserved_nodes.iter())
            .map(|addr| {
                (
                    *addr,
                    AddressData::new(
                        known_addresses.contains(addr),
                        reserved_nodes.contains(addr),
                        now,
                    ),
                )
            })
            .collect();

        Ok(Self {
            addresses,
            reserved_nodes,
            banned_addresses,
            anchor_addresses,
            p2p_config,
            time_getter,
            storage,
        })
    }

    /// Iterator of all known addresses.
    ///
    /// Result could be shared with remote peers over network.
    pub fn known_addresses(&self) -> impl Iterator<Item = &SocketAddress> {
        self.addresses.keys()
    }

    /// Selects peer addresses for outbound connections (except reserved).
    /// Only one outbound connection is allowed per address group.
    pub fn select_new_outbound_addresses(
        &self,
        automatic_outbound: &BTreeSet<SocketAddress>,
        count: usize,
    ) -> Vec<SocketAddress> {
        if count == 0 {
            return Vec::new();
        }

        let now = self.time_getter.get_time();

        // Only consider outbound connections, as inbound connections are open to attackers.
        // Manual and reserved outbound peers are ignored.
        let outbound_groups = automatic_outbound
            .iter()
            .map(|a| AddressGroup::from_peer_address(&a.as_peer_address()))
            .collect::<BTreeSet<_>>();

        let mut selected = self
            .addresses
            .iter()
            .filter_map(|(addr, address_data)| {
                if address_data.connect_now(now)
                    && !outbound_groups
                        .contains(&AddressGroup::from_peer_address(&addr.as_peer_address()))
                    && !address_data.reserved()
                    && !self.banned_addresses.contains_key(&addr.as_bannable())
                {
                    Some(*addr)
                } else {
                    None
                }
            })
            .choose_multiple(&mut make_pseudo_rng(), count);

        // Drop duplicate address groups as needed (shuffle selected addresses first to make the selection fair)
        selected.shuffle(&mut make_pseudo_rng());
        selected
            .into_iter()
            .unique_by(|a| AddressGroup::from_peer_address(&a.as_peer_address()))
            .collect()
    }

    /// Selects reserved peer addresses for outbound connections
    pub fn select_reserved_outbound_addresses(
        &self,
        pending_outbound: &BTreeSet<SocketAddress>,
    ) -> Vec<SocketAddress> {
        let now = self.time_getter.get_time();
        self.reserved_nodes
            .iter()
            .filter_map(|addr| {
                let address_data = self
                    .addresses
                    .get(addr)
                    .expect("reserved nodes must always be in the addresses map");
                if address_data.connect_now(now) && !pending_outbound.contains(addr) {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Perform the PeerDb maintenance
    pub fn heartbeat(&mut self) {
        let now = self.time_getter.get_time();
        self.addresses.retain(|_addr, address_data| address_data.retain(now));

        let now = self.time_getter.get_time();
        self.banned_addresses.retain(|address, banned_till| {
            let banned = now <= *banned_till;

            if !banned {
                storage::update_db(&self.storage, |tx| {
                    tx.del_banned_address(&address.to_string())
                })
                .expect("removing banned address is expected to succeed");
            }

            banned
        });
    }

    /// Add new peer addresses
    pub fn peer_discovered(&mut self, address: SocketAddress) {
        if let Entry::Vacant(entry) = self.addresses.entry(address) {
            log::debug!("new address discovered: {}", address.to_string());
            entry.insert(AddressData::new(false, false, self.time_getter.get_time()));
        }
    }

    /// Report outbound connection failure
    ///
    /// When [`crate::peer_manager::PeerManager::heartbeat()`] has initiated an outbound connection
    /// and the connection is refused, it's reported back to the `PeerDb` so it marks the address as unreachable.
    pub fn report_outbound_failure(&mut self, address: SocketAddress, _error: &P2pError) {
        self.change_address_state(address, AddressStateTransitionTo::ConnectionFailed);
    }

    /// Mark peer as connected
    ///
    /// After `PeerManager` has established either an inbound or an outbound connection,
    /// it informs the `PeerDb` about it.
    pub fn outbound_peer_connected(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::Connected);
    }

    /// Handle peer disconnect event with unspecified reason
    pub fn outbound_peer_disconnected(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::Disconnected);
    }

    pub fn remove_outbound_address(&mut self, address: &SocketAddress) {
        self.addresses.remove(address);
    }

    pub fn change_address_state(
        &mut self,
        address: SocketAddress,
        transition: AddressStateTransitionTo,
    ) {
        let now = self.time_getter.get_time();

        // Make sure the address always exists.
        // It's needed because unknown addresses may be reported after RPC connect requests.
        let address_data = self
            .addresses
            .entry(address)
            .or_insert_with(|| AddressData::new(false, false, now));

        let is_persistent_old = address_data.is_persistent();

        log::debug!(
            "update address {} state to {:?}",
            address.to_string(),
            transition,
        );

        address_data.transition_to(transition, now, &mut make_pseudo_rng());

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

    pub fn is_reserved_node(&self, address: &SocketAddress) -> bool {
        self.reserved_nodes.contains(address)
    }

    pub fn add_reserved_node(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::SetReserved);
        self.reserved_nodes.insert(address);
    }

    pub fn remove_reserved_node(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::UnsetReserved);
        self.reserved_nodes.remove(&address);
    }

    /// Checks if the given address is banned
    pub fn is_address_banned(&self, address: &BannableAddress) -> bool {
        self.banned_addresses.contains_key(address)
    }

    pub fn list_banned(&self) -> impl Iterator<Item = &BannableAddress> {
        self.banned_addresses.keys()
    }

    /// Changes the address state to banned
    pub fn ban(&mut self, address: BannableAddress) {
        let ban_till = self.time_getter.get_time() + *self.p2p_config.ban_duration;

        storage::update_db(&self.storage, |tx| {
            tx.add_banned_address(&address.to_string(), ban_till)
        })
        .expect("adding banned address is expected to succeed (ban_peer)");

        self.banned_addresses.insert(address, ban_till);
    }

    pub fn unban(&mut self, address: &BannableAddress) {
        storage::update_db(&self.storage, |tx| {
            tx.del_banned_address(&address.to_string())
        })
        .expect("adding banned address is expected to succeed (ban_peer)");

        self.banned_addresses.remove(address);
    }

    pub fn anchors(&self) -> &BTreeSet<SocketAddress> {
        &self.anchor_addresses
    }

    pub fn set_anchors(&mut self, anchor_addresses: BTreeSet<SocketAddress>) {
        if self.anchor_addresses == anchor_addresses {
            return;
        }
        storage::update_db(&self.storage, |tx| {
            for address in self.anchor_addresses.difference(&anchor_addresses) {
                log::debug!("remove anchor peer {address}");
                tx.del_anchor_address(&address.to_string())?;
            }
            for address in anchor_addresses.difference(&self.anchor_addresses) {
                log::debug!("add anchor peer {address}");
                tx.add_anchor_address(&address.to_string())?;
            }
            Ok(())
        })
        .expect("anchor addresses update is expected to succeed");
        self.anchor_addresses = anchor_addresses;
    }
}

#[cfg(test)]
mod tests;
