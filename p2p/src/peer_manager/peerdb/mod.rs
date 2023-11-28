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
mod address_tables;
pub mod config;
pub mod storage;
pub mod storage_impl;
mod storage_load;

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    sync::Arc,
};

use common::{chain::ChainConfig, primitives::time::Time, time_getter::TimeGetter};
use crypto::random::{make_pseudo_rng, seq::IteratorRandom, SliceRandom};
use itertools::Itertools;
use logging::log;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};

use crate::config::P2pConfig;

use self::{
    address_data::{AddressData, AddressStateTransitionTo},
    address_tables::AddressTables,
    config::PeerDbConfig,
    storage::{KnownAddressState, PeerDbStorage, PeerDbStorageWrite},
    storage_load::LoadedStorage,
};

use super::{
    address_groups::AddressGroup, ip_or_socket_address_to_peer_address,
    peerdb_common::storage::update_db,
};

pub use storage::StorageVersion;
pub use storage_load::open_storage;

pub struct PeerDb<S> {
    /// P2P configuration
    p2p_config: Arc<P2pConfig>,

    /// Map of all outbound peer addresses
    addresses: BTreeMap<SocketAddress, AddressData>,

    /// Set of addresses that have the `reserved` flag set.
    /// Used as an optimization to not iterate over the entire `addresses` map.
    /// Every listed address must exist in the `addresses` map.
    reserved_nodes: BTreeSet<SocketAddress>,

    /// Tables of "new" and "tried" addresses that control when and how the contents
    /// of the `addresses` map should be purged.
    ///
    /// Note that the number of addresses in the tables may be smaller than in the `addresses` map,
    /// because the latter always contains reserved nodes, while the tables may miss some of them.
    address_tables: AddressTables,

    /// Banned addresses along with the ban expiration time.
    banned_addresses: BTreeMap<BannableAddress, Time>,

    /// Anchor addresses
    anchor_addresses: BTreeSet<SocketAddress>,

    time_getter: TimeGetter,

    storage: S,
}

impl<S: PeerDbStorage> PeerDb<S> {
    pub fn new(
        chain_config: &ChainConfig,
        p2p_config: Arc<P2pConfig>,
        time_getter: TimeGetter,
        storage: S,
    ) -> crate::Result<Self> {
        Self::new_with_config(
            chain_config,
            p2p_config,
            &Default::default(),
            time_getter,
            storage,
        )
    }

    fn new_with_config(
        chain_config: &ChainConfig,
        p2p_config: Arc<P2pConfig>,
        peerdb_config: &PeerDbConfig,
        time_getter: TimeGetter,
        storage: S,
    ) -> crate::Result<Self> {
        // Node won't start if DB loading fails!
        let LoadedStorage {
            known_addresses,
            banned_addresses,
            anchor_addresses,
            addr_tables_random_key,
        } = LoadedStorage::load_storage(&storage, peerdb_config)?;

        let reserved_nodes = p2p_config
            .reserved_nodes
            .iter()
            .map(|addr| ip_or_socket_address_to_peer_address(addr, chain_config))
            .collect::<BTreeSet<_>>();
        let boot_nodes = p2p_config
            .boot_nodes
            .iter()
            .map(|addr| ip_or_socket_address_to_peer_address(addr, chain_config))
            .filter(|addr| !reserved_nodes.contains(addr))
            .collect::<BTreeSet<_>>();

        let now = time_getter.get_time();
        let mut addresses = BTreeMap::new();
        let mut address_tables = AddressTables::new(addr_tables_random_key, peerdb_config);

        for (addr, state) in &known_addresses {
            match *state {
                // Note: discarded_addr below will be `None` normally, but it can be `Some` if
                // address hashing logic has been changed without upping the storage version.
                // Also note that we don't update the db in such a case; this will lead to
                // some inconsistency between the db/known_addresses and the addr tables, but it
                // should resolve by itself eventually.
                KnownAddressState::Tried => {
                    let discarded_addr = address_tables.force_add_to_tried(addr);
                    if let Some(discarded_addr) = discarded_addr {
                        log::warn!("Tried address {discarded_addr} discarded when loading PeerDb");
                    }
                }
                KnownAddressState::New => {
                    let discarded_addr = address_tables.force_add_to_new(addr);
                    if let Some(discarded_addr) = discarded_addr {
                        log::warn!("New address {discarded_addr} discarded when loading PeerDb");
                    }
                }
            }

            let addr_data = AddressData::new(
                *state == KnownAddressState::Tried,
                reserved_nodes.contains(addr),
                now,
            );
            addresses.insert(*addr, addr_data);
        }

        for addr in &boot_nodes {
            if let Entry::Vacant(entry) = addresses.entry(*addr) {
                let discarded_addr = address_tables.force_add_to_new(addr);
                if let Some(discarded_addr) = discarded_addr {
                    log::info!("Previously loaded 'new' address {discarded_addr} replaced with boot address {addr} when loading PeerDb");
                }

                entry.insert(AddressData::new(false, false, now));
            }
        }

        // Note: no need to add reserved addresses to "new", because they are likely to get into
        // "tried" soon anyway (though doing so wouldn't hurt either).
        for addr in &reserved_nodes {
            if let Entry::Vacant(entry) = addresses.entry(*addr) {
                entry.insert(AddressData::new(false, true, now));
            }
        }

        Ok(Self {
            addresses,
            reserved_nodes,
            address_tables,
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

    /// Selects peer addresses for outbound connections, excluding reserved ones.
    /// Only one outbound connection is allowed per address group.
    pub fn select_new_non_reserved_outbound_addresses(
        &self,
        cur_outbound_conn_addr_groups: &BTreeSet<AddressGroup>,
        count: usize,
    ) -> Vec<SocketAddress> {
        if count == 0 {
            return Vec::new();
        }

        let now = self.time_getter.get_time();

        // TODO: select new vs tried addresses with equal probability (or at least with a specific
        // probability that is not directly tied to the sizes of both tables)
        let mut selected = self
            .addresses
            .iter()
            .filter_map(|(addr, address_data)| {
                if address_data.connect_now(now)
                    && !cur_outbound_conn_addr_groups
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
        cur_pending_outbound_conn_addresses: &BTreeSet<SocketAddress>,
    ) -> Vec<SocketAddress> {
        let now = self.time_getter.get_time();
        self.reserved_nodes
            .iter()
            .filter_map(|addr| {
                let address_data = self
                    .addresses
                    .get(addr)
                    .expect("reserved nodes must always be in the addresses map");
                if address_data.connect_now(now)
                    && !cur_pending_outbound_conn_addresses.contains(addr)
                {
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

        self.addresses.retain(|addr, address_data| {
            let retain = address_data.retain(now);

            if !retain {
                self.address_tables.remove(addr);
                update_db(&self.storage, |tx| tx.del_known_address(addr))
                    .expect("DB failure when deleting known address {addr}");
            }

            retain
        });

        self.banned_addresses.retain(|addr, banned_till| {
            let banned = now <= *banned_till;

            if !banned {
                update_db(&self.storage, |tx| tx.del_banned_address(addr))
                    .expect("removing banned address is expected to succeed");
            }

            banned
        });
    }

    /// Add a new peer address
    pub fn peer_discovered(&mut self, address: SocketAddress) {
        if self.addresses.get(&address).is_none() {
            log::debug!("New address discovered: {}", address.to_string());

            debug_assert!(
                !self.address_tables.have_addr(&address),
                "Address {address} is in 'address_tables' but not in 'addresses'"
            );

            if self.add_addr_to_new(&address) {
                self.addresses.insert(
                    address,
                    AddressData::new(false, false, self.time_getter.get_time()),
                );
            }
        }
    }

    /// Report outbound connection failure
    ///
    /// When [`crate::peer_manager::PeerManager::heartbeat()`] has initiated an outbound connection
    /// and the connection is refused, it's reported back to the `PeerDb` so it marks the address as unreachable.
    pub fn report_outbound_failure(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::ConnectionFailed);

        // Note: if the failed connection is a manual one, the address won't be in the addr tables,
        // but the 'change_address_state' call above will insert it into self.addresses.
        // We don't consider this a problem though.
        // The same happens in outbound_peer_disconnected too.
    }

    /// Mark peer as connected
    ///
    /// After `PeerManager` has established either an inbound or an outbound connection,
    /// it informs the `PeerDb` about it.
    pub fn outbound_peer_connected(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::Connected);
        self.move_addr_to_tried(&address);
    }

    /// Handle peer disconnect event with unspecified reason
    pub fn outbound_peer_disconnected(&mut self, address: SocketAddress) {
        self.change_address_state(address, AddressStateTransitionTo::Disconnected);
    }

    pub fn remove_outbound_address(&mut self, address: &SocketAddress) {
        if !self.reserved_nodes.contains(address) {
            self.addresses.remove(address);
        }
        self.address_tables.remove(address);

        update_db(&self.storage, |tx| tx.del_known_address(address))
            .expect("DB failure when removing known address {address}");
    }

    fn move_addr_to_tried(&mut self, address: &SocketAddress) {
        let move_result = self.address_tables.move_to_tried(address);
        let (addr_moved_to_new, discarded_addr) = match move_result {
            None => (None, None),
            Some(address_tables::MoveToTriedSideEffects {
                addr_moved_to_new,
                discarded_new_addr,
            }) => (Some(addr_moved_to_new), discarded_new_addr),
        };

        debug_assert!(discarded_addr != Some(*address));

        update_db(&self.storage, |tx| {
            tx.add_known_address(address, KnownAddressState::Tried)?;

            if let Some(addr_moved_to_new) = addr_moved_to_new {
                tx.add_known_address(&addr_moved_to_new, KnownAddressState::New)?;
            }

            crate::Result::Ok(())
        })
        .expect("DB failure when updating known addresses}");

        self.remove_from_addresses_if_some_non_reserved(discarded_addr);
    }

    fn add_addr_to_new(&mut self, address: &SocketAddress) -> bool {
        let outcome = self.address_tables.move_to_new(address, |existing_addr| {
            Self::can_discard_addr_in_new(&self.addresses, &existing_addr)
        });

        match outcome {
            address_tables::MoveToNewOutcome::Succeeded { prev_addr } => {
                update_db(&self.storage, |tx| {
                    tx.add_known_address(address, KnownAddressState::New)
                })
                .expect("DB failure when updating known address {address}");

                self.remove_from_addresses_if_some_non_reserved(prev_addr);
                true
            }
            address_tables::MoveToNewOutcome::Cancelled => false,
        }
    }

    fn can_discard_addr_in_new(
        cur_addresses: &BTreeMap<SocketAddress, AddressData>,
        address: &SocketAddress,
    ) -> bool {
        if let Some(existing_addr_data) = cur_addresses.get(address) {
            // TODO:
            // 1) also allow removing addresses with next_connect_after too far in
            // the future?
            // 2) also store last_seen_time in AddressData to be able to remove addresses
            // that haven't been advertised in a while?
            // 3) also store last_connect_time in AddressData to avoid removing addresses
            // that we've recently connected to?
            // 4) Allow removing banned addresses?
            existing_addr_data.reserved() || existing_addr_data.is_unreachable()
        } else {
            debug_assert!(
                false,
                "Address {address} is assumed to be in 'address_tables' but it's not in 'addresses'"
            );
            true
        }
    }

    // Note: this function assumes that the address has already been removed from `address_tables`.
    fn remove_from_addresses_if_some_non_reserved(&mut self, address: Option<SocketAddress>) {
        if let Some(address) = address {
            if !self.reserved_nodes.contains(&address) {
                self.addresses.remove(&address);

                update_db(&self.storage, |tx| tx.del_known_address(&address))
                    .expect("DB failure when deleting known address {address}");
            }
        }
    }

    fn change_address_state(
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

        log::debug!(
            "Updating address {} state to {:?}",
            address.to_string(),
            transition,
        );

        address_data.transition_to(transition, now, &mut make_pseudo_rng());
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
        let ban_till = (self.time_getter.get_time() + *self.p2p_config.ban_duration)
            .expect("Ban duration is expected to be valid");

        update_db(&self.storage, |tx| {
            tx.add_banned_address(&address, ban_till)
        })
        .expect("adding banned address is expected to succeed (ban_peer)");

        self.banned_addresses.insert(address, ban_till);
    }

    pub fn unban(&mut self, address: &BannableAddress) {
        update_db(&self.storage, |tx| tx.del_banned_address(address))
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
        update_db(&self.storage, |tx| {
            for address in self.anchor_addresses.difference(&anchor_addresses) {
                log::debug!("remove anchor peer {address}");
                tx.del_anchor_address(address)?;
            }
            for address in anchor_addresses.difference(&self.anchor_addresses) {
                log::debug!("add anchor peer {address}");
                tx.add_anchor_address(address)?;
            }
            crate::Result::Ok(())
        })
        .expect("anchor addresses update is expected to succeed");
        self.anchor_addresses = anchor_addresses;
    }
}

#[cfg(test)]
mod tests;
