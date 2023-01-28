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

pub mod storage;
pub mod storage_impl;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use common::time_getter::TimeGetter;
use crypto::random::{make_pseudo_rng, SliceRandom};

use crate::{
    config,
    error::{ConversionError, P2pError},
    net::{AsBannableAddress, NetworkingService},
};

use self::storage::{
    PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite, PeerDbTransactionRo, PeerDbTransactionRw,
};

pub struct PeerDb<T: NetworkingService, S> {
    /// P2P configuration
    p2p_config: Arc<config::P2pConfig>,

    /// Set of currently connected addresses
    connected_addresses: BTreeSet<T::Address>,

    /// Set of all known addresses
    known_addresses: BTreeSet<T::Address>,

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
        let added_nodes = p2p_config
            .added_nodes
            .iter()
            .map(|addr| {
                addr.parse::<T::Address>().map_err(|_err| {
                    P2pError::ConversionError(ConversionError::InvalidAddress(addr.clone()))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Node won't start if DB loading fails!
        let tx = storage.transaction_ro()?;
        let stored_known_addresses = tx.get_known_addresses()?;
        let stored_banned_addresses = tx.get_banned_addresses()?;
        tx.close();

        let stored_known_addresses_iter =
            stored_known_addresses.iter().filter_map(|address| address.parse().ok());
        // TODO: We need to handle added nodes differently from ordinary nodes.
        // There are peers that we want to persistently have, and others that we want to just give a "shot" at connecting at.
        let known_addresses = stored_known_addresses_iter.chain(added_nodes.into_iter()).collect();

        let banned_addresses = stored_banned_addresses
            .iter()
            .filter_map(|(address, duration)| {
                address.parse().ok().map(|address| (address, *duration))
            })
            .collect();

        Ok(Self {
            connected_addresses: Default::default(),
            known_addresses,
            banned_addresses,
            p2p_config,
            time_getter,
            storage,
        })
    }

    /// Get the number of idle (available) addresses
    pub fn available_addresses_count(&self) -> usize {
        self.known_addresses.len()
    }

    /// Checks if the given address is already connected.
    pub fn is_address_connected(&self, address: &T::Address) -> bool {
        self.connected_addresses.contains(address)
    }

    /// Selects requested count of peer addresses from the DB randomly.
    ///
    /// Result could be shared with remote peers over network.
    pub fn random_known_addresses(&self, count: usize) -> Vec<T::Address> {
        // TODO: Use something more efficient (without iterating over the all addresses first)
        let all_addresses = self.known_addresses.iter().cloned().collect::<Vec<_>>();
        all_addresses
            .choose_multiple(&mut make_pseudo_rng(), count)
            .cloned()
            .collect::<Vec<_>>()
    }

    /// Checks if the given address is banned.
    pub fn is_address_banned(&mut self, address: &T::BannableAddress) -> crate::Result<bool> {
        if let Some(banned_till) = self.banned_addresses.get(address) {
            // Check if the ban has expired.
            let now = self.time_getter.get_time();
            if now > *banned_till {
                self.banned_addresses.remove(address);
                let mut tx = self.storage.transaction_rw()?;
                tx.del_banned_address(&address.to_string())?;
                tx.commit()?;
            } else {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get socket address of the next best peer (TODO: in terms of peer score).
    // TODO: Rewrite this.
    pub fn get_best_peer_addr(&mut self) -> Option<T::Address> {
        self.random_known_addresses(1).into_iter().next()
    }

    /// Add new peer addresses
    pub fn peer_discovered(&mut self, address: &T::Address) -> crate::Result<()> {
        self.known_addresses.insert(address.clone());

        let mut tx = self.storage.transaction_rw()?;
        tx.add_known_address(&address.to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Report outbound connection failure
    ///
    /// When [`crate::peer_manager::PeerManager::heartbeat()`] has initiated an outbound connection
    /// and the connection is refused, it's reported back to the `PeerDb` so it marks the address as unreachable.
    pub fn report_outbound_failure(&mut self, _address: T::Address) {
        // TODO: implement
    }

    /// Mark peer as connected
    ///
    /// After `PeerManager` has established either an inbound or an outbound connection,
    /// it informs the `PeerDb` about it.
    pub fn peer_connected(&mut self, address: T::Address) {
        let old_value = self.connected_addresses.insert(address);
        assert!(old_value);
    }

    /// Handle peer disconnection event
    ///
    /// Close the connection to an active peer.
    pub fn peer_disconnected(&mut self, address: T::Address) {
        let removed = self.connected_addresses.remove(&address);
        assert!(removed);
    }

    /// Changes the peer state to `Peer::Banned` and bans it for 24 hours.
    pub fn ban_peer(&mut self, address: &T::Address) -> crate::Result<()> {
        let bannable_address = address.as_bannable();
        let ban_till = self.time_getter.get_time() + *self.p2p_config.ban_duration;
        let mut tx = self.storage.transaction_rw()?;
        tx.add_banned_address(&bannable_address.to_string(), ban_till)?;
        tx.commit()?;
        self.banned_addresses.insert(bannable_address, ban_till);
        Ok(())
    }

    #[cfg(feature = "testing_utils")]
    pub fn get_storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }
}
