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

use std::time::Duration;

use common::primitives::time::Time;
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use serialization::{encoded::Encoded, DecodeAll, Encode};
use storage::MakeMapRef;

use crate::{
    error::P2pError,
    peer_manager::peerdb_common::{
        storage_impl::{StorageImpl, StorageTxRo, StorageTxRw},
        StorageVersion,
    },
};

use super::{
    salt::Salt,
    storage::{KnownAddressState, PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite},
};

type ValueId = u32;

storage::decl_schema! {
    /// Database schema for peer db storage
    pub Schema {
        /// Storage for individual values
        pub DBValue: Map<ValueId, Vec<u8>>,

        /// Table for known addresses
        pub DBKnownAddresses: Map<String, KnownAddressState>,

        /// Table for banned addresses vs the time when they should be unbanned
        /// (Duration is a timestamp since UNIX Epoch)
        pub DBBannedAddresses: Map<String, Duration>,

        /// Table for discouraged addresses vs the time when the discouragement should expire
        /// (Duration is a timestamp since UNIX Epoch)
        pub DBDiscouragedAddresses: Map<String, Duration>,

        /// Table for anchor peers addresses
        pub DBAnchorAddresses: Map<String, ()>,
    }
}

const VALUE_ID_VERSION: ValueId = 1;
const VALUE_ID_SALT: ValueId = 2;

type PeerDbStoreTxRo<'st, B> = StorageTxRo<'st, B, Schema>;
type PeerDbStoreTxRw<'st, B> = StorageTxRw<'st, B, Schema>;

pub type PeerDbStorageImpl<B> = StorageImpl<B, Schema>;

impl<B: storage::SharedBackend + 'static> PeerDbStorage for PeerDbStorageImpl<B> {}

impl<B: storage::SharedBackend> PeerDbStorageWrite for PeerDbStoreTxRw<'_, B> {
    fn set_version(&mut self, version: StorageVersion) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBValue, _>().put(VALUE_ID_VERSION, version.encode())?)
    }

    fn set_salt(&mut self, salt: Salt) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBValue, _>().put(VALUE_ID_SALT, salt.encode())?)
    }

    fn add_known_address(
        &mut self,
        address: &SocketAddress,
        state: KnownAddressState,
    ) -> crate::Result<()> {
        Ok(self
            .storage()
            .get_mut::<DBKnownAddresses, _>()
            .put(address.to_string(), state)?)
    }

    fn del_known_address(&mut self, address: &SocketAddress) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBKnownAddresses, _>().del(address.to_string())?)
    }

    fn add_banned_address(&mut self, address: &BannableAddress, time: Time) -> crate::Result<()> {
        Ok(self
            .storage()
            .get_mut::<DBBannedAddresses, _>()
            .put(address.to_string(), time.as_duration_since_epoch())?)
    }

    fn del_banned_address(&mut self, address: &BannableAddress) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBBannedAddresses, _>().del(address.to_string())?)
    }

    fn add_discouraged_address(
        &mut self,
        address: &BannableAddress,
        time: Time,
    ) -> crate::Result<()> {
        Ok(self
            .storage()
            .get_mut::<DBDiscouragedAddresses, _>()
            .put(address.to_string(), time.as_duration_since_epoch())?)
    }

    fn del_discouraged_address(&mut self, address: &BannableAddress) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBDiscouragedAddresses, _>().del(address.to_string())?)
    }

    fn add_anchor_address(&mut self, address: &SocketAddress) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBAnchorAddresses, _>().put(address.to_string(), ())?)
    }

    fn del_anchor_address(&mut self, address: &SocketAddress) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBAnchorAddresses, _>().del(address.to_string())?)
    }
}

impl<B: storage::SharedBackend> PeerDbStorageRead for PeerDbStoreTxRo<'_, B> {
    fn get_version(&self) -> crate::Result<Option<StorageVersion>> {
        let map = self.storage().get::<DBValue, _>();
        let vec_opt = map.get(VALUE_ID_VERSION)?.as_ref().map(Encoded::decode);
        vec_opt
            .map(|vec| {
                StorageVersion::decode_all(&mut vec.as_ref()).map_err(|err| {
                    P2pError::InvalidStorageState(format!(
                        "Error decoding version from {vec:?}: {err}"
                    ))
                })
            })
            .transpose()
    }

    fn get_salt(&self) -> crate::Result<Option<Salt>> {
        let map = self.storage().get::<DBValue, _>();
        let vec_opt = map.get(VALUE_ID_SALT)?.as_ref().map(Encoded::decode);
        vec_opt
            .map(|vec| {
                Salt::decode_all(&mut vec.as_ref()).map_err(|err| {
                    P2pError::InvalidStorageState(format!(
                        "Error decoding addr tables' salt from {vec:?}: {err}"
                    ))
                })
            })
            .transpose()
    }

    fn get_known_addresses(&self) -> crate::Result<Vec<(SocketAddress, KnownAddressState)>> {
        let map = self.storage().get::<DBKnownAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?.map(|(addr_str, state)| {
            let addr = addr_str.parse::<SocketAddress>().map_err(|err| {
                P2pError::InvalidStorageState(format!(
                    "Error parsing address from {addr_str:?}: {err}"
                ))
            })?;
            crate::Result::Ok((addr, state))
        });
        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }

    fn get_banned_addresses(&self) -> crate::Result<Vec<(BannableAddress, Time)>> {
        let map = self.storage().get::<DBBannedAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?.map(|(addr_str, dur)| {
            let addr = addr_str.parse::<BannableAddress>().map_err(|err| {
                P2pError::InvalidStorageState(format!(
                    "Error parsing address from {addr_str:?}: {err}"
                ))
            })?;
            Ok((addr, Time::from_duration_since_epoch(dur)))
        });
        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }

    fn get_discouraged_addresses(&self) -> crate::Result<Vec<(BannableAddress, Time)>> {
        let map = self.storage().get::<DBDiscouragedAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?.map(|(addr_str, dur)| {
            let addr = addr_str.parse::<BannableAddress>().map_err(|err| {
                P2pError::InvalidStorageState(format!(
                    "Error parsing address from {addr_str:?}: {err}"
                ))
            })?;
            Ok((addr, Time::from_duration_since_epoch(dur)))
        });
        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }

    fn get_anchor_addresses(&self) -> crate::Result<Vec<SocketAddress>> {
        let map = self.storage().get::<DBAnchorAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?.map(|(addr_str, _)| {
            addr_str.parse::<SocketAddress>().map_err(|err| {
                P2pError::InvalidStorageState(format!(
                    "Error parsing address from {addr_str:?}: {err}"
                ))
            })
        });
        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }
}
