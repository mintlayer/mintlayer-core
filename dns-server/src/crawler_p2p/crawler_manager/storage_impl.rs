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

use crate::error::DnsServerError;

use super::storage::{AddressInfo, DnsServerStorage, DnsServerStorageRead, DnsServerStorageWrite};
use common::primitives::time::Time;
use p2p::{
    peer_manager::peerdb_common::{
        storage_impl::{StorageImpl, StorageTxRo, StorageTxRw},
        StorageVersion,
    },
    types::{bannable_address::BannableAddress, socket_address::SocketAddress},
};
use serialization::{encoded::Encoded, DecodeAll, Encode};
use storage::MakeMapRef;

type ValueId = u32;

storage::decl_schema! {
    /// Database schema for peer db storage
    pub Schema {
        /// Storage for individual values
        pub DBValue: Map<ValueId, Vec<u8>>,

        /// Table for all reachable addresses
        pub DBAddresses: Map<String, AddressInfo>,

        /// Table for banned addresses
        pub DBBannedAddresses: Map<String, Duration>,
    }
}

const VALUE_ID_VERSION: ValueId = 1;

type DnsServerStoreTxRo<'st, B> = StorageTxRo<'st, B, Schema>;
type DnsServerStoreTxRw<'st, B> = StorageTxRw<'st, B, Schema>;

pub type DnsServerStorageImpl<B> = StorageImpl<B, Schema>;

impl<B: storage::SharedBackend + 'static> DnsServerStorage for DnsServerStorageImpl<B> {}

impl<B: storage::SharedBackend> DnsServerStorageWrite for DnsServerStoreTxRw<'_, B> {
    fn set_version(&mut self, version: StorageVersion) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBValue, _>().put(VALUE_ID_VERSION, version.encode())?)
    }

    fn add_address(&mut self, address: &SocketAddress, info: &AddressInfo) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBAddresses, _>().put(address.to_string(), info)?)
    }

    fn del_address(&mut self, address: &SocketAddress) -> crate::Result<()> {
        Ok(self.storage().get_mut::<DBAddresses, _>().del(address.to_string())?)
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
}

impl<B: storage::SharedBackend> DnsServerStorageRead for DnsServerStoreTxRo<'_, B> {
    fn get_version(&self) -> crate::Result<Option<StorageVersion>> {
        let map = self.storage().get::<DBValue, _>();
        let vec_opt = map.get(VALUE_ID_VERSION)?.as_ref().map(Encoded::decode);
        vec_opt
            .map(|vec| {
                StorageVersion::decode_all(&mut vec.as_ref()).map_err(|err| {
                    DnsServerError::InvalidStorageState(format!(
                        "Error decoding version from {vec:?}: {err}"
                    ))
                })
            })
            .transpose()
    }

    fn get_addresses(&self) -> crate::Result<Vec<(SocketAddress, AddressInfo)>> {
        let map = self.storage().get::<DBAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?.map(|(addr_str, info)| {
            let addr = addr_str.parse::<SocketAddress>().map_err(|err| {
                DnsServerError::InvalidStorageState(format!(
                    "Error parsing address from {addr_str:?}: {err}"
                ))
            })?;
            crate::Result::Ok((addr, info))
        });
        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }

    fn get_banned_addresses(&self) -> crate::Result<Vec<(BannableAddress, Time)>> {
        let map = self.storage().get::<DBBannedAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?.map(|(addr_str, dur)| {
            let addr = addr_str.parse::<BannableAddress>().map_err(|err| {
                DnsServerError::InvalidStorageState(format!(
                    "Error parsing address from {addr_str:?}: {err}"
                ))
            })?;
            Ok((addr, Time::from_duration_since_epoch(dur)))
        });
        itertools::process_results(iter, |iter| iter.collect::<Vec<_>>())
    }
}
