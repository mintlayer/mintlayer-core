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

use crate::peer_manager::peerdb_common::storage_impl::{StorageImpl, StorageTxRo, StorageTxRw};

use super::storage::{PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite};
use common::primitives::time::Time;
use serialization::{encoded::Encoded, DecodeAll, Encode};

type ValueId = u32;

storage::decl_schema! {
    /// Database schema for peer db storage
    pub Schema {
        /// Storage for individual values
        pub DBValue: Map<ValueId, Vec<u8>>,

        /// Table for known addresses
        pub DBKnownAddresses: Map<String, ()>,

        /// Table for banned addresses vs when they can be unbanned (Duration is timestamp since UNIX Epoch)
        pub DBBannedAddresses: Map<String, Duration>,

        /// Table for anchor peers addresses
        pub DBAnchorAddresses: Map<String, ()>,
    }
}

const VALUE_ID_VERSION: ValueId = 1;

type PeerDbStoreTxRo<'st, B> = StorageTxRo<'st, B, Schema>;
type PeerDbStoreTxRw<'st, B> = StorageTxRw<'st, B, Schema>;

pub type PeerDbStorageImpl<B> = StorageImpl<B, Schema>;

impl<B: storage::Backend + 'static> PeerDbStorage for PeerDbStorageImpl<B> {}

impl<'st, B: storage::Backend> PeerDbStorageWrite for PeerDbStoreTxRw<'st, B> {
    fn set_version(&mut self, version: u32) -> Result<(), storage::Error> {
        self.storage().get_mut::<DBValue, _>().put(VALUE_ID_VERSION, version.encode())
    }

    fn add_known_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.storage().get_mut::<DBKnownAddresses, _>().put(address, ())
    }

    fn del_known_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.storage().get_mut::<DBKnownAddresses, _>().del(address)
    }

    fn add_banned_address(&mut self, address: &str, time: Time) -> Result<(), storage::Error> {
        self.storage()
            .get_mut::<DBBannedAddresses, _>()
            .put(address, time.as_duration_since_epoch())
    }

    fn del_banned_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.storage().get_mut::<DBBannedAddresses, _>().del(address)
    }

    fn add_anchor_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.storage().get_mut::<DBAnchorAddresses, _>().put(address, ())
    }

    fn del_anchor_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.storage().get_mut::<DBAnchorAddresses, _>().del(address)
    }
}

impl<'st, B: storage::Backend> PeerDbStorageRead for PeerDbStoreTxRo<'st, B> {
    fn get_version(&self) -> Result<Option<u32>, storage::Error> {
        let map = self.storage().get::<DBValue, _>();
        let vec_opt = map.get(VALUE_ID_VERSION)?.as_ref().map(Encoded::decode);
        Ok(vec_opt.map(|vec| {
            u32::decode_all(&mut vec.as_ref()).expect("db values to be encoded correctly")
        }))
    }

    fn get_known_addresses(&self) -> Result<Vec<String>, storage::Error> {
        let map = self.storage().get::<DBKnownAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?;
        Ok(iter.map(|(key, _value)| key).collect::<Vec<_>>())
    }

    fn get_banned_addresses(&self) -> Result<Vec<(String, Time)>, storage::Error> {
        let map = self.storage().get::<DBBannedAddresses, _>();
        let iter = map
            .prefix_iter_decoded(&())?
            .map(|(addr, dur)| (addr, Time::from_duration_since_epoch(dur)));
        Ok(iter.collect::<Vec<_>>())
    }

    fn get_anchor_addresses(&self) -> Result<Vec<String>, storage::Error> {
        let map = self.storage().get::<DBAnchorAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?;
        Ok(iter.map(|(key, _value)| key).collect::<Vec<_>>())
    }
}
