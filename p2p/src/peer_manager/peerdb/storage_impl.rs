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

use super::storage::{
    PeerDbStorage, PeerDbStorageRead, PeerDbStorageWrite, PeerDbTransactionRo, PeerDbTransactionRw,
    PeerDbTransactional,
};
use serialization::{encoded::Encoded, DecodeAll, Encode};

type ValueId = u32;

storage::decl_schema! {
    /// Database schema for peer db storage
    pub Schema {
        /// Storage for individual values
        pub DBValue: Map<ValueId, Vec<u8>>,

        /// Table for known addresses
        pub DBKnownAddresses: Map<String, ()>,

        /// Table for banned addresses
        pub DBBannedAddresses: Map<String, Duration>,
    }
}

const VALUE_ID_VERSION: ValueId = 1;

pub struct PeerDbStoreTxRo<'st, B: storage::Backend>(storage::TransactionRo<'st, B, Schema>);

pub struct PeerDbStoreTxRw<'st, B: storage::Backend>(storage::TransactionRw<'st, B, Schema>);

impl<'tx, B: storage::Backend + 'tx> PeerDbTransactional<'tx> for PeerDbStorageImpl<B> {
    type TransactionRo = PeerDbStoreTxRo<'tx, B>;
    type TransactionRw = PeerDbStoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> Result<Self::TransactionRo, storage::Error> {
        self.0.transaction_ro().map(PeerDbStoreTxRo)
    }

    fn transaction_rw<'st: 'tx>(&'st self) -> Result<Self::TransactionRw, storage::Error> {
        self.0.transaction_rw(None).map(PeerDbStoreTxRw)
    }
}

impl<B: storage::Backend + 'static> PeerDbStorage for PeerDbStorageImpl<B> {}

pub struct PeerDbStorageImpl<T: storage::Backend>(storage::Storage<T, Schema>);

impl<B: storage::Backend> PeerDbStorageImpl<B> {
    pub fn new(storage: B) -> crate::Result<Self> {
        let store = storage::Storage::<_, Schema>::new(storage)?;
        Ok(Self(store))
    }
}

impl<'st, B: storage::Backend> PeerDbStorageWrite for PeerDbStoreTxRw<'st, B> {
    fn set_version(&mut self, version: u32) -> Result<(), storage::Error> {
        self.0.get_mut::<DBValue, _>().put(VALUE_ID_VERSION, version.encode())
    }

    fn add_known_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.0.get_mut::<DBKnownAddresses, _>().put(address, ())
    }

    fn del_known_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.0.get_mut::<DBKnownAddresses, _>().del(address)
    }

    fn add_banned_address(
        &mut self,
        address: &str,
        duration: Duration,
    ) -> Result<(), storage::Error> {
        self.0.get_mut::<DBBannedAddresses, _>().put(address, duration)
    }

    fn del_banned_address(&mut self, address: &str) -> Result<(), storage::Error> {
        self.0.get_mut::<DBBannedAddresses, _>().del(address)
    }
}

impl<'st, B: storage::Backend> PeerDbTransactionRw for PeerDbStoreTxRw<'st, B> {
    fn abort(self) {
        self.0.abort()
    }

    fn commit(self) -> Result<(), storage::Error> {
        self.0.commit()
    }
}

impl<'st, B: storage::Backend> PeerDbStorageRead for PeerDbStoreTxRo<'st, B> {
    fn get_version(&self) -> Result<Option<u32>, storage::Error> {
        let map = self.0.get::<DBValue, _>();
        let vec_opt = map.get(VALUE_ID_VERSION)?.as_ref().map(Encoded::decode);
        Ok(vec_opt.map(|vec| {
            u32::decode_all(&mut vec.as_ref()).expect("db values to be encoded correctly")
        }))
    }

    fn get_known_addresses(&self) -> Result<Vec<String>, storage::Error> {
        let map = self.0.get::<DBKnownAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?;
        Ok(iter.map(|(key, _value)| key).collect::<Vec<_>>())
    }

    fn get_banned_addresses(&self) -> Result<Vec<(String, Duration)>, storage::Error> {
        let map = self.0.get::<DBBannedAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?;
        Ok(iter.collect::<Vec<_>>())
    }
}

impl<'st, B: storage::Backend> PeerDbTransactionRo for PeerDbStoreTxRo<'st, B> {
    fn close(self) {
        self.0.close()
    }
}
