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

storage::decl_schema! {
    /// Database schema for peer db storage
    pub Schema {
        /// Table for known addresses
        pub DBKnownAddresses: Map<String, ()>,

        /// Table for banned addresses
        pub DBBannedAddresses: Map<String, Duration>,
    }
}

pub struct PeerDbStoreTxRo<'st, B: storage::Backend>(storage::TransactionRo<'st, B, Schema>);

pub struct PeerDbStoreTxRw<'st, B: storage::Backend>(storage::TransactionRw<'st, B, Schema>);

impl<'tx, B: storage::Backend + 'tx> PeerDbTransactional<'tx> for PeerDbStorageImpl<B> {
    type TransactionRo = PeerDbStoreTxRo<'tx, B>;
    type TransactionRw = PeerDbStoreTxRw<'tx, B>;

    fn transaction_ro<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRo> {
        self.0.transaction_ro().map_err(crate::P2pError::from).map(PeerDbStoreTxRo)
    }

    fn transaction_rw<'st: 'tx>(&'st self) -> crate::Result<Self::TransactionRw> {
        self.0.transaction_rw(None).map_err(crate::P2pError::from).map(PeerDbStoreTxRw)
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
    fn add_known_address(&mut self, address: &str) -> crate::Result<()> {
        self.0.get_mut::<DBKnownAddresses, _>().put(address, ()).map_err(Into::into)
    }

    fn del_known_address(&mut self, address: &str) -> crate::Result<()> {
        self.0.get_mut::<DBKnownAddresses, _>().del(address).map_err(Into::into)
    }

    fn add_banned_address(&mut self, address: &str, duration: Duration) -> crate::Result<()> {
        self.0
            .get_mut::<DBBannedAddresses, _>()
            .put(address, duration)
            .map_err(Into::into)
    }

    fn del_banned_address(&mut self, address: &str) -> crate::Result<()> {
        self.0.get_mut::<DBBannedAddresses, _>().del(address).map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> PeerDbTransactionRw for PeerDbStoreTxRw<'st, B> {
    fn abort(self) {
        self.0.abort()
    }

    fn commit(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }
}

impl<'st, B: storage::Backend> PeerDbStorageRead for PeerDbStoreTxRo<'st, B> {
    fn get_known_addresses(&self) -> crate::Result<Vec<String>> {
        let map = self.0.get::<DBKnownAddresses, _>();
        let iter = map.prefix_iter_decoded(&())?;
        Ok(iter.map(|(key, _value)| key).collect::<Vec<_>>())
    }

    fn get_banned_addresses(&self) -> crate::Result<Vec<(String, Duration)>> {
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
