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

mod read_impls;
mod write_impls;

use common::primitives::{BlockHeight, Id};
use serialization::{Codec, DecodeAll, Encode, EncodeLike};
use storage::{schema, MakeMapRef};

use crate::{
    schema::{self as db, Schema},
    ChainstateStorageVersion,
};

mod well_known {
    use common::chain::{self, GenBlock};

    use super::{BlockHeight, ChainstateStorageVersion, Codec, Id};

    /// Pre-defined database keys
    pub trait Entry {
        /// Key for this entry
        const KEY: &'static [u8];
        /// Value type for this entry
        type Value: Codec;
    }

    macro_rules! declare_entry {
        ($name:ident: $type:ty) => {
            pub struct $name;
            impl Entry for $name {
                const KEY: &'static [u8] = stringify!($name).as_bytes();
                type Value = $type;
            }
        };
    }

    declare_entry!(StoreVersion: ChainstateStorageVersion);
    declare_entry!(BestBlockId: Id<GenBlock>);
    declare_entry!(UtxosBestBlockId: Id<GenBlock>);
    declare_entry!(MagicBytes: chain::config::MagicBytes);
    declare_entry!(ChainType: String);
    declare_entry!(MinHeightForReorg: BlockHeight);
}

/// Read-only chainstate storage transaction
pub struct StoreTxRo<'st, B: storage::Backend>(pub(super) storage::TransactionRo<'st, B, Schema>);

/// Read-write chainstate storage transaction
///
/// It tracks if an error was encountered during the execution of the transaction. If so, it will
/// be recorded here and returned by all subsequent operations.
pub struct StoreTxRw<'st, B: storage::Backend> {
    db_tx: crate::Result<storage::TransactionRw<'st, B, Schema>>,
}

impl<B: storage::Backend> StoreTxRo<'_, B> {
    // Read a value from the database and decode it
    fn read<DbMap, I, K>(&self, key: K) -> crate::Result<Option<DbMap::Value>>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<DbMap::Key>,
    {
        let map = self.0.get::<DbMap, I>();
        map.get(key).map_err(crate::Error::from).map(|x| x.map(|x| x.decode()))
    }

    // Return true if an entry for the given key exists in the db.
    // This is cheaper than calling `read` and checking for is_some.
    fn entry_exists<DbMap, I, K>(&self, key: K) -> crate::Result<bool>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<DbMap::Key>,
    {
        let map = self.0.get::<DbMap, I>();
        map.get(key).map_err(crate::Error::from).map(|x| x.is_some())
    }

    // Read a value for a well-known entry
    fn read_value<E: well_known::Entry>(&self) -> crate::Result<Option<E::Value>> {
        self.read::<db::DBValue, _, _>(E::KEY).map(|x| {
            x.map(|x| {
                E::Value::decode_all(&mut x.as_ref()).expect("db values to be encoded correctly")
            })
        })
    }
}

impl<'st, B: storage::Backend> StoreTxRw<'st, B> {
    pub(super) fn new(db_tx: storage::TransactionRw<'st, B, Schema>) -> Self {
        let db_tx = Ok(db_tx);
        Self { db_tx }
    }

    fn db_tx_ref(&self) -> crate::Result<&storage::TransactionRw<'st, B, Schema>> {
        self.db_tx.as_ref().map_err(Clone::clone)
    }

    fn db_tx_mut(&mut self) -> crate::Result<&mut storage::TransactionRw<'st, B, Schema>> {
        self.db_tx.as_mut().map_err(|e| e.clone())
    }

    fn track_error<R>(
        &mut self,
        func: impl FnOnce(&mut storage::TransactionRw<'st, B, Schema>) -> crate::Result<R>,
    ) -> crate::Result<R> {
        let result = func(self.db_tx_mut()?);
        if let Err(e) = &result {
            self.db_tx = Err(e.clone());
        }
        result
    }

    // Get a key-value map
    fn get_map<DbMap, I>(
        &self,
    ) -> crate::Result<storage::MapRef<'_, storage::TransactionRw<'st, B, Schema>, DbMap>>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
    {
        Ok(self.db_tx_ref()?.get::<DbMap, I>())
    }

    // Read a value from the database and decode it
    fn read<DbMap, I, K>(&self, key: K) -> crate::Result<Option<DbMap::Value>>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<DbMap::Key>,
    {
        logging::log::trace!(
            "Reading {}/{}",
            DbMap::NAME,
            serialization::hex_encoded::HexEncoded::new(&key),
        );

        let map = self.db_tx_ref()?.get::<DbMap, I>();
        map.get(key).map_err(crate::Error::from).map(|x| x.map(|x| x.decode()))
    }

    // Return true if an entry for the given key exists in the db.
    // This is cheaper than calling `read` and checking for is_some.
    fn entry_exists<DbMap, I, K>(&self, key: K) -> crate::Result<bool>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<DbMap::Key>,
    {
        let map = self.db_tx_ref()?.get::<DbMap, I>();
        map.get(key).map_err(crate::Error::from).map(|x| x.is_some())
    }

    // Read a value for a well-known entry
    fn read_value<E: well_known::Entry>(&self) -> crate::Result<Option<E::Value>> {
        self.read::<db::DBValue, _, _>(E::KEY).map(|x| {
            x.map(|x| {
                E::Value::decode_all(&mut x.as_ref()).expect("db values to be encoded correctly")
            })
        })
    }

    // Encode a value and write it to the database
    fn write<DbMap, I, K, V>(&mut self, key: K, value: V) -> crate::Result<()>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<<DbMap as schema::DbMap>::Key>,
        V: EncodeLike<<DbMap as schema::DbMap>::Value>,
    {
        logging::log::trace!(
            "Writing {}/{}",
            DbMap::NAME,
            serialization::hex_encoded::HexEncoded::new(&key),
        );

        self.track_error(|tx| Ok(tx.get_mut::<DbMap, I>().put(key, value)?))
    }

    // Write a value for a well-known entry
    fn write_value<E: well_known::Entry>(&mut self, val: &E::Value) -> crate::Result<()> {
        self.write::<db::DBValue, _, _, _>(E::KEY, val.encode())
    }

    // Delete a value from the database
    fn del<DbMap, I, K>(&mut self, key: K) -> crate::Result<()>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<<DbMap as schema::DbMap>::Key>,
    {
        self.track_error(|tx| Ok(tx.get_mut::<DbMap, I>().del(key)?))
    }
}

impl<B: storage::Backend> crate::TransactionRo for StoreTxRo<'_, B> {
    fn close(self) {
        self.0.close()
    }
}

impl<B: storage::Backend> crate::TransactionRw for StoreTxRw<'_, B> {
    fn commit(self) -> crate::Result<()> {
        Ok(self.db_tx?.commit()?)
    }

    fn abort(self) {
        self.db_tx.map_or((), |tx| tx.abort())
    }

    fn check_error(&self) -> crate::Result<()> {
        self.db_tx_ref().map(|_| ())
    }
}
