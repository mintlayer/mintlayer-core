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
pub struct StoreTxRw<'st, B: storage::Backend> {
    // The underlying storage transaction
    db_tx: storage::TransactionRw<'st, B, Schema>,

    // Track if an error was encountered during the execution of the transaction. If so, it will be
    // recorded here and returned by all subsequent operations up to and including the final
    // `.commit()` or `.abort()`.
    error: crate::Result<()>,
}

impl<'st, B: storage::Backend> StoreTxRo<'st, B> {
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
        let error = Ok(());
        Self { db_tx, error }
    }

    fn check_error(&self) -> crate::Result<()> {
        self.error.clone()
    }

    fn track_error<R>(
        &mut self,
        func: impl FnOnce(&mut Self) -> crate::Result<R>,
    ) -> crate::Result<R> {
        self.check_error()?;
        let result = func(self);
        self.error = result.as_ref().map(|_| ()).map_err(Clone::clone);
        result
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

        self.check_error()?;
        let map = self.db_tx.get::<DbMap, I>();
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
        let map = self.db_tx.get::<DbMap, I>();
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

        self.track_error(|this| Ok(this.db_tx.get_mut::<DbMap, I>().put(key, value)?))
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
        self.track_error(|this| Ok(this.db_tx.get_mut::<DbMap, I>().del(key)?))
    }
}

impl<'st, B: storage::Backend> crate::TransactionRo for StoreTxRo<'st, B> {
    fn close(self) {
        self.0.close()
    }
}

impl<'st, B: storage::Backend> crate::TransactionRw for StoreTxRw<'st, B> {
    fn commit(self) -> crate::Result<()> {
        self.check_error()?;
        self.db_tx.commit().map_err(Into::into)
    }

    fn abort(self) -> crate::Result<()> {
        self.check_error()?;
        self.db_tx.abort();
        Ok(())
    }
}
