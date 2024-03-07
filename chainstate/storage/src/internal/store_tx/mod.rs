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
pub struct StoreTxRw<'st, B: storage::Backend>(pub(super) storage::TransactionRw<'st, B, Schema>);

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
    // Encode a value and write it to the database
    fn write<DbMap, I, K, V>(&mut self, key: K, value: V) -> crate::Result<()>
    where
        DbMap: schema::DbMap,
        Schema: schema::HasDbMap<DbMap, I>,
        K: EncodeLike<<DbMap as schema::DbMap>::Key>,
        V: EncodeLike<<DbMap as schema::DbMap>::Value>,
    {
        self.0.get_mut::<DbMap, I>().put(key, value).map_err(Into::into)
    }

    // Write a value for a well-known entry
    fn write_value<E: well_known::Entry>(&mut self, val: &E::Value) -> crate::Result<()> {
        self.write::<db::DBValue, _, _, _>(E::KEY, val.encode())
    }
}

impl<'st, B: storage::Backend> crate::TransactionRo for StoreTxRo<'st, B> {
    fn close(self) {
        self.0.close()
    }
}

impl<'st, B: storage::Backend> crate::TransactionRw for StoreTxRw<'st, B> {
    fn commit(self) -> crate::Result<()> {
        self.0.commit().map_err(Into::into)
    }

    fn abort(self) {
        self.0.abort()
    }
}
