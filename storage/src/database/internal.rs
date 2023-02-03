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

//! Internal database implementation utils

use std::borrow::Cow;

use crate::schema;
use serialization::{encoded::Encoded, EncodeLike};
use storage_core::{
    backend::{self, PrefixIter, ReadOps},
    Backend, MapIndex,
};

/// Map high-level transaction type to the backend-specific implementation type
pub trait TxImpl {
    /// The implementation type
    type Impl;
}

impl<'tx, B: Backend, Sch> TxImpl for super::TransactionRo<'tx, B, Sch> {
    type Impl = <B::Impl as backend::TransactionalRo<'tx>>::TxRo;
}

impl<'tx, B: Backend, Sch> TxImpl for super::TransactionRw<'tx, B, Sch> {
    type Impl = <B::Impl as backend::TransactionalRw<'tx>>::TxRw;
}

/// Get a value from the database backend as a SCALE-encoded object
#[allow(clippy::type_complexity)]
pub fn get<DbMap: schema::DbMap, Tx: ReadOps, K: EncodeLike<DbMap::Key>>(
    dbtx: &Tx,
    idx: MapIndex,
    key: K,
) -> crate::Result<Option<Encoded<Cow<[u8]>, DbMap::Value>>> {
    key.using_encoded(|key| dbtx.get(idx, key).map(|x| x.map(Encoded::from_bytes_unchecked)))
}

/// Iterator over DB map entries
pub trait EntryIterator<DbMap: schema::DbMap>:
    Iterator<Item = (DbMap::Key, Encoded<Vec<u8>, DbMap::Value>)>
{
}

impl<DbMap: schema::DbMap, I: Iterator<Item = (DbMap::Key, Encoded<Vec<u8>, DbMap::Value>)>>
    EntryIterator<DbMap> for I
{
}

pub fn prefix_iter<'tx, DbMap: schema::DbMap, Tx: PrefixIter<'tx>>(
    dbtx: &'tx Tx,
    idx: MapIndex,
    prefix: Vec<u8>,
) -> crate::Result<impl 'tx + EntryIterator<DbMap>> {
    dbtx.prefix_iter(idx, prefix).map(|iter| {
        iter.map(|(k, v)| {
            (
                Encoded::from_bytes_unchecked(k).decode(),
                Encoded::from_bytes_unchecked(v),
            )
        })
    })
}
