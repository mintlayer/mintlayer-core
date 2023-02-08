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

use crate::{
    error::Error,
    storage::{PoSAccountingStorageRead, PoSAccountingStorageWrite},
    StorageTag,
};
use chainstate_types::storage_result;

pub struct BorrowedStorageValue<'a, T, S, Getter, Setter, Deleter> {
    store: &'a mut S,
    getter: Getter,
    setter: Setter,
    deleter: Deleter,

    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T, S, Getter, Setter, Deleter> BorrowedStorageValue<'a, T, S, Getter, Setter, Deleter> {
    pub fn new(store: &'a mut S, getter: Getter, setter: Setter, deleter: Deleter) -> Self {
        Self {
            store,
            getter,
            setter,
            deleter,
            _phantom: Default::default(),
        }
    }
}

impl<'a, T: StorageTag, S: PoSAccountingStorageRead<T>, Getter, Setter, Deleter>
    BorrowedStorageValue<'a, T, S, Getter, Setter, Deleter>
{
    pub fn get<K: Ord + Copy, V: Clone>(&self, id: K) -> Result<Option<V>, Error>
    where
        Getter: Fn(&S, K) -> Result<Option<V>, storage_result::Error>,
    {
        (self.getter)(self.store, id).map_err(Error::StorageError)
    }
}

impl<'a, T: StorageTag, S: PoSAccountingStorageWrite<T>, Getter, Setter, Deleter>
    BorrowedStorageValue<'a, T, S, Getter, Setter, Deleter>
{
    pub fn set<K: Ord + Copy, V: Clone>(&mut self, id: K, value: V) -> Result<(), Error>
    where
        Setter: FnMut(&mut S, K, V) -> Result<(), storage_result::Error>,
    {
        (self.setter)(self.store, id, value).map_err(Error::StorageError)
    }

    pub fn delete<K: Ord + Copy>(&mut self, id: K) -> Result<(), Error>
    where
        Deleter: FnMut(&mut S, K) -> Result<(), storage_result::Error>,
    {
        (self.deleter)(self.store, id).map_err(Error::StorageError)
    }
}
