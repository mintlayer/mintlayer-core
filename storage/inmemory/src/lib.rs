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

use storage_core::{adaptor, backend, util::MapPrefixIter, Data, DbDesc, DbMapId, DbMapsData};

use std::{borrow::Cow, collections::BTreeMap};

type Map = BTreeMap<Data, Data>;

pub struct StorageMaps(DbMapsData<Map>);

impl backend::ReadOps for StorageMaps {
    fn get(&self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<Option<Cow<'_, [u8]>>> {
        Ok(self.0[map_id].get(key).map(|p| p.into()))
    }

    fn prefix_iter(
        &self,
        map_id: DbMapId,
        prefix: Data,
    ) -> storage_core::Result<impl Iterator<Item = (Data, Data)> + '_> {
        Ok(MapPrefixIter::new(&self.0[map_id], prefix).map(|(k, v)| (k.clone(), v.clone())))
    }

    fn greater_equal_iter(
        &self,
        map_id: DbMapId,
        key: Data,
    ) -> storage_core::Result<impl Iterator<Item = (Data, Data)> + '_> {
        Ok(self.0[map_id].range(key..).map(|(k, v)| (k.clone(), v.clone())))
    }
}

impl backend::WriteOps for StorageMaps {
    fn put(&mut self, map_id: DbMapId, key: Data, val: Data) -> storage_core::Result<()> {
        let _ = self.0[map_id].insert(key, val);
        Ok(())
    }

    fn del(&mut self, map_id: DbMapId, key: &[u8]) -> storage_core::Result<()> {
        let _ = self.0[map_id].remove(key);
        Ok(())
    }
}

impl adaptor::Construct for StorageMaps {
    type From = ();

    fn construct(_: (), desc: DbDesc) -> storage_core::Result<Self> {
        Ok(Self(desc.db_maps().transform(|_| Map::new())))
    }
}

#[derive(Clone)]
pub struct InMemory(adaptor::Locking<StorageMaps>);

impl backend::Backend for InMemory {
    type Impl = <adaptor::Locking<StorageMaps> as backend::Backend>::Impl;

    fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
        self.0.open(desc)
    }
}

impl InMemory {
    /// Create a new in-memory storage backend
    pub fn new() -> Self {
        Self(adaptor::Locking::new(()))
    }
}

impl Default for InMemory {
    fn default() -> Self {
        Self::new()
    }
}
