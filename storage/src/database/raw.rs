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

//! Raw database representation for contents inspection purposes

use crate::{
    schema::{self, HasDbMap, Schema},
    Backend, Storage,
};
use std::collections::BTreeMap;
use storage_core::backend::PrefixIter;

pub use storage_core::Data;

/// Database index, parametrized by schema
///
/// This is basically a type-safe version of [storage_core::MapIndex].
pub struct MapIndex<Sch> {
    idx: storage_core::MapIndex,
    _phantom: std::marker::PhantomData<fn() -> Sch>,
}

impl<Sch> MapIndex<Sch> {
    fn from_idx_unchecked(idx: storage_core::MapIndex) -> Self {
        let _phantom = Default::default();
        Self { idx, _phantom }
    }

    fn from_usize_unchecked(idx: usize) -> Self {
        Self::from_idx_unchecked(storage_core::MapIndex::new(idx))
    }

    /// Get index as usize
    pub fn as_usize(&self) -> usize {
        self.idx.get()
    }
}

impl<Sch: Schema> MapIndex<Sch> {
    /// New database index from the database identifier
    pub fn new<M: schema::DbMap, I>() -> Self
    where
        Sch: HasDbMap<M, I>,
    {
        Self::from_idx_unchecked(<Sch as HasDbMap<M, I>>::INDEX)
    }

    /// Database index from a numeric index
    pub fn from_usize(idx: usize) -> Option<Self> {
        utils::ensure!(idx < Sch::desc_iter().count());
        Some(Self::from_usize_unchecked(idx))
    }

    /// Database index from key-value map name
    pub fn from_name<S: AsRef<str>>(name: S) -> Option<Self> {
        Sch::desc_iter()
            .position(|desc| desc.name == name.as_ref())
            .map(Self::from_usize_unchecked)
    }

    /// Get index info
    pub fn info(&self) -> storage_core::info::MapDesc {
        Sch::desc_iter()
            .nth(self.idx.get())
            .expect("index to be in range due to schema")
    }

    /// Get map name at this index
    pub fn name(&self) -> String {
        self.info().name
    }
}

impl<Sch> Ord for MapIndex<Sch> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.idx.cmp(&other.idx)
    }
}

impl<Sch> PartialOrd for MapIndex<Sch> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.idx.partial_cmp(&other.idx)
    }
}

impl<Sch> PartialEq for MapIndex<Sch> {
    fn eq(&self, other: &Self) -> bool {
        self.idx.eq(&other.idx)
    }
}

impl<Sch> Eq for MapIndex<Sch> {}

impl<Sch> Clone for MapIndex<Sch> {
    fn clone(&self) -> Self {
        Self::from_idx_unchecked(self.idx)
    }
}

impl<Sch> Copy for MapIndex<Sch> {}

impl<Sch> std::fmt::Debug for MapIndex<Sch> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.idx.fmt(f)
    }
}

/// Low-level representation of single key-value store
pub type MapContents = BTreeMap<Data, Data>;

/// Low-level representation of the whole storage
pub type StorageContents<Sch> = BTreeMap<MapIndex<Sch>, MapContents>;

/// Get raw database by dumping database data
pub fn dump_storage<B: Backend, Sch: Schema>(
    storage: &Storage<B, Sch>,
) -> crate::Result<StorageContents<Sch>> {
    let dbtx = storage.transaction_ro()?;
    Sch::desc_iter()
        .enumerate()
        .map(|(idx, _dbinfo)| {
            let idx = storage_core::MapIndex::new(idx);
            let items = dbtx.dbtx.prefix_iter(idx, Vec::new())?;
            Ok((MapIndex::from_idx_unchecked(idx), items.collect()))
        })
        .collect::<crate::Result<StorageContents<Sch>>>()
}

#[cfg(test)]
mod test {
    use super::*;
    use storage_inmemory::InMemory;

    crate::decl_schema! {
        TestSchema {
            Db0: Map<u32, u32>,
            Db1: Map<u16, Vec<u8>>,
        }
    }

    #[test]
    fn indices() {
        type TestMapIndex = MapIndex<TestSchema>;
        let idx0: TestMapIndex = MapIndex::from_usize_unchecked(0);
        let idx1: TestMapIndex = MapIndex::from_usize_unchecked(1);

        assert_eq!(TestMapIndex::new::<Db0, _>(), idx0);
        assert_eq!(TestMapIndex::new::<Db1, _>(), idx1);

        assert_eq!(TestMapIndex::from_usize(0), Some(idx0));
        assert_eq!(TestMapIndex::from_usize(1), Some(idx1));
        assert_eq!(TestMapIndex::from_usize(2), None);

        assert_eq!(TestMapIndex::from_name("Db0"), Some(idx0));
        assert_eq!(TestMapIndex::from_name("Db1"), Some(idx1));
        assert_eq!(TestMapIndex::from_name("DbX"), None);
    }

    #[test]
    fn basic_dump() {
        utils::concurrency::model(|| {
            let storage = Storage::<_, TestSchema>::new(InMemory::new()).unwrap();
            let db1 = MapIndex::new::<Db0, _>();
            let db2 = MapIndex::new::<Db1, _>();

            {
                // Check the DB dump is empty initially
                let raw_db = storage.dump_raw().unwrap();
                assert_eq!(raw_db.len(), 2);
                assert!(raw_db.iter().all(|x| x.1.is_empty()));
            }

            // Add some values, check the dump contents
            let mut dbtx = storage.transaction_rw(None).unwrap();
            dbtx.get_mut::<Db0, _>().put(42, 1337).unwrap();
            dbtx.get_mut::<Db1, _>().put(21, vec![1, 2, 3, 4]).unwrap();
            dbtx.commit().unwrap();

            {
                let raw_db = storage.dump_raw().unwrap();
                assert_eq!(raw_db[&db1].len(), 1);
                assert_eq!(raw_db[&db1][[42, 0, 0, 0].as_ref()], vec![57, 5, 0, 0]);
                assert_eq!(raw_db[&db2].len(), 1);
                assert_eq!(raw_db[&db2][[21, 0].as_ref()], vec![4 << 2, 1, 2, 3, 4]);
            }

            // More modifications, check contents
            let mut dbtx = storage.transaction_rw(None).unwrap();
            dbtx.get_mut::<Db0, _>().del(42).unwrap();
            dbtx.get_mut::<Db1, _>().put(22, vec![1, 2]).unwrap();
            dbtx.commit().unwrap();

            {
                let raw_db = storage.dump_raw().unwrap();
                assert_eq!(raw_db[&db1].len(), 0);
                assert_eq!(raw_db[&db2].len(), 2);
                assert_eq!(raw_db[&db2][[21, 0].as_ref()], vec![4 << 2, 1, 2, 3, 4]);
                assert_eq!(raw_db[&db2][[22, 0].as_ref()], vec![2 << 2, 1, 2]);
            }
        })
    }
}
