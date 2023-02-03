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

//! Low-level runtime database layout description

/// Used to identify particular key-value map in the database
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct DbMapId(usize);

impl DbMapId {
    /// New index
    pub const fn new(idx: usize) -> Self {
        DbMapId(idx)
    }

    /// Get the index as usize
    pub const fn as_usize(&self) -> usize {
        self.0
    }
}

/// Number of key-value maps in the database
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct DbMapCount(usize);

impl DbMapCount {
    /// Convert to `usize`
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Iterator over all database indices
    pub fn indices(self) -> impl Iterator<Item = DbMapId> + ExactSizeIterator {
        (0..self.0).map(DbMapId::new)
    }
}

/// Associate data of type `T` with each database map
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DbMapsData<T>(Vec<T>);

impl<T> DbMapsData<T> {
    /// New maps data for given number of key-value maps
    pub fn new(map_count: DbMapCount, constructor: impl FnMut(DbMapId) -> T) -> Self {
        Self(map_count.indices().map(constructor).collect())
    }

    /// Get the number of maps
    pub fn map_count(&self) -> DbMapCount {
        DbMapCount(self.0.len())
    }

    /// Apply given function to each map and collect the results
    pub fn transform<U>(&self, func: impl FnMut(&T) -> U) -> DbMapsData<U> {
        DbMapsData(self.0.iter().map(func).collect::<Vec<_>>())
    }

    /// Like [Self::transform] but fallible
    pub fn try_transform<U, E>(
        &self,
        func: impl FnMut(&T) -> Result<U, E>,
    ) -> Result<DbMapsData<U>, E> {
        self.0.iter().map(func).collect::<Result<Vec<_>, _>>().map(DbMapsData)
    }

    /// Convert into iterator over map indices together with associated data
    pub fn into_idx_iter(self) -> impl Iterator<Item = (DbMapId, T)> + ExactSizeIterator {
        self.0.into_iter().enumerate().map(|(i, m)| (DbMapId::new(i), m))
    }
}

impl<T> std::ops::Index<DbMapId> for DbMapsData<T> {
    type Output = T;
    fn index(&self, idx: DbMapId) -> &Self::Output {
        &self.0[idx.0]
    }
}

impl<T> std::ops::IndexMut<DbMapId> for DbMapsData<T> {
    fn index_mut(&mut self, idx: DbMapId) -> &mut Self::Output {
        &mut self.0[idx.0]
    }
}

/// Description of one key-value store in a database
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DbMapDesc {
    /// Key-value map name
    pub name: String,
    /// Value size hint
    pub size_hint: core::ops::Range<usize>,
}

impl DbMapDesc {
    /// New map description
    pub fn new(name: impl Into<String>) -> Self {
        let size_hint = 0..usize::MAX;
        let name = name.into();
        Self { name, size_hint }
    }
}

/// Metadata about the whole database
pub struct DbDesc {
    map_descs: DbMapsData<DbMapDesc>,
}

impl DbDesc {
    /// Get descriptions of individual key-value maps
    pub fn maps(&self) -> &DbMapsData<DbMapDesc> {
        &self.map_descs
    }

    /// Number of maps in the database
    pub fn map_count(&self) -> DbMapCount {
        self.map_descs.map_count()
    }
}

/// Internal constructors.
///
/// Only to be used by storage framework and testing. Not for use by backend implementations.
pub mod construct {
    use super::{DbDesc, DbMapDesc, DbMapsData};

    /// Construct database description.
    pub fn db_desc(iter: impl Iterator<Item = DbMapDesc>) -> DbDesc {
        let map_descs = DbMapsData(iter.collect());
        assert_names_unique(&map_descs);
        DbDesc { map_descs }
    }

    fn assert_names_unique(maps: &DbMapsData<DbMapDesc>) {
        let set: std::collections::BTreeSet<_> = maps.0.iter().map(|desc| &desc.name).collect();
        assert_eq!(
            set.len(),
            maps.map_count().as_usize(),
            "Duplicate map names found"
        );
    }
}
