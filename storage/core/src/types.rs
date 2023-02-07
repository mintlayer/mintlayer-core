// Copyright (c) 2022-2023 RBB S.r.l
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

//! Database backend support building blocks

use core::ops::Range;

/// Used to identify particular key-value map in the database
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct DbMapId(usize);

impl DbMapId {
    /// New index
    pub const fn new(id: usize) -> Self {
        DbMapId(id)
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

/// Associate data of type `T` with each DB map
///
/// This is used to associate certain data with each DB map. The data can be metadata containing
/// names and other information about the maps, like [DbMapDesc]. It can also be used by the
/// backend to store for example handles to open key-value maps.
///
/// The interface of this type is deliberately constrained to make it hard to use inappropriately.
/// It can be constructed in two ways:
/// 1. The [Self::new] method takes in the number of DB maps. The map count is in a type wrapper to
///    make it harder to use arbitrary number there.
/// 2. The [Self::transform] method is used to derive one piece of data from another. It preserves
///    the data count and ensures the DB map IDs remain consistent between the original and the
///    derived [DbMapsData] instance.
/// 3. The data can only be accessed by a [DbMapId] so it's only indexed into using a valid DB
///    map identifier.
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DbMapsData<T>(Vec<T>);

impl<T> DbMapsData<T> {
    /// New maps data for given number of key-value maps and initialization function
    pub fn new(map_count: DbMapCount, constructor: impl FnMut(DbMapId) -> T) -> Self {
        Self(map_count.indices().map(constructor).collect())
    }

    /// Get the number of maps
    pub fn db_map_count(&self) -> DbMapCount {
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
    pub fn into_iter_with_id(self) -> impl Iterator<Item = (DbMapId, T)> + ExactSizeIterator {
        self.0.into_iter().enumerate().map(|(i, m)| (DbMapId::new(i), m))
    }
}

impl<T> std::ops::Index<DbMapId> for DbMapsData<T> {
    type Output = T;
    fn index(&self, map_id: DbMapId) -> &Self::Output {
        &self.0[map_id.0]
    }
}

impl<T> std::ops::IndexMut<DbMapId> for DbMapsData<T> {
    fn index_mut(&mut self, map_id: DbMapId) -> &mut Self::Output {
        &mut self.0[map_id.0]
    }
}

/// Description of one key-value store in a database
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DbMapDesc {
    /// Key-value map name
    name: String,
    /// Value size hint
    value_size_hint: Range<usize>,
}

impl DbMapDesc {
    /// New DB map description
    pub fn new(name: impl Into<String>) -> Self {
        Self::new_with_details(name.into(), 0..usize::MAX)
    }

    /// New DB map description with all details
    pub fn new_with_details(name: String, value_size_hint: Range<usize>) -> Self {
        Self {
            name,
            value_size_hint,
        }
    }

    /// Get DB map name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get value size hint
    pub fn value_size_hint(&self) -> &Range<usize> {
        &self.value_size_hint
    }
}

/// Metadata about the whole database
pub struct DbDesc {
    map_descs: DbMapsData<DbMapDesc>,
}

impl DbDesc {
    /// Get descriptions of individual key-value maps
    pub fn db_maps(&self) -> &DbMapsData<DbMapDesc> {
        &self.map_descs
    }

    /// Number of maps in the database
    pub fn db_map_count(&self) -> DbMapCount {
        self.map_descs.db_map_count()
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
            maps.db_map_count().as_usize(),
            "Duplicate map names found"
        );
    }
}
