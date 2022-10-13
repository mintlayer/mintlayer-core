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

/// Database index type, just a thin wrapper over usize
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct DbIndex(usize);

impl DbIndex {
    /// New index
    pub const fn new(idx: usize) -> Self {
        DbIndex(idx)
    }

    /// Get the index as usize
    pub const fn get(&self) -> usize {
        self.0
    }
}

/// Description of one key-value store in a database
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct MapDesc {
    /// Key-value map name
    pub name: String,
    /// Value size hint
    pub size_hint: core::ops::Range<usize>,
}

impl MapDesc {
    pub fn new(name: impl Into<String>) -> Self {
        let size_hint = 0..usize::MAX;
        let name = name.into();
        Self { name, size_hint }
    }
}

/// Description of a database, i.e. a collection of key-value maps
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DbDesc(Vec<MapDesc>);

#[allow(clippy::len_without_is_empty)]
impl DbDesc {
    /// Number of databases
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Iterate over map descriptions of this database
    pub fn iter(&self) -> impl '_ + Iterator<Item = &MapDesc> + ExactSizeIterator {
        self.0.iter()
    }
}

impl std::ops::Index<DbIndex> for DbDesc {
    type Output = MapDesc;
    fn index(&self, idx: DbIndex) -> &MapDesc {
        &self.0[idx.0]
    }
}

impl FromIterator<MapDesc> for DbDesc {
    fn from_iter<T: IntoIterator<Item = MapDesc>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}
