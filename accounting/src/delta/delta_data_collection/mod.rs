// Copyright (c) 2021-2022 RBB S.r.l
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

pub mod undo;
use self::undo::*;

use std::collections::{btree_map::Entry, BTreeMap};

use serialization::{Decode, Encode};

use crate::error::Error;

///
/// Basic primitive that represents a difference introduced to a data.
///
/// Following properties are defined for deltas:
/// - Associativity:
///   (d1 + d2) + d3 = d1 + (d2 + d3), where '+' is the combine operation implemented by `combine_delta_data`
///
///   Associativity property doesn't hold if a combine operation produces an error, e.g.:
///   (Delta(Some, None) + Delta(Some, None)) + Delta(None, Some) = Error + Delta(None, Some)
///   Delta(Some, None) + (Delta(Some, None) + Delta(None, Some)) = Delta(Some, None) + Delta(Some, Some) = Error
///
/// - Inversion in the sense that:
///   d + d.invert() + d = d
///
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct DataDelta<T> {
    old: Option<T>,
    new: Option<T>,
}

impl<T: Clone> DataDelta<T> {
    pub fn new(old: Option<T>, new: Option<T>) -> Self {
        Self { old, new }
    }

    /// Returns an invert delta that has the opposite effect of the provided delta
    /// and serves as an undo object
    pub fn invert(self) -> DataDeltaUndo<T> {
        DataDeltaUndo::new(Self::new(self.new, self.old))
    }

    pub fn consume(self) -> (Option<T>, Option<T>) {
        (self.old, self.new)
    }
}

/// `GetDataResult` is represented by 3 states instead of typical 2 states, because it is
/// important to distinguish the case when data was explicitly deleted from the case when the data is just not there.
pub enum GetDataResult<T> {
    Present(T),
    Deleted,
    Missing,
}
/// `DeltaDataCollection` is a container for deltas. It encapsulates all the logic of merging deltas and
/// undoing them.
#[must_use]
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct DeltaDataCollection<K, T> {
    data: BTreeMap<K, DataDelta<T>>,
}

impl<K: Ord + Copy, T: Clone + Eq> DeltaDataCollection<K, T> {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn data(&self) -> &BTreeMap<K, DataDelta<T>> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<K, DataDelta<T>> {
        self.data
    }

    pub fn get_data(&self, key: &K) -> GetDataResult<&T> {
        match self.data.get(key) {
            Some(delta) => match &delta.new {
                None => GetDataResult::Deleted,
                Some(d) => GetDataResult::Present(d),
            },
            None => GetDataResult::Missing,
        }
    }

    pub fn merge_delta_data(
        &mut self,
        other: Self,
    ) -> Result<DeltaDataUndoCollection<K, T>, Error> {
        let data_undo = other
            .data
            .into_iter()
            .map(|(key, other_pool_data)| {
                Ok((key, self.merge_delta_data_element(key, other_pool_data)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(DeltaDataUndoCollection::new(data_undo))
    }

    pub fn merge_delta_data_element(
        &mut self,
        key: K,
        other: DataDelta<T>,
    ) -> Result<DataDeltaUndo<T>, Error> {
        let undo = other.clone().invert();

        let el = match self.data.entry(key) {
            Entry::Occupied(e) => combine_delta_data(e.remove(), other)?,
            Entry::Vacant(_) => other,
        };

        self.data.insert(key, el);

        Ok(undo)
    }

    pub fn undo_merge_delta_data(
        &mut self,
        undo_data: DeltaDataUndoCollection<K, T>,
    ) -> Result<(), Error> {
        undo_data
            .consume()
            .into_iter()
            .try_for_each(|(key, data)| self.undo_merge_delta_data_element(key, data))
    }

    pub fn undo_merge_delta_data_element(
        &mut self,
        key: K,
        undo: DataDeltaUndo<T>,
    ) -> Result<(), Error> {
        self.merge_delta_data_element(key, undo.consume()).map(|_| ())
    }
}

impl<K: Ord + Copy, T: Clone> FromIterator<(K, DataDelta<T>)> for DeltaDataCollection<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, DataDelta<T>)>>(iter: I) -> Self {
        DeltaDataCollection {
            data: BTreeMap::<K, DataDelta<T>>::from_iter(iter.into_iter()),
        }
    }
}

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
fn combine_delta_data<T: Clone + Eq>(
    lhs: DataDelta<T>,
    rhs: DataDelta<T>,
) -> Result<DataDelta<T>, Error> {
    utils::ensure!(lhs.new == rhs.old, Error::DeltaDataMismatch);
    Ok(DataDelta::new(lhs.old, rhs.new))
}

#[cfg(test)]
mod tests;
