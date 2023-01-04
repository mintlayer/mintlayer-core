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
///   (d + d.invert()) + d = d
///
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct DataDelta<T> {
    prev: Option<T>,
    next: Option<T>,
}

impl<T: Clone> DataDelta<T> {
    pub fn new(old: Option<T>, new: Option<T>) -> Self {
        Self {
            prev: old,
            next: new,
        }
    }

    pub fn prev(&self) -> &Option<T> {
        &self.prev
    }

    pub fn next(&self) -> &Option<T> {
        &self.next
    }

    /// Returns an invert delta that has the opposite effect of the provided delta
    /// and serves as an undo object
    fn invert(self) -> DataDeltaUndo<T> {
        DataDeltaUndo(Self::new(self.next, self.prev))
    }
}

/// Elements inside `DeltaDataCollection` can store either a delta or an undo.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DeltaMapElement<T> {
    Delta(DataDelta<T>),
    DeltaUndo(DataDeltaUndo<T>),
}

impl<T> DeltaMapElement<T> {
    pub fn get_data_delta(&self) -> &DataDelta<T> {
        match self {
            DeltaMapElement::Delta(d) => d,
            DeltaMapElement::DeltaUndo(d) => &d.0,
        }
    }

    fn consume(self) -> DataDelta<T> {
        match self {
            DeltaMapElement::Delta(d) => d,
            DeltaMapElement::DeltaUndo(d) => d.0,
        }
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
    data: BTreeMap<K, DeltaMapElement<T>>,
}

impl<K: Ord + Copy, T: Clone + PartialEq> DeltaDataCollection<K, T> {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn data(&self) -> &BTreeMap<K, DeltaMapElement<T>> {
        &self.data
    }

    pub fn get_data(&self, key: &K) -> Result<GetDataResult<&T>, Error> {
        match self.data.get(key) {
            Some(d) => {
                let delta = d.get_data_delta();
                match (&delta.prev, &delta.next) {
                    (None, None) => Ok(GetDataResult::Deleted),
                    (None, Some(d)) => Ok(GetDataResult::Present(d)),
                    (Some(_), None) => Ok(GetDataResult::Deleted),
                    (Some(_), Some(d)) => Ok(GetDataResult::Present(d)),
                }
            }
            None => Ok(GetDataResult::Missing),
        }
    }

    pub fn merge_delta_data(
        &mut self,
        other: Self,
    ) -> Result<DeltaDataUndoCollection<K, T>, Error> {
        let data_undo = other
            .data
            .into_iter()
            .filter_map(|(key, other_pool_data)| {
                match self.merge_delta_data_element_impl(key, other_pool_data) {
                    Ok(delta_op) => delta_op.map(|d| Ok((key, d))),
                    Err(e) => Some(Err(e)),
                }
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(DeltaDataUndoCollection::new(data_undo))
    }

    pub fn merge_delta_data_element(
        &mut self,
        key: K,
        other: DataDelta<T>,
    ) -> Result<Option<DataDeltaUndo<T>>, Error> {
        self.merge_delta_data_element_impl(key, DeltaMapElement::Delta(other))
    }

    fn merge_delta_data_element_impl(
        &mut self,
        key: K,
        other: DeltaMapElement<T>,
    ) -> Result<Option<DataDeltaUndo<T>>, Error> {
        let undo = match &other {
            DeltaMapElement::Delta(other_delta) => Some(other_delta.clone().invert()),
            DeltaMapElement::DeltaUndo(_) => None,
        };

        let el = match self.data.entry(key) {
            Entry::Occupied(e) => {
                DeltaMapElement::Delta(combine_delta_data(e.remove().consume(), other.consume())?)
            }
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
        self.merge_delta_data_element_impl(key, DeltaMapElement::DeltaUndo(undo))
            .map(|_| ())
    }
}

impl<K: Ord + Copy, T: Clone> FromIterator<(K, DeltaMapElement<T>)> for DeltaDataCollection<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, DeltaMapElement<T>)>>(iter: I) -> Self {
        DeltaDataCollection {
            data: BTreeMap::<K, DeltaMapElement<T>>::from_iter(iter),
        }
    }
}

impl<K: Ord + Copy, T: Clone> FromIterator<(K, DataDelta<T>)> for DeltaDataCollection<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, DataDelta<T>)>>(iter: I) -> Self {
        DeltaDataCollection {
            data: BTreeMap::<K, DeltaMapElement<T>>::from_iter(
                iter.into_iter().map(|(k, d)| (k, DeltaMapElement::Delta(d))),
            ),
        }
    }
}

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
fn combine_delta_data<T: Clone + PartialEq>(
    lhs: DataDelta<T>,
    rhs: DataDelta<T>,
) -> Result<DataDelta<T>, Error> {
    utils::ensure!(lhs.next == rhs.prev, Error::DeltaDataMismatch);
    Ok(DataDelta::new(lhs.prev, rhs.next))
}

#[cfg(test)]
mod tests;
