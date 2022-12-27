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

use std::collections::BTreeMap;

use serialization::{Decode, Encode};

use crate::error::Error;

mod combine;
use self::combine::*;

/// The outcome of combining two deltas for a given key upon the map that contains it
enum DeltaMapOp<T> {
    /// Insert a specific value (for example, to write a Create or Modify operation)
    Insert(DeltaMapElement<T>),
    /// Erase the value at the relevant key spot (for example, a Create followed by Delete yields nothing)
    Erase,
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DataDelta<T> {
    // Stores new value
    Create(T),
    // Stores prev and new values
    Modify(T, T),
    // Stores value to restore
    Delete(T),
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DataDeltaUndo<T> {
    // Stores new value
    Create(T),
    // Stores prev and new values
    Modify(T, T),
    // Stores value to restore
    Delete(T),
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DeltaMapElement<T> {
    Delta(DataDelta<T>),
    DeltaUndo(DataDeltaUndo<T>),
}

pub enum GetDataResult<T> {
    Present(T),
    Deleted,
    Missing,
}

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

    pub fn get_data(&self, key: &K) -> GetDataResult<&T> {
        match self.data.get(key) {
            Some(d) => match d {
                DeltaMapElement::Delta(d) => match d {
                    DataDelta::Create(d) => GetDataResult::Present(d),
                    DataDelta::Modify(_, d) => GetDataResult::Present(d),
                    DataDelta::Delete(_) => GetDataResult::Deleted,
                },
                DeltaMapElement::DeltaUndo(d) => match d {
                    DataDeltaUndo::Create(d) => GetDataResult::Present(d),
                    DataDeltaUndo::Modify(_, d) => GetDataResult::Present(d),
                    DataDeltaUndo::Delete(_) => GetDataResult::Deleted,
                },
            },
            None => GetDataResult::Missing,
        }
    }

    pub fn merge_delta_data(
        &mut self,
        delta_to_apply: Self,
    ) -> Result<DeltaDataUndoCollection<K, T>, Error> {
        let data_undo = delta_to_apply
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
        other_data: DataDelta<T>,
    ) -> Result<Option<DataDeltaUndo<T>>, Error> {
        self.merge_delta_data_element_impl(key, DeltaMapElement::Delta(other_data))
    }

    fn merge_delta_data_element_impl(
        &mut self,
        key: K,
        other: DeltaMapElement<T>,
    ) -> Result<Option<DataDeltaUndo<T>>, Error> {
        let undo = match &other {
            DeltaMapElement::Delta(other_delta) => Some(create_undo_delta(other_delta.clone())),
            DeltaMapElement::DeltaUndo(_) => None,
        };

        let op = match self.data.get(&key) {
            Some(current) => combine_delta_elements(current, other)?,
            None => DeltaMapOp::Insert(other),
        };

        match op {
            DeltaMapOp::Insert(el) => self.data.insert(key, el),
            DeltaMapOp::Erase => self.data.remove(&key),
        };

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

/// Returns an undo delta that has the opposite result of the provided delta
fn create_undo_delta<T: Clone>(delta: DataDelta<T>) -> DataDeltaUndo<T> {
    match delta {
        DataDelta::Create(d) => DataDeltaUndo::Delete(d),
        DataDelta::Modify(prev, new) => DataDeltaUndo::Modify(new, prev),
        DataDelta::Delete(d) => DataDeltaUndo::Create(d),
    }
}

fn combine_delta_elements<T: Clone + PartialEq>(
    lhs: &DeltaMapElement<T>,
    rhs: DeltaMapElement<T>,
) -> Result<DeltaMapOp<T>, Error> {
    match (lhs, rhs) {
        (DeltaMapElement::Delta(d1), DeltaMapElement::Delta(d2)) => match combine_deltas(d1, d2)? {
            Some(d) => Ok(DeltaMapOp::Insert(DeltaMapElement::Delta(d))),
            None => Ok(DeltaMapOp::Erase),
        },
        (DeltaMapElement::Delta(d), DeltaMapElement::DeltaUndo(u)) => {
            match combine_delta_with_undo(d, u)? {
                Some(d) => Ok(DeltaMapOp::Insert(DeltaMapElement::Delta(d))),
                None => Ok(DeltaMapOp::Erase),
            }
        }
        (DeltaMapElement::DeltaUndo(_), DeltaMapElement::Delta(_)) => {
            Err(Error::DeltaOverUndoApplied)
        }
        (DeltaMapElement::DeltaUndo(u1), DeltaMapElement::DeltaUndo(u2)) => {
            match combine_undos(u1, u2)? {
                Some(d) => Ok(DeltaMapOp::Insert(DeltaMapElement::DeltaUndo(d))),
                None => Ok(DeltaMapOp::Erase),
            }
        }
    }
}

#[cfg(test)]
mod tests;
