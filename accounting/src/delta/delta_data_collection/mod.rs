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

use std::collections::BTreeMap;

use serialization::{Decode, Encode};

use crate::error::Error;

use self::undo::*;

/// The outcome of combining two deltas for a given key upon the map that contains it
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
enum DeltaMapOp<T: Clone> {
    /// Write a specific value (for example, to write a Create or Modify operation)
    Write(T),
    /// Erase the value at the relevant key spot (for example, a modify followed by Erase yields nothing).
    Erase,
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DataDelta<T: Clone> {
    Create(Box<T>),
    Modify(Box<T>),
    Delete(Box<T>),
}

impl<T: Clone> DataDelta<T> {
    pub fn data(&self) -> &Box<T> {
        match self {
            DataDelta::Create(d) => d,
            DataDelta::Modify(d) => d,
            DataDelta::Delete(d) => d,
        }
    }
}

// A collection can store either a delta with data or an undo operation to perform.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DeltaMapElement<T: Clone> {
    Data(DataDelta<T>),
    Operation(DataDeltaUndoOp<T>),
}

impl<T: Clone> DeltaMapElement<T> {
    pub fn delta_data(&self) -> &DataDelta<T> {
        match self {
            DeltaMapElement::Data(d) => d,
            DeltaMapElement::Operation(op) => match &op.0 {
                DataDeltaUndoOpInternal::Write(d) => d,
                DataDeltaUndoOpInternal::Erase(d) => d,
            },
        }
    }
}

#[must_use]
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct DeltaDataCollection<K: Ord, T: Clone> {
    data: BTreeMap<K, DeltaMapElement<T>>,
}

impl<K: Ord + Copy, T: Clone> DeltaDataCollection<K, T> {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn data(&self) -> &BTreeMap<K, DeltaMapElement<T>> {
        &self.data
    }

    //FIXME: is it valid to skip ops?
    pub fn get_data_delta(&self, key: &K) -> Option<&DataDelta<T>> {
        match self.data.get(key) {
            Some(el) => match el {
                DeltaMapElement::Data(d) => Some(d),
                DeltaMapElement::Operation(_) => None,
            },
            None => None,
        }
    }

    pub fn merge_delta_data(
        &mut self,
        delta_to_apply: Self,
    ) -> Result<DeltaDataUndoCollection<K, T>, Error> {
        let data_undo = delta_to_apply
            .data
            .into_iter()
            .map(|(key, other_pool_data)| {
                self.merge_delta_data_element_impl(key, other_pool_data).map(|v| (key, v))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(DeltaDataUndoCollection::new(data_undo))
    }

    pub fn merge_delta_data_element(
        &mut self,
        key: K,
        other_data: DataDelta<T>,
    ) -> Result<DataDeltaUndoOp<T>, Error> {
        self.merge_delta_data_element_impl(key, DeltaMapElement::Data(other_data))
    }

    fn merge_delta_data_element_impl(
        &mut self,
        key: K,
        other_data: DeltaMapElement<T>,
    ) -> Result<DataDeltaUndoOp<T>, Error> {
        let current = self.data.get(&key);

        // create the operation/change that would modify the current delta and do the merge
        let new_data = match current {
            Some(current_data) => combine_delta_elements(current_data, other_data)?,
            None => match other_data {
                DeltaMapElement::Data(d) => DeltaMapOp::Write(d),
                DeltaMapElement::Operation(op) => match op.0 {
                    DataDeltaUndoOpInternal::Write(d) => DeltaMapOp::Write(d),
                    DataDeltaUndoOpInternal::Erase(d) => DeltaMapOp::Write(d),
                },
            },
        };

        // apply the change to the current map and create the undo data
        let undo = match new_data {
            // when we insert to a map, undoing is restoring previously state, and erasing if it was empty
            DeltaMapOp::Write(v) => match self.data.insert(key, DeltaMapElement::Data(v.clone())) {
                Some(prev_value) => match prev_value {
                    DeltaMapElement::Data(d) => DataDeltaUndoOp::new_write(d),
                    DeltaMapElement::Operation(_) => {
                        return Err(Error::UndoOpsCombinedNotSupported)
                    }
                },
                None => DataDeltaUndoOp::new_erase(create_inverse_delta(&v)),
            },
            // when we remove from a map, undoing is rewriting what we removed
            DeltaMapOp::Erase => match self.data.remove(&key) {
                Some(el) => match el {
                    DeltaMapElement::Data(d) => DataDeltaUndoOp::new_write(d),
                    DeltaMapElement::Operation(_) => {
                        return Err(Error::UndoOpsCombinedNotSupported)
                    }
                },
                None => return Err(Error::RemoveNonexistingData),
            },
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
        undo_op: DataDeltaUndoOp<T>,
    ) -> Result<(), Error> {
        match undo_op.0 {
            DataDeltaUndoOpInternal::Write(d) => {
                self.data.insert(key, DeltaMapElement::Data(d));
            }
            DataDeltaUndoOpInternal::Erase(_) => {
                if self.data.remove(&key).is_none() {
                    // It's OK to undo delta that is not present.
                    // Store it and later it can be later applied on another collection.
                    self.data.insert(key, DeltaMapElement::Operation(undo_op));
                }
            }
        };
        Ok(())
    }
}

impl<K: Ord + Copy, T: Clone> FromIterator<(K, DataDelta<T>)> for DeltaDataCollection<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, DataDelta<T>)>>(iter: I) -> Self {
        DeltaDataCollection {
            data: BTreeMap::<K, DeltaMapElement<T>>::from_iter(
                iter.into_iter().map(|(k, d)| (k, DeltaMapElement::Data(d))),
            ),
        }
    }
}

fn create_inverse_delta<T: Clone>(applied_delta: &DataDelta<T>) -> DataDelta<T> {
    match applied_delta {
        DataDelta::Create(d) => DataDelta::Delete(d.clone()),
        DataDelta::Modify(d) => DataDelta::Modify(d.clone()),
        DataDelta::Delete(d) => DataDelta::Create(d.clone()),
    }
}

fn combine_delta_elements<T: Clone>(
    lhs: &DeltaMapElement<T>,
    rhs: DeltaMapElement<T>,
) -> Result<DeltaMapOp<DataDelta<T>>, Error> {
    match (lhs, rhs) {
        (DeltaMapElement::Data(d1), DeltaMapElement::Data(d2)) => combine_delta_data(d1, d2),
        (DeltaMapElement::Data(d), DeltaMapElement::Operation(op)) => match (d, op.0) {
            (DataDelta::Create(_), DataDeltaUndoOpInternal::Write(_)) => todo!(),
            (DataDelta::Create(_), DataDeltaUndoOpInternal::Erase(_)) => Ok(DeltaMapOp::Erase),
            (DataDelta::Modify(_), DataDeltaUndoOpInternal::Write(_)) => todo!(),
            (DataDelta::Modify(_), DataDeltaUndoOpInternal::Erase(_)) => Ok(DeltaMapOp::Erase),
            (DataDelta::Delete(_), DataDeltaUndoOpInternal::Write(_)) => todo!(),
            (DataDelta::Delete(_), DataDeltaUndoOpInternal::Erase(_)) => Ok(DeltaMapOp::Erase),
        },
        (DeltaMapElement::Operation(_), DeltaMapElement::Data(_)) => {
            Err(Error::DataCombinedOverUndoOpNotSupported)
        }
        (DeltaMapElement::Operation(_), DeltaMapElement::Operation(_)) => {
            Err(Error::UndoOpsCombinedNotSupported)
        }
    }
}

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
fn combine_delta_data<T: Clone>(
    lhs: &DataDelta<T>,
    rhs: DataDelta<T>,
) -> Result<DeltaMapOp<DataDelta<T>>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Create(_), DataDelta::Modify(d)) => Ok(DeltaMapOp::Write(DataDelta::Create(d))),
        (DataDelta::Create(_), DataDelta::Delete(_)) => {
            // if lhs had a creation, and we delete, this means nothing is left and there's a net zero to return
            Ok(DeltaMapOp::Erase)
        }
        (DataDelta::Modify(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Modify(_), DataDelta::Modify(d)) => Ok(DeltaMapOp::Write(DataDelta::Modify(d))),
        (DataDelta::Modify(_), DataDelta::Delete(_)) => {
            // if lhs had a modification, and we delete, this means nothing is left and there's a net zero to return
            Ok(DeltaMapOp::Erase)
        }
        (DataDelta::Delete(_), DataDelta::Create(d)) => Ok(DeltaMapOp::Write(DataDelta::Create(d))),
        (DataDelta::Delete(_), DataDelta::Modify(_)) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete(_), DataDelta::Delete(_)) => Err(Error::DeltaDataDeletedMultipleTimes),
    }
}

#[cfg(test)]
mod tests;
