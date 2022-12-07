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

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DataDelta<T: Clone> {
    // Stores new value
    Create(Box<T>),
    // Stores prev and new values
    Modify((Box<T>, Box<T>)),
    // Stores value to restore
    Delete(Box<T>),
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DataDeltaUndo<T: Clone> {
    // Stores new value
    Create(Box<T>),
    // Stores prev and new values
    Modify((Box<T>, Box<T>)),
    // Stores value to restore
    Delete(Box<T>),
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DeltaMapElement<T: Clone> {
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

    pub fn get_data_delta(&self, key: &K) -> GetDataResult<&T> {
        match self.data.get(key) {
            Some(d) => match d {
                DeltaMapElement::Delta(d) => match d {
                    DataDelta::Create(d) => GetDataResult::Present(d),
                    DataDelta::Modify((_, d)) => GetDataResult::Present(d),
                    DataDelta::Delete(_) => GetDataResult::Deleted,
                },
                DeltaMapElement::DeltaUndo(d) => match d {
                    DataDeltaUndo::Create(d) => GetDataResult::Present(d),
                    DataDeltaUndo::Modify((_, d)) => GetDataResult::Present(d),
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
        let current_element = self.data.get(&key);

        let undo = match &other {
            DeltaMapElement::Delta(other_delta) => {
                let current_delta = match current_element {
                    Some(d) => match d {
                        DeltaMapElement::Delta(d) => Some(d),
                        DeltaMapElement::DeltaUndo(_) => None,
                    },
                    None => None,
                };
                let undo = create_undo_delta(current_delta, other_delta.clone())?;
                Some(undo)
            }
            DeltaMapElement::DeltaUndo(_) => None,
        };

        let new_element = match current_element {
            Some(current) => combine_delta_elements(current, other)?,
            None => other,
        };

        self.data.insert(key, new_element);

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

/// Returns a delta that if applied to the result of combine(delta1,delta2) has the same effect as original delta1.
/// "Has the same effect as" and not "is identical to" because of Modify/Delete case: undo for merge(Modify,Delete) is Create,
/// which when applied to original Modify(a,b) will change it to Create(b), which has the same effect on the data.
fn create_undo_delta<T: Clone>(
    lhs: Option<&DataDelta<T>>,
    rhs: DataDelta<T>,
) -> Result<DataDeltaUndo<T>, Error> {
    match lhs {
        Some(lhs) => match (lhs, rhs) {
            (DataDelta::Create(_), DataDelta::Create(_)) => {
                Err(Error::DeltaDataCreatedMultipleTimes)
            }
            (DataDelta::Create(d1), DataDelta::Modify((_, d2))) => {
                Ok(DataDeltaUndo::Modify((d2, d1.clone())))
            }
            (DataDelta::Create(_), DataDelta::Delete(d)) => Ok(DataDeltaUndo::Create(d)),

            (DataDelta::Modify(_), DataDelta::Create(_)) => {
                Err(Error::DeltaDataCreatedMultipleTimes)
            }
            (DataDelta::Modify((_, prev)), DataDelta::Modify((_, new))) => {
                Ok(DataDeltaUndo::Modify((new, prev.clone())))
            }
            (DataDelta::Modify((_, _)), DataDelta::Delete(d)) => Ok(DataDeltaUndo::Create(d)),

            (DataDelta::Delete(_), DataDelta::Create(d)) => Ok(DataDeltaUndo::Delete(d)),
            (DataDelta::Delete(_), DataDelta::Modify(_)) => Err(Error::DeltaDataModifyAfterDelete),
            (DataDelta::Delete(_), DataDelta::Delete(_)) => {
                Err(Error::DeltaDataDeletedMultipleTimes)
            }
        },
        None => match rhs {
            DataDelta::Create(d) => Ok(DataDeltaUndo::Delete(d)),
            DataDelta::Modify((prev, new)) => Ok(DataDeltaUndo::Modify((new, prev))),
            DataDelta::Delete(d) => Ok(DataDeltaUndo::Create(d)),
        },
    }
}

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
fn combine_deltas<T: Clone>(lhs: &DataDelta<T>, rhs: DataDelta<T>) -> Result<DataDelta<T>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Create(_), DataDelta::Modify((_, d))) => Ok(DataDelta::Create(d)),
        (DataDelta::Create(_), DataDelta::Delete(d)) => {
            // if lhs had a creation, and we delete, this means nothing is left and there's a net zero to return
            Ok(DataDelta::Delete(d))
        }
        (DataDelta::Modify(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Modify((d1, _)), DataDelta::Modify((_, d2))) => {
            Ok(DataDelta::Modify((d1.clone(), d2)))
        }
        (DataDelta::Modify(_), DataDelta::Delete(d)) => {
            // if lhs had a modification, and we delete, this means nothing is left and there's a net zero to return
            Ok(DataDelta::Delete(d))
        }
        (DataDelta::Delete(_), DataDelta::Create(d)) => Ok(DataDelta::Create(d)),
        (DataDelta::Delete(_), DataDelta::Modify(_)) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete(_), DataDelta::Delete(_)) => Err(Error::DeltaDataDeletedMultipleTimes),
    }
}

/// Given a delta with undo delta, combine them into undo delta.
/// This operation is contagious as returned result becomes `DataDeltaUndo`
/// The rules are different than for `combine_deltas`.
fn combine_delta_with_undo<T: Clone>(
    lhs: &DataDelta<T>,
    rhs: DataDeltaUndo<T>,
) -> Result<DataDeltaUndo<T>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDeltaUndo::Create(d)) => {
            // Undo(Create) is a result of reverting Delta(Delete) so it's ok to combine it with Delta(Create)
            Ok(DataDeltaUndo::Create(d))
        }
        (DataDelta::Create(_), DataDeltaUndo::Modify((_, d))) => Ok(DataDeltaUndo::Create(d)),
        (DataDelta::Create(_), DataDeltaUndo::Delete(d)) => Ok(DataDeltaUndo::Delete(d)),

        (DataDelta::Modify((d1, _)), DataDeltaUndo::Create(d2)) => {
            // Undo(Create) is a result of reverting Delta(Delete) so it's ok to combine it with Delta(Modify)
            Ok(DataDeltaUndo::Modify((d1.clone(), d2)))
        }
        (DataDelta::Modify((prev, _)), DataDeltaUndo::Modify((_, new))) => {
            Ok(DataDeltaUndo::Modify((prev.clone(), new)))
        }
        (DataDelta::Modify(_), DataDeltaUndo::Delete(d)) => Ok(DataDeltaUndo::Delete(d)),

        (DataDelta::Delete(_), DataDeltaUndo::Create(d)) => Ok(DataDeltaUndo::Create(d)),
        (DataDelta::Delete(_), DataDeltaUndo::Modify(_)) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete(_), DataDeltaUndo::Delete(d)) => {
            // Undo(Delete) is a result of reverting Create so it's ok to combine it with DataDelta::Delete
            Ok(DataDeltaUndo::Delete(d))
        }
    }
}

fn combine_undos<T: Clone>(
    lhs: &DataDeltaUndo<T>,
    rhs: DataDeltaUndo<T>,
) -> Result<DataDeltaUndo<T>, Error> {
    match (lhs, rhs) {
        (DataDeltaUndo::Create(_), DataDeltaUndo::Create(_)) => {
            // Delta(Delete) + Delta(Delete) is forbidden thus its undo is forbidden as well
            Err(Error::DeltaDataDeletedMultipleTimes)
        }
        (DataDeltaUndo::Create(_), DataDeltaUndo::Modify((_, d))) => Ok(DataDeltaUndo::Create(d)),
        (DataDeltaUndo::Create(_), DataDeltaUndo::Delete(d)) => Ok(DataDeltaUndo::Delete(d)),

        (DataDeltaUndo::Modify((d1, _)), DataDeltaUndo::Create(d2)) => {
            Ok(DataDeltaUndo::Modify((d1.clone(), d2)))
        }
        (DataDeltaUndo::Modify((prev, _)), DataDeltaUndo::Modify((_, new))) => {
            Ok(DataDeltaUndo::Modify((prev.clone(), new)))
        }
        (DataDeltaUndo::Modify(_), DataDeltaUndo::Delete(d)) => Ok(DataDeltaUndo::Delete(d)),

        (DataDeltaUndo::Delete(_), DataDeltaUndo::Create(d)) => Ok(DataDeltaUndo::Create(d)),
        (DataDeltaUndo::Delete(_), DataDeltaUndo::Modify(_)) => {
            Err(Error::DeltaDataModifyAfterDelete)
        }
        (DataDeltaUndo::Delete(_), DataDeltaUndo::Delete(_)) => {
            // Delta(Create) + Delta(Create) is forbidden thus its undo is forbidden as well
            Err(Error::DeltaDataCreatedMultipleTimes)
        }
    }
}

fn combine_delta_elements<T: Clone>(
    lhs: &DeltaMapElement<T>,
    rhs: DeltaMapElement<T>,
) -> Result<DeltaMapElement<T>, Error> {
    match (lhs, rhs) {
        (DeltaMapElement::Delta(d1), DeltaMapElement::Delta(d2)) => {
            combine_deltas(d1, d2).map(|d| DeltaMapElement::Delta(d))
        }
        (DeltaMapElement::Delta(d), DeltaMapElement::DeltaUndo(u)) => {
            combine_delta_with_undo(d, u).map(|d| DeltaMapElement::DeltaUndo(d))
        }
        (DeltaMapElement::DeltaUndo(_), DeltaMapElement::Delta(_)) => {
            Err(Error::DeltaOverUndoApplied)
        }
        (DeltaMapElement::DeltaUndo(u1), DeltaMapElement::DeltaUndo(u2)) => {
            combine_undos(u1, u2).map(|d| DeltaMapElement::DeltaUndo(d))
        }
    }
}

#[cfg(test)]
mod tests;
