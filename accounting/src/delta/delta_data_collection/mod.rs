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
    // stores new value
    Create(Box<T>),
    // stores prev and new values
    Modify((Box<T>, Box<T>)),
    // stores prev value before deletion
    Delete(Box<T>),
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DeltaMapElement<T: Clone> {
    Delta(DataDelta<T>),
    Undo(DataDelta<T>),
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

    pub fn get_data_delta(&self, key: &K) -> Option<&DataDelta<T>> {
        match self.data.get(key) {
            Some(el) => match el {
                DeltaMapElement::Delta(d) => Some(d),
                DeltaMapElement::Undo(_) => None,
            },
            None => None,
        }
    }

    pub fn delta_iter(&self) -> impl Iterator<Item = (&K, &DataDelta<T>)> {
        self.data.iter().map(|(k, el)| match el {
            DeltaMapElement::Delta(d) => (k, d),
            DeltaMapElement::Undo(d) => (k, d),
        })
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
        let current_el = self.data.get(&key);
        let current_delta = match current_el {
            Some(d) => match d {
                DeltaMapElement::Delta(d) => Some(d),
                DeltaMapElement::Undo(_) => None,
            },
            None => None,
        };

        let undo = match &other {
            DeltaMapElement::Delta(other_delta) => {
                let undo = create_undo_delta(current_delta, other_delta.clone())?;
                Some(DataDeltaUndo(undo))
            }
            DeltaMapElement::Undo(_) => None,
        };

        let new_element = match current_el {
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
        undo_op: DataDeltaUndo<T>,
    ) -> Result<(), Error> {
        let new_data = match self.data.get(&key) {
            Some(current_data) => {
                combine_delta_elements(current_data, DeltaMapElement::Undo(undo_op.0))?
            }
            None => DeltaMapElement::Undo(undo_op.0),
        };

        self.data.insert(key, new_data);

        Ok(())
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

/// This function returns a delta that if applied to the result of merge(lhs,rhs) gives original lhs
fn create_undo_delta<T: Clone>(
    lhs: Option<&DataDelta<T>>,
    rhs: DataDelta<T>,
) -> Result<DataDelta<T>, Error> {
    match lhs {
        Some(lhs) => match (lhs, rhs) {
            (DataDelta::Create(d1), DataDelta::Create(d2)) => {
                Ok(DataDelta::Modify((d2, d1.clone())))
            }
            (DataDelta::Create(d1), DataDelta::Modify((_, d2))) => {
                Ok(DataDelta::Modify((d2, d1.clone())))
            }
            (DataDelta::Create(_), DataDelta::Delete(d)) => Ok(DataDelta::Create(d)),

            (DataDelta::Modify((_, d1)), DataDelta::Create(d2)) => {
                Ok(DataDelta::Modify((d2, d1.clone())))
            }
            (DataDelta::Modify((_, prev)), DataDelta::Modify((_, new))) => {
                Ok(DataDelta::Modify((new, prev.clone())))
            }
            (DataDelta::Modify((_, _)), DataDelta::Delete(d)) => Ok(DataDelta::Create(d)),

            (DataDelta::Delete(_), DataDelta::Create(d)) => Ok(DataDelta::Delete(d)),
            (DataDelta::Delete(_), DataDelta::Modify((_, _))) => {
                Err(Error::DeltaDataModifyAfterDelete)
            }
            (DataDelta::Delete(_), DataDelta::Delete(_)) => {
                Err(Error::DeltaDataDeletedMultipleTimes)
            }
        },
        None => match rhs {
            DataDelta::Create(d) => Ok(DataDelta::Delete(d)),
            DataDelta::Modify((prev, new)) => Ok(DataDelta::Modify((new, prev))),
            DataDelta::Delete(d) => Ok(DataDelta::Create(d)),
        },
    }
}

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
fn combine_delta_data<T: Clone>(
    lhs: &DataDelta<T>,
    rhs: DataDelta<T>,
) -> Result<DataDelta<T>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDelta::Create(d)) => Ok(DataDelta::Create(d)),
        (DataDelta::Create(_), DataDelta::Modify((_, d))) => Ok(DataDelta::Create(d)),
        (DataDelta::Create(_), DataDelta::Delete(d)) => Ok(DataDelta::Delete(d)),

        (DataDelta::Modify((d1, _)), DataDelta::Create(d2)) => {
            Ok(DataDelta::Modify((d1.clone(), d2)))
        }
        (DataDelta::Modify((prev, _)), DataDelta::Modify((_, new))) => {
            Ok(DataDelta::Modify((prev.clone(), new)))
        }
        (DataDelta::Modify((_, _)), DataDelta::Delete(d)) => Ok(DataDelta::Delete(d)),

        (DataDelta::Delete(_), DataDelta::Create(d)) => Ok(DataDelta::Create(d)),
        (DataDelta::Delete(_), DataDelta::Modify((_, _))) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete(_), DataDelta::Delete(_)) => Err(Error::DeltaDataDeletedMultipleTimes),
    }
}

fn combine_delta_elements<T: Clone>(
    lhs: &DeltaMapElement<T>,
    rhs: DeltaMapElement<T>,
) -> Result<DeltaMapElement<T>, Error> {
    match (lhs, rhs) {
        (DeltaMapElement::Delta(d1), DeltaMapElement::Delta(d2)) => {
            combine_delta_data(d1, d2).map(|d| DeltaMapElement::Delta(d))
        }
        (DeltaMapElement::Delta(d), DeltaMapElement::Undo(u)) => {
            combine_delta_data(d, u).map(|d| DeltaMapElement::Delta(d))
        }
        (DeltaMapElement::Undo(_), DeltaMapElement::Delta(_)) => {
            Err(Error::DataCombinedOverUndoNotSupported)
        }
        (DeltaMapElement::Undo(_), DeltaMapElement::Undo(_)) => Err(Error::UndoUndoNotSupported),
    }
}

#[cfg(test)]
mod tests;
