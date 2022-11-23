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
enum DeltaMapOp<T> {
    /// Write a specific value (for example, to write a Create or Modify operation)
    Write(T),
    /// Erase the value at the relevant key spot (for example, a modify followed by Erase yields nothing)
    Erase,
}

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub enum DataDelta<T> {
    Create(Box<T>),
    Modify(Box<T>),
    Delete,
}

// A collection can store either a delta with data or an operation to perform.
// Operations are a result of merge undo on a collection that misses the key.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
enum DeltaMapElement<T> {
    Data(DataDelta<T>),
    Operation(DeltaMapOp<DataDelta<T>>),
}

#[must_use]
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct DeltaDataCollection<K: Ord, T> {
    data: BTreeMap<K, DeltaMapElement<T>>,
}

impl<K: Ord + Copy, T> DeltaDataCollection<K, T> {
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    pub fn data_iter(&self) -> impl Iterator<Item = (&K, &DataDelta<T>)> {
        self.data.iter().filter_map(|(k, el)| match el {
            DeltaMapElement::Data(d) => Some((k, d)),
            DeltaMapElement::Operation(_) => None,
        })
    }

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
        //FIXME get rid of unreachable
        let current = self.data.get(&key);

        // create the operation/change that would modify the current delta and do the merge
        let new_data = match current {
            Some(current_data) => combine_delta_elements(current_data, other_data)?,
            None => match other_data {
                DeltaMapElement::Data(d) => DeltaMapOp::Write(d),
                DeltaMapElement::Operation(op) => op,
            },
        };

        // apply the change to the current map and create the undo data
        let undo = match new_data {
            // when we insert to a map, undoing is restoring what was there beforehand, and erasing if it was empty
            DeltaMapOp::Write(v) => match self.data.insert(key, DeltaMapElement::Data(v)) {
                Some(prev_value) => match prev_value {
                    DeltaMapElement::Data(d) => DataDeltaUndoOp(DeltaMapOp::Write(d)),
                    DeltaMapElement::Operation(_) => unreachable!(),
                },
                None => DataDeltaUndoOp(DeltaMapOp::Erase),
            },
            // when we remove from a map, undoing is rewriting what we removed
            DeltaMapOp::Erase => self
                .data
                .remove(&key)
                .map(|v| match v {
                    DeltaMapElement::Data(d) => DataDeltaUndoOp(DeltaMapOp::Write(d)),
                    DeltaMapElement::Operation(_) => unreachable!(),
                })
                .expect("key should always be present"),
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
        data: DataDeltaUndoOp<T>,
    ) -> Result<(), Error> {
        match data.0 {
            DeltaMapOp::Write(d) => {
                self.data.insert(key, DeltaMapElement::Data(d));
            }
            // FIXME? we shouldn't remove information from the collection.
            // Some kind of combine is required here
            DeltaMapOp::Erase => {
                if self.data.remove(&key).is_none() {
                    // It's OK to undo delta that is not present.
                    // It can be later found in another collection.
                    // Therefore to avoid data loss just propagate the operation.
                    self.data.insert(key, DeltaMapElement::Operation(data.0));
                }
            }
        };
        Ok(())
    }
}

impl<K: Ord + Copy, T> FromIterator<(K, DataDelta<T>)> for DeltaDataCollection<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, DataDelta<T>)>>(iter: I) -> Self {
        DeltaDataCollection {
            data: BTreeMap::<K, DeltaMapElement<T>>::from_iter(
                iter.into_iter().map(|(k, d)| (k, DeltaMapElement::Data(d))),
            ),
        }
    }
}

fn combine_delta_elements<T>(
    lhs: &DeltaMapElement<T>,
    rhs: DeltaMapElement<T>,
) -> Result<DeltaMapOp<DataDelta<T>>, Error> {
    match (lhs, rhs) {
        (DeltaMapElement::Data(d1), DeltaMapElement::Data(d2)) => combine_delta_data(d1, d2),
        (DeltaMapElement::Data(d), DeltaMapElement::Operation(op)) => match (d, op) {
            (DataDelta::Create(_), DeltaMapOp::Write(_)) => todo!(),
            (DataDelta::Create(_), DeltaMapOp::Erase) => Ok(DeltaMapOp::Erase),
            (DataDelta::Modify(_), DeltaMapOp::Write(_)) => todo!(),
            (DataDelta::Modify(_), DeltaMapOp::Erase) => Ok(DeltaMapOp::Erase),
            (DataDelta::Delete, DeltaMapOp::Write(_)) => todo!(),
            (DataDelta::Delete, DeltaMapOp::Erase) => Ok(DeltaMapOp::Erase),
        },
        (DeltaMapElement::Operation(_), DeltaMapElement::Data(_)) => panic!("how?"),
        (DeltaMapElement::Operation(_), DeltaMapElement::Operation(_)) => panic!("how?"),
    }
}

/// Given two deltas, combine them into one delta, this is the basic delta data composability function
fn combine_delta_data<T>(
    lhs: &DataDelta<T>,
    rhs: DataDelta<T>,
) -> Result<DeltaMapOp<DataDelta<T>>, Error> {
    match (lhs, rhs) {
        (DataDelta::Create(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Create(_), DataDelta::Modify(d)) => Ok(DeltaMapOp::Write(DataDelta::Create(d))),
        (DataDelta::Create(_), DataDelta::Delete) => {
            // if lhs had a creation, and we delete, this means nothing is left and there's a net zero to return
            Ok(DeltaMapOp::Erase)
        }
        (DataDelta::Modify(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Modify(_), DataDelta::Modify(d)) => Ok(DeltaMapOp::Write(DataDelta::Modify(d))),
        (DataDelta::Modify(_), DataDelta::Delete) => {
            // if lhs had a modification, and we delete, this means nothing is left and there's a net zero to return
            Ok(DeltaMapOp::Erase)
        }
        (DataDelta::Delete, DataDelta::Create(d)) => Ok(DeltaMapOp::Write(DataDelta::Create(d))),
        (DataDelta::Delete, DataDelta::Modify(_)) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete, DataDelta::Delete) => Err(Error::DeltaDataDeletedMultipleTimes),
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn test_combine_delta_data() {
        use DataDelta::{Create, Delete, Modify};

        assert_eq!(combine_delta_data(&Create(Box::new('a')), Create(Box::new('b'))), Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_delta_data(&Create(Box::new('a')), Modify(Box::new('b'))), Ok(DeltaMapOp::Write(DataDelta::Create(Box::new('b')))));
        assert_eq!(combine_delta_data(&Create(Box::new('a')), Delete),                Ok(DeltaMapOp::Erase));

        assert_eq!(combine_delta_data(&Modify(Box::new('a')), Create(Box::new('b'))), Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_delta_data(&Modify(Box::new('a')), Modify(Box::new('b'))), Ok(DeltaMapOp::Write(DataDelta::Modify(Box::new('b')))));
        assert_eq!(combine_delta_data(&Modify(Box::new('a')), Delete),                Ok(DeltaMapOp::Erase));

        assert_eq!(combine_delta_data(&Delete,                Create(Box::new('b'))), Ok(DeltaMapOp::Write(DataDelta::Create(Box::new('b')))));
        assert_eq!(combine_delta_data(&Delete,                Modify(Box::new('b'))), Err(Error::DeltaDataModifyAfterDelete));
        assert_eq!(combine_delta_data::<char>(&Delete,        Delete),                Err(Error::DeltaDataDeletedMultipleTimes));
    }

    #[test]
    fn test_merge_collections() {
        // This test check all valid combinations:
        //    collection1 - collection2
        //    -------------------------
        //         Create - Modify
        //         Create - Delete
        //         Modify - Modify
        //         Modify - Delete
        //         Delete - Create
        //         Create - None
        //         Modify - None
        //         Delete - None
        //         None   - Create
        //         None   - Modify
        //         None   - Delete

        let mut collection1 = DeltaDataCollection::from_iter(
            [
                (1, DataDelta::Create(Box::new('a'))),
                (2, DataDelta::Create(Box::new('b'))),
                (3, DataDelta::Modify(Box::new('c'))),
                (4, DataDelta::Modify(Box::new('d'))),
                (5, DataDelta::Delete),
                (6, DataDelta::Create(Box::new('e'))),
                (7, DataDelta::Modify(Box::new('f'))),
                (8, DataDelta::Delete),
            ]
            .into_iter(),
        );
        let collection1_origin = collection1.clone();

        let collection2 = DeltaDataCollection::from_iter(
            [
                (1, DataDelta::Modify(Box::new('g'))),
                (2, DataDelta::Delete),
                (3, DataDelta::Modify(Box::new('h'))),
                (4, DataDelta::Delete),
                (5, DataDelta::Create(Box::new('i'))),
                (9, DataDelta::Create(Box::new('j'))),
                (10, DataDelta::Modify(Box::new('k'))),
                (11, DataDelta::Delete),
            ]
            .into_iter(),
        );

        let expected_data = BTreeMap::from_iter(
            [
                (1, DeltaMapElement::Data(DataDelta::Create(Box::new('g')))),
                // 2 was erased
                (3, DeltaMapElement::Data(DataDelta::Modify(Box::new('h')))),
                // 4 was erased
                (5, DeltaMapElement::Data(DataDelta::Create(Box::new('i')))),
                (6, DeltaMapElement::Data(DataDelta::Create(Box::new('e')))),
                (7, DeltaMapElement::Data(DataDelta::Modify(Box::new('f')))),
                (8, DeltaMapElement::Data(DataDelta::Delete)),
                (9, DeltaMapElement::Data(DataDelta::Create(Box::new('j')))),
                (10, DeltaMapElement::Data(DataDelta::Modify(Box::new('k')))),
                (11, DeltaMapElement::Data(DataDelta::Delete)),
            ]
            .into_iter(),
        );

        let undo_data = collection1.merge_delta_data(collection2).unwrap();
        assert_eq!(collection1.data, expected_data);

        collection1.undo_merge_delta_data(undo_data).unwrap();
        assert_eq!(collection1.data, collection1_origin.data);
    }

    #[test]
    fn test_undo_nonexisting_delta() {
        {
            let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
            collection
                .undo_merge_delta_data_element(0, DataDeltaUndoOp(DeltaMapOp::Erase))
                .unwrap();
            let expected_data = BTreeMap::from_iter(
                [(0, DeltaMapElement::Operation(DeltaMapOp::Erase))].into_iter(),
            );
            assert_eq!(collection.data, expected_data);
        }

        {
            let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
            collection
                .undo_merge_delta_data_element(
                    0,
                    DataDeltaUndoOp(DeltaMapOp::Write(DataDelta::Create(Box::new('a')))),
                )
                .unwrap();
            let expected_data =
                DeltaDataCollection::from_iter([(0, DataDelta::Create(Box::new('a')))].into_iter());
            assert_eq!(collection, expected_data);
        }

        {
            let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
            collection
                .undo_merge_delta_data_element(
                    0,
                    DataDeltaUndoOp(DeltaMapOp::Write(DataDelta::Modify(Box::new('a')))),
                )
                .unwrap();
            let expected_data =
                DeltaDataCollection::from_iter([(0, DataDelta::Modify(Box::new('a')))].into_iter());
            assert_eq!(collection, expected_data);
        }

        {
            let mut collection: DeltaDataCollection<i32, char> = DeltaDataCollection::new();
            collection
                .undo_merge_delta_data_element(
                    0,
                    DataDeltaUndoOp(DeltaMapOp::Write(DataDelta::Delete)),
                )
                .unwrap();
            let expected_data =
                DeltaDataCollection::from_iter([(0, DataDelta::Delete)].into_iter());
            assert_eq!(collection, expected_data);
        }
    }

    // TODO: increase test coverage (consider using proptest)

    #[test]
    fn create_delete_undo() {
        let mut collection1 =
            DeltaDataCollection::from_iter([(1, DataDelta::Create(Box::new('a')))].into_iter());
        let collection1_origin = collection1.clone();

        let mut collection2 = DeltaDataCollection::new();
        let undo_op = collection2.merge_delta_data_element(1, DataDelta::Delete).unwrap();

        let mut collection3 = DeltaDataCollection::new();
        collection3.undo_merge_delta_data_element(1, undo_op).unwrap();

        let _ = collection2.merge_delta_data(collection3).unwrap();
        let _ = collection1.merge_delta_data(collection2).unwrap();
        assert_eq!(collection1.data, collection1_origin.data);
    }
}
