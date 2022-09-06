use std::collections::BTreeMap;

use serialization::{Decode, Encode};

use crate::error::Error;

pub mod undo;

// TODO: move DataDeltaUndoOp here

/// The outcome of combining two deltas for a given key upon the map that contains it
#[derive(PartialEq, Debug)]
pub enum DeltaMapOp<T> {
    /// Write a specific value (for example, to write a Create or Modify operation)
    Write(T),
    /// Erase the value at the relevant key spot (for example, a modify followed by Erase yields nothing)
    Delete,
}

use self::undo::{DataDeltaUndoOp, DeltaDataUndoCollection};

#[derive(PartialEq, Clone, Encode, Decode, Debug)]
pub enum DataDelta<T> {
    Create(Box<T>),
    Modify(Box<T>),
    Delete,
}

#[derive(Clone, Encode, Decode)]
pub struct DeltaDataCollection<K: Ord, T> {
    data: BTreeMap<K, DataDelta<T>>,
}

impl<K: Ord + Copy, T> DeltaDataCollection<K, T> {
    pub fn merge_delta_data(
        &mut self,
        delta_to_apply: Self,
    ) -> Result<DeltaDataUndoCollection<K, T>, Error> {
        let data_undo = delta_to_apply
            .data
            .into_iter()
            .map(|(key, other_pool_data)| {
                self.merge_delta_data_element(key, other_pool_data).map(|v| (key, v))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        // TODO: maybe we don't have to run Collect::<_>() twice, but dealing with Result<Option<A>> is tricky in a functional way
        let data_undo = data_undo
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect::<BTreeMap<_, _>>();

        Ok(DeltaDataUndoCollection::new(data_undo))
    }

    pub fn merge_delta_data_element(
        &mut self,
        key: K,
        other_data: DataDelta<T>,
    ) -> Result<Option<DataDeltaUndoOp<T>>, Error> {
        let current = self.data.get(&key);

        // create the operation/change that would modify the current delta and do the merge
        let new_data = match current {
            Some(current_data) => combine_delta_data(current_data, other_data)?,
            None => DeltaMapOp::Write(other_data),
        };

        // apply the change to the current map and create the undo data
        let undo = match new_data {
            // when we insert to a map, undoing is restoring what was there beforehand, and erasing if it was empty
            DeltaMapOp::Write(v) => match self.data.insert(key, v) {
                Some(prev_value) => Some(DataDeltaUndoOp::Write(prev_value)),
                None => Some(DataDeltaUndoOp::Erase),
            },
            // when we remove from a map, undoing is rewriting what we removed
            DeltaMapOp::Delete => self.data.remove(&key).map(DataDeltaUndoOp::Write),
        };

        Ok(undo)
    }

    pub fn undo_merge_delta_data(
        &mut self,
        undo_data: DeltaDataUndoCollection<K, T>,
    ) -> Result<(), Error> {
        for (key, data) in undo_data.consume().into_iter() {
            self.undo_merge_delta_data_element(key, data)?
        }
        Ok(())
    }

    pub fn undo_merge_delta_data_element(
        &mut self,
        key: K,
        data: DataDeltaUndoOp<T>,
    ) -> Result<(), Error> {
        match data {
            DataDeltaUndoOp::Write(undo) => self.data.insert(key, undo),
            DataDeltaUndoOp::Erase => self.data.remove(&key),
        };
        Ok(())
    }

    pub fn data(&self) -> &BTreeMap<K, DataDelta<T>> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<K, DataDelta<T>> {
        self.data
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
            Ok(DeltaMapOp::Delete)
        }
        (DataDelta::Modify(_), DataDelta::Create(_)) => Err(Error::DeltaDataCreatedMultipleTimes),
        (DataDelta::Modify(_), DataDelta::Modify(d)) => Ok(DeltaMapOp::Write(DataDelta::Modify(d))),
        (DataDelta::Modify(_), DataDelta::Delete) => {
            // if lhs had a modification, and we delete, this means nothing is left and there's a net zero to return
            Ok(DeltaMapOp::Delete)
        }
        (DataDelta::Delete, DataDelta::Create(d)) => Ok(DeltaMapOp::Write(DataDelta::Create(d))),
        (DataDelta::Delete, DataDelta::Modify(_)) => Err(Error::DeltaDataModifyAfterDelete),
        (DataDelta::Delete, DataDelta::Delete) => Err(Error::DeltaDataDeletedMultipleTimes),
    }
}

impl<K: Ord, T> Default for DeltaDataCollection<K, T> {
    fn default() -> Self {
        Self {
            data: Default::default(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    #[rustfmt::skip]
    fn test_combine_delta_data() {
        use DataDelta::{Create, Delete, Modify};
        let data = |v| Box::new(v);

        assert_eq!(combine_delta_data(&Create(data(2)), Create(data(3))), Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_delta_data(&Create(data(2)), Modify(data(3))), Ok(DeltaMapOp::Write(DataDelta::Create(data(3)))));
        assert_eq!(combine_delta_data(&Create(data(2)), Delete),          Ok(DeltaMapOp::Delete));

        assert_eq!(combine_delta_data(&Modify(data(2)), Create(data(3))), Err(Error::DeltaDataCreatedMultipleTimes));
        assert_eq!(combine_delta_data(&Modify(data(2)), Modify(data(3))), Ok(DeltaMapOp::Write(DataDelta::Modify(data(3)))));
        assert_eq!(combine_delta_data(&Modify(data(2)), Delete),          Ok(DeltaMapOp::Delete));

        assert_eq!(combine_delta_data(&Delete,          Create(data(3))), Ok(DeltaMapOp::Write(DataDelta::Create(data(3)))));
        assert_eq!(combine_delta_data(&Delete,          Modify(data(3))), Err(Error::DeltaDataModifyAfterDelete));
        assert_eq!(combine_delta_data::<i32>(&Delete,   Delete),          Err(Error::DeltaDataDeletedMultipleTimes));
    }

    #[test]
    fn test_merge_collections() {
        let mut collection1 = DeltaDataCollection {
            data: BTreeMap::from([
                (1, DataDelta::Create(Box::new(10))),
                (2, DataDelta::Modify(Box::new(20))),
                (3, DataDelta::Delete),
                (4, DataDelta::Create(Box::new(40))),
            ]),
        };
        let collection1_origin = collection1.clone();

        let collection2 = DeltaDataCollection {
            data: BTreeMap::from([
                (1, DataDelta::Modify(Box::new(11))),
                (2, DataDelta::Modify(Box::new(21))),
                (4, DataDelta::Delete),
                (5, DataDelta::Delete),
            ]),
        };

        let expected_data = BTreeMap::from([
            (1, DataDelta::Create(Box::new(11))),
            (2, DataDelta::Modify(Box::new(21))),
            (3, DataDelta::Delete),
            (5, DataDelta::Delete),
        ]);

        let undo_data = collection1.merge_delta_data(collection2).unwrap();
        assert_eq!(collection1.data, expected_data);

        collection1.undo_merge_delta_data(undo_data).unwrap();
        assert_eq!(collection1.data, collection1_origin.data);
    }
}
