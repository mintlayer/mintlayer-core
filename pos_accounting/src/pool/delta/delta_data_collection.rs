use std::collections::BTreeMap;

use serialization::{Decode, Encode};

use crate::error::Error;
// TODO: move DataDeltaUndoOp here
// TODO: move DeltaMapOp here
use super::{combine::DeltaMapOp, DataDelta, DataDeltaUndoOp};
#[derive(Clone, Encode, Decode)]
pub struct DeltaDataCollection<K: Ord, T> {
    data: BTreeMap<K, DataDelta<T>>,
}

impl<K: Ord + Copy, T> DeltaDataCollection<K, T> {
    pub fn merge_delta_data(
        &mut self,
        delta_to_apply: Self,
    ) -> Result<BTreeMap<K, DataDeltaUndoOp<T>>, Error> {
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

        Ok(data_undo)
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
        undo_data: BTreeMap<K, DataDeltaUndoOp<T>>,
    ) -> Result<(), Error> {
        for (key, data) in undo_data.into_iter() {
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
pub(super) fn combine_delta_data<T>(
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
