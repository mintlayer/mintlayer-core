use std::collections::BTreeMap;

use super::DataDelta;

/// The operations we have to do in order to undo a delta
pub enum DataDeltaUndoOp<T> {
    Write(DataDelta<T>),
    Erase,
}

pub struct DeltaDataUndoCollection<K: Ord, T> {
    data: BTreeMap<K, DataDeltaUndoOp<T>>,
}

impl<K: Ord, T> DeltaDataUndoCollection<K, T> {
    pub fn new(data: BTreeMap<K, DataDeltaUndoOp<T>>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &BTreeMap<K, DataDeltaUndoOp<T>> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<K, DataDeltaUndoOp<T>> {
        self.data
    }
}
