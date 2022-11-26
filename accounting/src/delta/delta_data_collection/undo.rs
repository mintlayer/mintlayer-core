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

use std::collections::BTreeMap;

use super::DataDelta;

use serialization::{Decode, Encode};

/// The operations we have to perform in order to undo a delta
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(super) enum DataDeltaUndoOpInternal<T: Clone> {
    Write(DataDelta<T>),
    /// This op preserves original data before the erased value. It is important for merging deltas with data.
    Erase(DataDelta<T>),
}
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct DataDeltaUndoOp<T: Clone>(pub(super) DataDeltaUndoOpInternal<T>);

impl<T: Clone> DataDeltaUndoOp<T> {
    pub fn new_write(data: DataDelta<T>) -> Self {
        Self(DataDeltaUndoOpInternal::Write(data))
    }

    pub fn new_erase(data: DataDelta<T>) -> Self {
        Self(DataDeltaUndoOpInternal::Erase(data))
    }
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaDataUndoCollection<K: Ord, T: Clone> {
    data: BTreeMap<K, DataDeltaUndoOp<T>>,
}

impl<K: Ord, T: Clone> DeltaDataUndoCollection<K, T> {
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
