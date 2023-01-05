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

use serialization::{Decode, Encode};

use super::DataDelta;

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct DataDeltaUndo<T>(DataDelta<T>);

impl<T> DataDeltaUndo<T> {
    pub fn new(delta: DataDelta<T>) -> Self {
        Self(delta)
    }

    pub fn as_delta(&self) -> &DataDelta<T> {
        &self.0
    }

    pub fn consume(self) -> DataDelta<T> {
        self.0
    }
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaDataUndoCollection<K, T> {
    data: BTreeMap<K, DataDeltaUndo<T>>,
}

impl<K: Ord, T: Clone> DeltaDataUndoCollection<K, T> {
    pub fn new(data: BTreeMap<K, DataDeltaUndo<T>>) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &BTreeMap<K, DataDeltaUndo<T>> {
        &self.data
    }

    pub fn consume(self) -> BTreeMap<K, DataDeltaUndo<T>> {
        self.data
    }
}
