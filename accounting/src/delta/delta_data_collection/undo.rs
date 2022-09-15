// Copyright (c) 2021 RBB S.r.l
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
