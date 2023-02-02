// Copyright (c) 2022 RBB S.r.l
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

use lmdb::DatabaseResizeInfo;

pub type MapResizeCallbackFn = dyn Fn(DatabaseResizeInfo);

/// A function wrapper that represents the callback when the map within lmdb resizes
#[derive(Default)]
pub struct MapResizeCallback {
    f: Option<Box<MapResizeCallbackFn>>,
}

impl MapResizeCallback {
    pub fn new(f: Box<MapResizeCallbackFn>) -> Self {
        Self { f: Some(f) }
    }

    pub fn take(self) -> Option<Box<MapResizeCallbackFn>> {
        self.f
    }
}

impl From<MapResizeCallback> for Option<Box<MapResizeCallbackFn>> {
    fn from(f: MapResizeCallback) -> Self {
        f.take()
    }
}

impl From<Box<MapResizeCallbackFn>> for MapResizeCallback {
    fn from(f: Box<MapResizeCallbackFn>) -> Self {
        Self { f: Some(f) }
    }
}
