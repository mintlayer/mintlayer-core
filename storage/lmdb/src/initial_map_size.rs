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

use crate::memsize::MemSize;

pub struct InitialMapSize {
    initial_map_size: Option<MemSize>,
}

impl InitialMapSize {
    pub fn into_memsize(&self) -> Option<MemSize> {
        self.initial_map_size
    }
}

impl Default for InitialMapSize {
    fn default() -> Self {
        Self {
            initial_map_size: None,
        }
    }
}

impl From<MemSize> for InitialMapSize {
    fn from(initial_map_size: MemSize) -> Self {
        Self {
            initial_map_size: Some(initial_map_size),
        }
    }
}

impl From<InitialMapSize> for Option<MemSize> {
    fn from(initial_map_size: InitialMapSize) -> Self {
        initial_map_size.initial_map_size
    }
}
