// Copyright (c) 2023 RBB S.r.l
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

use serialization::{Decode, Encode};

#[derive(Debug, Encode, Decode, Clone, Copy, Eq, PartialEq)]
pub struct ChainstateStorageVersion(u32);

impl ChainstateStorageVersion {
    pub const CURRENT: Self = Self(11);

    pub fn new(value: u32) -> Self {
        Self(value)
    }
}
