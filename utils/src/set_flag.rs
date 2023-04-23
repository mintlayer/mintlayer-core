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

/// Wrapper for the bool type that can only be set to true
pub struct SetFlag(bool);

impl SetFlag {
    /// Creates a new unset flag
    pub fn new() -> Self {
        Self(false)
    }

    /// If the flag is already set
    pub fn test(&self) -> bool {
        self.0
    }

    /// Sets the flag
    pub fn set(&mut self) {
        self.0 = true;
    }

    /// Sets the flag and returns the old value
    pub fn test_and_set(&mut self) -> bool {
        let old_value = self.0;
        self.0 = true;
        old_value
    }
}
