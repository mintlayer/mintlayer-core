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
    /// Note: the PoS seal maps introduced alongside this version start empty on
    /// the nodes that upgrade, so the seal duplication tracking only covers the
    /// blocks processed after the upgrade and does not backfill the history
    /// (see the schema docs). The maps must remain advisory: if seal duplication
    /// ever gates block acceptance, a storage version bump with a backfill (or a
    /// consensus-rule anchoring of the seals) will be required.
    pub const CURRENT: Self = Self(11);

    pub fn new(value: u32) -> Self {
        Self(value)
    }
}
