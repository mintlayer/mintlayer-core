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
//
// Author(s): L. Kuklinek

use common::chain::GenBlock;
use common::primitives::Id;
use serialization::{Decode, Encode};

/// Locator is a list of block IDs at exponentially increasing distance from the tip
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct Locator(Vec<Id<GenBlock>>);

impl Locator {
    /// A new locator
    pub fn new(entries: Vec<Id<GenBlock>>) -> Locator {
        Locator(entries)
    }

    /// Get iterator over locator entries
    pub fn iter(&self) -> impl Iterator<Item = &Id<GenBlock>> + ExactSizeIterator {
        self.0.iter()
    }

    /// Get number of entries in the locator
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Convert into a vector.
    pub fn into_vec(self) -> Vec<Id<GenBlock>> {
        self.0
    }
}

impl std::ops::Index<usize> for Locator {
    type Output = Id<GenBlock>;
    fn index(&self, i: usize) -> &Id<GenBlock> {
        &self.0[i]
    }
}
