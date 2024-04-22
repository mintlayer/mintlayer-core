// Copyright (c) 2021-2023 RBB S.r.l
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

use std::hash::{Hash, Hasher};

use randomness::{make_pseudo_rng, Rng};
use serialization::{Decode, Encode};

/// A random number that is generated once and then mixed into certain hashes in the peer manager.
#[derive(Debug, Hash, Encode, Decode, Copy, Clone)]
pub struct Salt(u64);

impl Salt {
    pub fn from_u64(val: u64) -> Self {
        Self(val)
    }

    pub fn new_random() -> Self {
        Self::new_random_with_rng(&mut make_pseudo_rng())
    }

    pub fn new_random_with_rng<R: Rng>(rng: &mut R) -> Self {
        Self(rng.gen::<u64>())
    }

    pub fn mix_with<T: Hash>(&self, data: T) -> Self {
        Self(calc_hash64(&(self.0, data)))
    }
}

/// Calculate a 64-bit non-cryptographic hash of a 'single' value.
///
/// Note: if multiple values are required to produce a single hash, pass them as a tuple.
pub fn calc_hash64<T: Hash>(val: &T) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    val.hash(&mut hasher);
    hasher.finish()
}
