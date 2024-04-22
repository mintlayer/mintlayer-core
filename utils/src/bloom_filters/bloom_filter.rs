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

use std::{fmt::Debug, hash::Hash};

use probabilistic_collections::SipHasherBuilder;
use randomness::Rng;

/// A space-efficient probabilistic data structure to test for membership in a set.
pub struct BloomFilter<T>(probabilistic_collections::bloom::BloomFilter<T>);

impl<T: Hash> BloomFilter<T> {
    /// Constructs a new, empty `BloomFilter` with an estimated max capacity of `size` items,
    /// and a maximum false positive probability of `fpp`.
    pub fn new(size: usize, fpp: f64, rng: &mut impl Rng) -> Self {
        assert!(size > 0);
        assert!(fpp > 0.0 && fpp < 1.0);
        Self(
            probabilistic_collections::bloom::BloomFilter::<T>::with_hashers(
                size,
                fpp,
                [
                    SipHasherBuilder::from_seed(rng.gen(), rng.gen()),
                    SipHasherBuilder::from_seed(rng.gen(), rng.gen()),
                ],
            ),
        )
    }

    /// Inserts an element into the bloom filter
    pub fn insert(&mut self, value: &T) {
        self.0.insert(value);
    }

    /// Checks if an element is possibly in the bloom filter
    pub fn contains(&self, value: &T) -> bool {
        self.0.contains(value)
    }

    /// Clears the bloom filter, removing all elements
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

impl<T> Debug for BloomFilter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BloomFilter").finish()
    }
}
