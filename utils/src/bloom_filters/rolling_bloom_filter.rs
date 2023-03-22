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

#![allow(clippy::float_arithmetic)]

use std::hash::Hash;

use crypto::random::Rng;

use super::bloom_filter::BloomFilter;

/// RollingBloomFilter is a probabilistic set of the most recently inserted items
/// with the specified number of items and expected false positive rate.
///
/// It works by constructing 3 smaller bloom filters and inserting items until all subfilters are full.
/// Then that the oldest subfilter is replaced by a new one.
/// An element is present if it's present in any subfilter.
pub struct RollingBloomFilter<T> {
    /// The list of subfilters that store items.
    /// The oldest subfilter will be replaced by a new empty subfilter when they are full.
    subfilters: [BloomFilter<T>; 3],

    /// Currently used subfilter index
    subfilter_index: usize,

    /// Number of items added to the current subfilter
    count_subfilter: usize,

    /// Maximum number of items that can be added to a subfilter
    size_subfilter: usize,

    /// Desired false positive probability in each subfilter
    fpp_subfilter: f64,
}

impl<T: Hash> RollingBloomFilter<T> {
    /// Constructs a new rolling bloom filter.
    ///
    /// # Arguments
    /// `size` - maximum number of items to store in the filter (up to 3/2*size of last items can be stored at times)
    /// `fpp` - required false positive rate
    /// `rng` - random number generator used to randomize hashes
    pub fn new(size: usize, fpp: f64, rng: &mut impl Rng) -> Self {
        assert!(size > 0);
        assert!(fpp > 0.0 && fpp < 1.0);

        // Use the smaller bloom filters to store size/2 of the last items in each.
        // This way we always remember `size..3/2*size` items.
        let size_per_filter = (size + 1) / 2;

        // `fpp_per_filter` must be derived from `fpp` so that the probability of being detected in any subfilter is about `fpp`.
        // Since each subfilter can be considered independent, it is about (1 - p)^3,
        // which can be approximated by 1-3*p (if p is small).
        // As a result, the required ffp per filter should be about fpp / 3.0.
        let fpp_per_filter = fpp / 3.0;

        RollingBloomFilter {
            subfilters: [
                BloomFilter::new(size_per_filter, fpp_per_filter, rng),
                BloomFilter::new(size_per_filter, fpp_per_filter, rng),
                BloomFilter::new(size_per_filter, fpp_per_filter, rng),
            ],
            subfilter_index: 0,
            count_subfilter: 0,
            size_subfilter: size_per_filter,
            fpp_subfilter: fpp_per_filter,
        }
    }

    /// Add item to the rolling bloom filter.
    pub fn insert(&mut self, item: &T, rng: &mut impl Rng) {
        self.subfilters[self.subfilter_index].insert(item);
        self.count_subfilter += 1;
        if self.count_subfilter == self.size_subfilter {
            // The maximum number of items in the current subfilter has been reached.
            // Create a new subfilter with new seeds to get new false positives.
            self.subfilter_index = (self.subfilter_index + 1) % 3;
            self.subfilters[self.subfilter_index] =
                BloomFilter::new(self.size_subfilter, self.fpp_subfilter, rng);
            self.count_subfilter = 0;
        }
    }

    /// Returns if the item's hash is present in the rolling bloom filter.
    pub fn contains(&self, item: &T) -> bool {
        self.subfilters.iter().any(|filter| filter.contains(item))
    }
}
