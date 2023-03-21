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

use std::hash::Hash;

use crypto::random::Rng;

use super::bloom_filter::BloomFilter;

pub struct RollingBloomFilter<T> {
    filters: [BloomFilter<T>; 3],
    filter_index: usize,
    count: usize,
    size_per_filter: usize,
    fpp_per_filter: f64,
}

impl<T: Hash> RollingBloomFilter<T> {
    pub fn new(size: usize, fpp: f64, rng: &mut impl Rng) -> Self {
        assert!(size > 0);
        assert!(fpp > 0.0 && fpp < 1.0);
        let size_per_filter = (size + 1) / 2;
        let fpp_per_filter = fpp / 3.0;

        let mut new_filter = || BloomFilter::new(size_per_filter, fpp_per_filter, rng);

        RollingBloomFilter {
            filters: [new_filter(), new_filter(), new_filter()],
            filter_index: 0,
            count: 0,
            size_per_filter,
            fpp_per_filter,
        }
    }

    pub fn insert(&mut self, item: &T, rng: &mut impl Rng) {
        self.filters[self.filter_index].insert(item);
        self.count += 1;
        if self.count == self.size_per_filter {
            self.filter_index = (self.filter_index + 1) % 3;
            self.filters[self.filter_index] =
                BloomFilter::new(self.size_per_filter, self.fpp_per_filter, rng);
            self.count = 0;
        }
    }

    pub fn contains(&self, item: &T) -> bool {
        for filter in self.filters.iter() {
            if filter.contains(item) {
                return true;
            }
        }
        false
    }
}
