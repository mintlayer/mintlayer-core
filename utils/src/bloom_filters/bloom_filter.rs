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

use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use randomness::{Rng, RngExt as _};
use siphasher::sip::SipHasher13;

/// A space-efficient probabilistic data structure to test for membership in a set.
///
/// Items can be added, but never removed. `contains` never produces false negatives,
/// but may produce false positives with a probability of at most `fpp` for filters
/// that contain no more than `size` items.
///
/// We used to depend on the `probabilistic_collections` crate here, but it is
/// abandoned (and pulls in the vulnerable `rand` 0.7), so this is a minimal
/// reimplementation of the functionality that we need.
pub struct BloomFilter<T> {
    /// The bit array, storing `bit_count` bits
    bits: Vec<u64>,

    /// The number of bits in the bit array (commonly denoted as `m`)
    bit_count: usize,

    /// The number of hash functions (commonly denoted as `k`)
    hash_count: u32,

    /// The pair of hashers used to derive the item indices (Kirsch-Mitzenmacher scheme)
    hashers: [SipHasher13; 2],

    _phantom: PhantomData<fn(&T)>,
}

impl<T: Hash> BloomFilter<T> {
    /// Constructs a new, empty `BloomFilter` with an estimated max capacity of `size` items,
    /// and a maximum false positive probability of `fpp`.
    pub fn new(size: usize, fpp: f64, rng: &mut impl Rng) -> Self {
        assert!(size > 0);
        assert!(fpp > 0.0 && fpp < 1.0);

        // The optimal number of bits per item: -log2(fpp) / (ln(2)^2)
        #[allow(clippy::float_arithmetic)]
        let (bit_count, hash_count) = {
            let ln2 = std::f64::consts::LN_2;
            let bit_count = -((size as f64) * fpp.ln()) / (ln2 * ln2);
            let hash_count = ((bit_count / size as f64) * ln2).round();

            (
                bit_count.ceil() as usize,
                // Round down but ensure that there is at least one hash function.
                std::cmp::max(hash_count as u32, 1),
            )
        };

        Self {
            bits: vec![0; bit_count.div_ceil(u64::BITS as usize)],
            bit_count,
            hash_count,
            hashers: [
                SipHasher13::new_with_keys(rng.random(), rng.random()),
                SipHasher13::new_with_keys(rng.random(), rng.random()),
            ],
            _phantom: PhantomData,
        }
    }

    fn indices(&self, value: &T) -> impl Iterator<Item = usize> + '_ {
        let hashes: [u64; 2] = {
            let mut hash1 = self.hashers[0];
            let mut hash2 = self.hashers[1];
            value.hash(&mut hash1);
            value.hash(&mut hash2);
            [hash1.finish(), hash2.finish()]
        };

        let bit_count = self.bit_count as u64;
        (0..self.hash_count).map(move |i| {
            // The Kirsch-Mitzenmacher scheme: h1 + i*h2 + i^2, modulo the number of bits.
            // 128-bit arithmetic is used to avoid overflows.
            let idx = (hashes[0] as u128)
                .wrapping_add((i as u128) * (hashes[1] as u128))
                .wrapping_add((i as u128) * (i as u128));
            (idx % bit_count as u128) as usize
        })
    }

    /// Inserts an element into the bloom filter
    pub fn insert(&mut self, value: &T) {
        let indices: Vec<usize> = self.indices(value).collect();
        for idx in indices {
            self.bits[idx / u64::BITS as usize] |= 1 << (idx % u64::BITS as usize);
        }
    }

    /// Checks if an element is possibly in the bloom filter
    pub fn contains(&self, value: &T) -> bool {
        self.indices(value).all(|idx| {
            self.bits[idx / u64::BITS as usize] & (1 << (idx % u64::BITS as usize)) != 0
        })
    }

    /// Clears the bloom filter, removing all elements
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }
}

impl<T> Debug for BloomFilter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BloomFilter").finish()
    }
}

#[cfg(test)]
mod tests {
    use test_utils::random::Seed;

    use super::BloomFilter;

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn no_false_negatives(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut filter = BloomFilter::<u64>::new(1000, 0.001, &mut rng);

        for i in 0..1000u64 {
            filter.insert(&i);
        }

        for i in 0..1000u64 {
            assert!(filter.contains(&i), "false negative for {i}");
        }
    }

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn false_positive_rate(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut filter = BloomFilter::<u64>::new(1000, 0.001, &mut rng);

        for i in 0..1000u64 {
            filter.insert(&i);
        }

        // Check 100k items that were never inserted and count the false positives.
        // The expected number is about 100; the sanity bounds are generous.
        let mut false_positives = 0;
        for i in 10_000u64..110_000 {
            if filter.contains(&i) {
                false_positives += 1;
            }
        }
        assert!(
            false_positives > 10 && false_positives < 300,
            "invalid number of false positives: {false_positives}"
        );
    }

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn clear(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let mut filter = BloomFilter::<u64>::new(100, 0.01, &mut rng);

        for i in 0..100u64 {
            filter.insert(&i);
        }

        filter.clear();

        // After clearing, most items must be reported as absent. Note that a bloom
        // filter cannot guarantee this for previously inserted items, but a cleared
        // (all-zero) filter must not report any false positives at all.
        assert!(filter.bits.iter().all(|&word| word == 0));
        for i in 0..100u64 {
            assert!(!filter.contains(&i));
        }
    }

    #[rstest::rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn randomized_hash_keys(#[case] seed: Seed) {
        // Two filters constructed with different rng states must not share hash keys,
        // otherwise persistent false positives would plague long-lived filters.
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let filter1 = BloomFilter::<u64>::new(100, 0.01, &mut rng);
        let filter2 = BloomFilter::<u64>::new(100, 0.01, &mut rng);

        assert_ne!(
            filter1.indices(&12345u64).collect::<Vec<_>>(),
            filter2.indices(&12345u64).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn deterministic_behavior() {
        // The same item must always map to the same indices within a given filter.
        let mut rng = randomness::make_pseudo_rng();
        let mut filter = BloomFilter::<String>::new(100, 0.01, &mut rng);
        filter.insert(&"hello".to_owned());

        assert!(filter.contains(&"hello".to_owned()));
        assert!(!filter.contains(&"world".to_owned()));
    }
}
