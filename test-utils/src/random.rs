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

pub use crypto::random::{self, seq::IteratorRandom, CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{num::ParseIntError, str::FromStr};

#[derive(Debug, Copy, Clone)]
pub struct Seed(pub u64);

impl Seed {
    pub fn from_entropy() -> Self {
        Seed(crypto::random::make_true_rng().gen::<u64>())
    }

    pub fn from_entropy_and_print(test_name: &str) -> Self {
        let result = Seed(crypto::random::make_true_rng().gen::<u64>());
        result.print_with_decoration(test_name);
        result
    }

    pub fn from_u64(v: u64) -> Self {
        Seed(v)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn print_with_decoration(&self, test_name: &str) {
        println!("{test_name} seed: {}", self.0);
    }
}

impl FromStr for Seed {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.parse::<u64>()?;
        Ok(Seed::from_u64(v))
    }
}

impl From<u64> for Seed {
    fn from(v: u64) -> Self {
        Seed::from_u64(v)
    }
}

#[derive(Debug, Clone)]
pub struct TestRng(rand_chacha::ChaChaRng);

impl TestRng {
    pub fn new(seed: Seed) -> Self {
        Self(ChaChaRng::seed_from_u64(seed.as_u64()))
    }

    pub fn random(rng: &mut (impl Rng + CryptoRng)) -> Self {
        Self::new(Seed(rng.gen()))
    }

    pub fn from_entropy() -> Self {
        Self::new(Seed::from_entropy())
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for TestRng {}

#[must_use]
pub fn make_seedable_rng(seed: Seed) -> impl Rng + CryptoRng {
    TestRng::new(seed)
}

// This is similar to SliceRandom::shuffle, but it makes sure that the resulting order
// will be different from the original one.
pub fn shuffle_until_different<T>(slice: &mut [T], rng: &mut impl Rng) {
    const MAX_ATTEMPTS: usize = 1000;

    for _ in 0..MAX_ATTEMPTS {
        let mut swapped = false;

        for i in (1..slice.len()).rev() {
            let other_idx = rng.gen_range(0..(i + 1));
            if other_idx != i {
                slice.swap(i, other_idx);
                swapped = true;
            }
        }

        if swapped {
            return;
        }
    }

    panic!("Can't shuffle the slice");
}

pub fn flip_random_bit(data: &mut [u8], rng: &mut impl Rng) {
    assert!(!data.is_empty());

    let byte_idx = rng.gen_range(0..data.len());
    let bit_idx = rng.gen_range(0..8);
    let bit_mask = (1 << bit_idx) as u8;

    let byte = &mut data[byte_idx];
    *byte = (*byte & !bit_mask) | (!*byte & bit_mask);
}

pub fn with_random_bit_flipped(data: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut data = data.to_vec();
    flip_random_bit(&mut data, rng);
    data
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn shuffle_until_different_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let vec = vec![1, 2];
        let mut shuffled_vec = vec.clone();
        shuffle_until_different(&mut shuffled_vec, &mut rng);
        assert_ne!(vec, shuffled_vec);

        let vec = vec![1, 2, 3];
        let mut shuffled_vec = vec.clone();
        shuffle_until_different(&mut shuffled_vec, &mut rng);
        assert_ne!(vec, shuffled_vec);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn flip_random_bit_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let data: Vec<u8> = (1..20).map(|_| rng.gen()).collect();
        let data_with_flipped_bit = with_random_bit_flipped(&data, &mut rng);
        assert_eq!(data.len(), data_with_flipped_bit.len());
        assert_ne!(data, data_with_flipped_bit);

        let different_bits_count = data
            .iter()
            .zip(data_with_flipped_bit.iter())
            .fold(0, |acc, (byte1, byte2)| acc + (byte1 ^ byte2).count_ones());
        assert_eq!(different_bits_count, 1);
    }
}
