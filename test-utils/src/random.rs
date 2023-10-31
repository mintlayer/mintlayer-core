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

pub use crypto::random as inner_random;
pub use crypto::random::{CryptoRng, Rng, SeedableRng};
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

#[must_use]
pub fn make_seedable_rng(seed: Seed) -> impl Rng + CryptoRng {
    ChaChaRng::seed_from_u64(seed.0)
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
}
