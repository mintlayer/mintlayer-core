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

mod basic_test_time_getter;
pub mod mock_time_getter;
pub mod nft_utils;
pub mod random;
pub mod test_dir;
pub mod threading;

use std::collections::BTreeMap;

use hex::ToHex;
use itertools::Itertools;

use randomness::distributions::uniform::SampleRange;
use randomness::Rng;

pub use basic_test_time_getter::BasicTestTimeGetter;

/// Assert that the encoded object matches the expected hex string.
pub fn assert_encoded_eq<E: serialization::Encode>(to_encode: &E, expected_hex: &str) {
    assert_eq!(to_encode.encode().encode_hex::<String>(), expected_hex);
}

/// Encodes an object to a hex string
pub fn encode_to_hex<E: serialization::Encode>(to_encode: &E) -> String {
    to_encode.encode().encode_hex::<String>()
}

/// Decodes a hex string to an object. Will panic on errors
pub fn decode_from_hex<D: serialization::DecodeAll>(to_decode: &str) -> D {
    D::decode_all(&mut hex::decode(to_decode).expect("The provided string is a hex").as_slice())
        .expect("The decoding succeeded")
}

/// Get all variants of the object with single-bit flips (decoding may fail).
pub fn try_all_single_bit_mutations<T>(obj: &T) -> impl Iterator<Item = serialization::Result<T>>
where
    T: serialization::DecodeAll + serialization::Encode,
{
    let obj_enc = obj.encode();
    (0..(obj_enc.len() * 8)).map(move |bit| {
        let (byte, bit) = (bit / 8, bit % 8);
        let mut mutated = obj_enc.clone();
        mutated[byte] ^= 1u8 << bit;
        T::decode_all(&mut mutated.as_slice())
    })
}

/// Get all variants of the object with single-bit flips (decoding failures are dropped).
pub fn all_single_bit_mutations<T>(obj: &T) -> impl Iterator<Item = T>
where
    T: serialization::DecodeAll + serialization::Encode,
{
    try_all_single_bit_mutations(obj).filter_map(Result::ok)
}

pub fn get_random_non_ascii_alphanumeric_byte(rng: &mut impl Rng) -> u8 {
    for _ in 0..1000 {
        let random_byte = rng.gen::<u8>();
        if !random_byte.is_ascii_alphanumeric() {
            return random_byte;
        }
    }
    // it's approximately 0.75^1000 that this panics
    panic!("couldn't sample non_ascii_alphanumeric_char");
}

pub fn random_ascii_alphanumeric_string<R: SampleRange<usize>>(
    rng: &mut impl Rng,
    range_len: R,
) -> String {
    use randomness::distributions::{Alphanumeric, DistString};
    if range_len.is_empty() {
        return String::new();
    }
    let len = rng.gen_range(range_len);
    Alphanumeric.sample_string(rng, len)
}

pub fn gen_text_with_non_ascii(c: u8, rng: &mut impl Rng, max_len: usize) -> Vec<u8> {
    assert!(!c.is_ascii_alphanumeric());
    let text_len = 1 + rng.gen::<usize>() % max_len;
    let random_index_to_replace = rng.gen::<usize>() % text_len;
    let token_ticker: Vec<u8> = (0..text_len)
        .map(|idx| {
            if idx != random_index_to_replace {
                rng.sample(randomness::distributions::Alphanumeric)
            } else {
                c
            }
        })
        .take(text_len)
        .collect();
    token_ticker
}

pub fn gen_different_value<T, G>(orig_val: &T, mut gen: G) -> T
where
    T: Eq,
    G: FnMut() -> T,
{
    for _ in 0..1000 {
        let val = gen();

        if val != *orig_val {
            return val;
        }
    }

    panic!("Failed to generate a value");
}

pub fn split_value(rng: &mut impl Rng, value: u128) -> Vec<u128> {
    let mut numbers = vec![0, value];
    let n = rng.gen_range(0..10);

    if value > 1 && n > 0 {
        numbers.extend((0..=n).map(|_| rng.gen_range(1..value)).collect::<Vec<_>>());
        numbers.sort();
    }

    numbers.iter().tuple_windows().map(|(v0, v1)| v1 - v0).collect()
}

pub fn merge_btree_maps<K: Ord, V>(map1: BTreeMap<K, V>, map2: BTreeMap<K, V>) -> BTreeMap<K, V> {
    let mut result = map2;
    for (k, v) in map1.into_iter() {
        let prev_item = result.insert(k, v);
        assert!(prev_item.is_none());
    }

    result
}

#[macro_export]
macro_rules! assert_matches_return_val {
    ($in:expr, $pattern:pat $(if $guard:expr)?, $out:expr) => {
        {
            let to_match = $in;
            match to_match {
                $pattern $(if $guard)? => $out,
                _ => {
                    panic!(
                        "Assertion failed: expression {:?} doesn't match pattern {}",
                        to_match,
                        stringify!($pattern)
                    )
                }
            }
        }
    };
}

#[macro_export]
macro_rules! assert_matches {
    ($in:expr, $pattern:pat $(if $guard:expr)?) => {
        $crate::assert_matches_return_val!($in, $pattern $(if $guard)?, ())
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{make_seedable_rng, Seed};
    use rstest::rstest;

    mod match_macro_tests {
        #[allow(unused)]
        #[derive(Debug)]
        enum TestEnum {
            E1(usize),
            E2,
        }

        #[test]
        fn assert_matches_return_val_success() {
            let test_val = TestEnum::E1(123);

            let val = assert_matches_return_val!(test_val, TestEnum::E1(x), x);
            assert_eq!(val, 123);
        }

        #[test]
        #[should_panic]
        fn assert_matches_return_val_failure() {
            let test_val = TestEnum::E1(123);

            assert_matches_return_val!(test_val, TestEnum::E2, ());
        }

        #[test]
        fn assert_matches_success() {
            let test_val = TestEnum::E1(123);

            assert_matches!(test_val, TestEnum::E1(_));
        }

        #[test]
        #[should_panic]
        fn assert_matches_failure() {
            let test_val = TestEnum::E1(123);

            assert_matches!(test_val, TestEnum::E2);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn split_value_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        assert_eq!(vec![0], split_value(&mut rng, 0));
        assert_eq!(vec![1], split_value(&mut rng, 1));

        let value = rng.gen::<u128>();
        let result = split_value(&mut rng, value);
        assert_eq!(value, result.iter().sum());
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn random_ascii_alphanumeric_string_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let result = random_ascii_alphanumeric_string(&mut rng, 1..100);
        assert!(result.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
