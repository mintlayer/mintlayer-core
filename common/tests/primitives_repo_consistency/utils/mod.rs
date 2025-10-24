// Copyright (c) 2025 RBB S.r.l
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

use itertools::Itertools as _;
use rstest::rstest;

use randomness::{CryptoRng, Rng, SliceRandom};
use serialization::Encode;
use test_utils::random::{make_seedable_rng, Seed};
use utils::sorted::Sorted;

pub mod converters;
pub mod makers;

#[derive(Encode)]
struct CompactEncodedU128(#[codec(compact)] pub u128);

/// Create values of type T with different compact encoding sizes; `values_count` values
/// will be created for each size.
/// T is supposed to be u128 or smaller.
pub fn make_test_values_for_compact_encoding<T>(
    rng: &mut (impl Rng + CryptoRng),
    values_count: usize,
) -> Vec<T>
where
    T: num_traits::Num + num_traits::Bounded,
    u128: From<T>,
    T: TryFrom<u128>,
{
    // The first number in each tuple is the start of the range, and the second one is the expected
    // number of bytes in a compact encoding of an arbitrary value in that range.
    // The end of the range (exclusive) is the beginning of the next range, or 2^128 if it's
    // the last element in the list.
    let encoding_ranges: Vec<(u128, usize)> = [(0, 1), (1 << 6, 2), (1 << 14, 4), (1 << 30, 5)]
        .into_iter()
        .chain(
            (32..128)
                .step_by(8)
                .enumerate()
                .map(|(idx, bit_shift)| (1 << bit_shift, idx + 6)),
        )
        .collect();

    let mut result = Vec::with_capacity(values_count * encoding_ranges.len());

    for _ in 0..values_count {
        for (first, second) in
            encoding_ranges.iter().map(Some).chain(std::iter::once(None)).tuple_windows()
        {
            let (range_start, expected_encoded_size) = *first.unwrap();
            let range_end_inclusive = second.map_or(u128::MAX, |(val, _)| val - 1);
            let max_val: u128 = T::max_value().into();

            if max_val >= range_start {
                let val = rng.gen_range(range_start..=std::cmp::min(max_val, range_end_inclusive));

                // Sanity check
                let encoded_size = CompactEncodedU128(val).encoded_size();
                assert_eq!(encoded_size, expected_encoded_size);

                result.push(val.try_into().map_err(|_| ()).unwrap());
            } else {
                break;
            }
        }
    }

    result.shuffle(rng);

    result
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_make_test_values_for_compact_encoding(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    for _ in 0..100 {
        let vals = make_test_values_for_compact_encoding(&mut rng, 1);

        let encoded_sizes = vals
            .into_iter()
            .map(|val| CompactEncodedU128(val).encoded_size())
            .collect_vec()
            .sorted();
        let expected_encoded_sizes = [1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        assert_eq!(encoded_sizes, expected_encoded_sizes);
    }
}
