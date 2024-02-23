// Copyright (c) 2021-2022 RBB S.r.l
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
    cmp::{Eq, Ord},
    collections::BTreeMap,
    ops::{Div, Sub},
};

use num_traits::ops::checked::{CheckedAdd, CheckedMul};

use common::primitives::Amount;

use crate::FeeRate;

pub fn linear_interpolation<X, Y>(p0: (X, Y), p1: (X, Y), x: X) -> Option<Y>
where
    X: Sub<Output = X> + Eq + Ord + Copy,
    Y: CheckedAdd<Output = Y> + CheckedMul<Output = Y> + Div<Output = Y> + Copy + From<X>,
{
    if p0.0 == p1.0 {
        // Avoid division by zero
        return if p0.0 == x { Some(p0.1) } else { None };
    }

    if x < p0.0 || x > p1.0 {
        // The interpolation factor is outside the range
        None
    } else {
        let scaled_v1 = p0.1.checked_mul(&Y::from(p1.0 - x))?;
        let scaled_v2 = p1.1.checked_mul(&Y::from(x - p0.0))?;
        let total_scale = Y::from(p1.0 - p0.0);

        let interpolated_value = scaled_v1.checked_add(&scaled_v2)? / total_scale;
        Some(interpolated_value)
    }
}

pub fn find_interpolated_value<T: From<FeeRate> + Into<FeeRate> + Copy>(
    map: &BTreeMap<usize, T>,
    key: usize,
) -> Option<T> {
    match map.get(&key) {
        Some(value) => Some(*value),
        None => {
            let (k1, left_value) = map.range(..key).next_back()?;
            let (k2, right_value) = map.range(key..).next()?;
            let left_value: FeeRate = (*left_value).into();
            let right_value: FeeRate = (*right_value).into();

            let interpolated_value = linear_interpolation(
                (*k1 as u64, left_value.atoms_per_kb()),
                (*k2 as u64, right_value.atoms_per_kb()),
                key as u64,
            )?;

            Some(FeeRate::from_amount_per_kb(Amount::from_atoms(interpolated_value)).into())
        }
    }
}

// Generate equidistant points to evaluate the mathematical function at for interpolation
pub fn generate_equidistant_span(first: usize, last: usize, n: usize) -> Vec<usize> {
    if first == last || n < 2 {
        return vec![first];
    }

    let mut points = Vec::with_capacity(n);
    points.push(first);

    let distance = (last - first) as u128;

    for i in 1..(n - 1) {
        points.push(first + ((distance * i as u128) / (n - 1) as u128) as usize);
    }

    points.push(last);

    points
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    pub use test_utils::random::{make_seedable_rng, Rng, Seed};

    use crate::pool::tx_pool::DescendantScore;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[test]
    fn test_generate_equidistant_span(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let first = rng.gen_range(0..100);
        let last = rng.gen_range(100..200);
        let n = rng.gen_range(0..10);

        eprintln!("testing {first} {last} {n}");
        let result = generate_equidistant_span(first, last, n);

        if first == last || n < 2 {
            assert_eq!(result.len(), 1);
            assert_eq!(result.first(), Some(&first));
        } else {
            assert_eq!(result.len(), n);
            assert_eq!(result.first(), Some(&first));
            assert_eq!(result.last(), Some(&last));

            // assert that the difference between elements is equal or off by 1
            let step = result[1] - result[0] + 1;
            for i in 1..(n - 1) {
                assert!(result[i] - result[i - 1] <= step);
            }
        }
    }

    #[test]
    fn test_linear_interpolation_exact_key() {
        let k1 = 0;
        let v1 = 10;
        let k2 = 10;
        let v2 = 100;
        let k3 = 5;

        assert_eq!(linear_interpolation((k1, v1), (k2, v2), k3), Some(55));
    }

    #[test]
    fn test_linear_interpolation_invalid_parameters() {
        // Same keys, invalid interpolation
        assert_eq!(linear_interpolation((1, 10), (1, 10), 3), None);
        assert_eq!(linear_interpolation((1, 10), (2, 20), 3), None);

        // k1 == k2 == k3, should return v1
        assert_eq!(linear_interpolation((1, 10), (1, 20), 1), Some(10));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[test]
    fn test_find_interpolated_value_exact_key(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut map = BTreeMap::new();
        for _ in 0..rng.gen_range(1..10) {
            map.insert(
                rng.gen::<usize>(),
                DescendantScore::new(FeeRate::from_atoms_per_kb(rng.gen_range(0..1_000_000))),
            );
        }

        // check that all keys can be found and the returned value is the same as the one in the
        // map
        for key in map.keys() {
            assert_eq!(
                find_interpolated_value::<DescendantScore>(&map, *key),
                map.get(key).cloned()
            );
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[test]
    fn test_find_interpolated_value_interpolation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut map = BTreeMap::new();
        let min = rng.gen_range(0..1_000_000);
        let max = rng.gen_range(min..2_000_000);

        map.insert(0, DescendantScore::new(FeeRate::from_atoms_per_kb(min)));
        map.insert(10, DescendantScore::new(FeeRate::from_atoms_per_kb(max)));

        assert_eq!(
            find_interpolated_value(&map, 5),
            Some(DescendantScore::new(FeeRate::from_atoms_per_kb(
                linear_interpolation((0_u64, min), (10, max), 5).unwrap()
            )))
        );
    }
}
