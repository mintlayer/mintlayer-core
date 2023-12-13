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
use std::collections::BTreeMap;

pub fn get_closest_value<V: Copy>(size_to_score: &BTreeMap<usize, V>, key: usize) -> Option<V> {
    match (
        size_to_score.range(..=key).next_back(),
        size_to_score.range(key..).next(),
    ) {
        (Some((&k1, &v1)), Some((&k2, &v2))) => {
            let diff1 = key - k1;
            let diff2 = k2 - key;

            if diff1 <= diff2 {
                Some(v1)
            } else {
                Some(v2)
            }
        }
        (Some((_, &v1)), None) => Some(v1),
        (None, Some((_, &v2))) => Some(v2),
        (None, None) => None,
    }
}

// Generate equidistant points to evaluate the mathematical function at for interpolation
pub fn generate_equidistant_span(first: usize, last: usize, n: usize) -> Vec<usize> {
    if first == last || n < 2 {
        return vec![first];
    }

    let mut points = Vec::with_capacity(n);
    points.push(first);

    let step = (last - first) / (n - 1);

    for i in 1..(n - 1) {
        points.push(first + step * i);
    }

    points.push(last);

    points
}

#[cfg(test)]
mod tests {
    use crypto::random::distributions::Standard;
    use rstest::rstest;
    pub use test_utils::random::{make_seedable_rng, CryptoRng, Rng, Seed};

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

            // Assert that the difference between elements is equal in the entire array except for the
            // last element
            let step = result[1] - result[0];
            for i in 1..(n - 1) {
                assert_eq!(result[i] - result[i - 1], step);
            }
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[test]
    fn test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut size_to_score = BTreeMap::new();

        for _ in 0..rng.gen_range(0..10) {
            size_to_score.insert(rng.gen::<usize>(), rng.gen::<u32>());
        }

        let key = rng.gen_range(
            *size_to_score.keys().next().unwrap()..*size_to_score.keys().last().unwrap(),
        );

        let result = get_closest_value(&size_to_score, key);

        if size_to_score.is_empty() {
            assert!(result.is_none());
        } else {
            assert!(result.is_some());
        }

        if let Some(value) = result {
            let (selected_key, selected_value) =
                size_to_score.iter().find(|&(_, &v)| v == value).unwrap();
            assert_eq!(*selected_value, value);

            // Get the previous and next keys from the BTreeMap
            let prev_key = size_to_score.range(..selected_key).next_back().map(|(&k, _)| k);
            let next_key = size_to_score.range(selected_key..).skip(1).next().map(|(&k, _)| k);

            // Check the differences between the selected key and the previous and next keys
            if let Some(prev) = prev_key {
                if *selected_key <= key {
                    assert!(key - prev >= key - *selected_key);
                } else if prev > key {
                    assert!(prev - key >= *selected_key - key);
                } else {
                    assert!(key - prev >= *selected_key - key);
                }
            }

            if let Some(next) = next_key {
                if *selected_key >= key {
                    assert!(next - key >= *selected_key - key);
                } else if next < key {
                    assert!(key - next >= key - *selected_key);
                } else {
                    assert!(next - key >= key - *selected_key);
                }
            }
        }
    }
}
