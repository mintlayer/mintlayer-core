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

use super::*;

use crypto::random::rngs::StepRng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

mod exponential_rand {
    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_average_value(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let count = 1000;
        let sum: f64 = (0..count).map(|_| exponential_rand(&mut rng)).sum();
        let average = sum / count as f64;
        assert!(0.8 < average && average < 1.2);
    }

    #[test]
    fn expect_finite_values_in_degenerate_cases() {
        let mut always_zero_rng = StepRng::new(0, 0);
        let val = exponential_rand(&mut always_zero_rng);
        assert!(val.is_finite());

        let mut always_max_rng = StepRng::new(u64::MAX, 0);
        let val = exponential_rand(&mut always_max_rng);
        assert!(val.is_finite());
    }
}

mod choose_multiple_weighted {
    use super::*;

    // 1) Choosing an amount bigger than the number of available items should just return the items
    // in some order.
    // 2) Choosing a smaller amount should produce the correct number of items; the items' values
    // should be among those that were passed to the function.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let start_val = 0;
        let end_val = 100;
        let items_count = (end_val - start_val) as usize;
        let vals: Vec<i32> = (start_val..end_val).collect();
        let weights: Vec<f64> = (0..items_count)
            .map(|_| {
                let w = rng.gen();
                if w == 0.0 {
                    // Just make sure weights can't be zero.
                    0.000001
                } else {
                    w
                }
            })
            .collect();

        // Choose items_count items.
        let mut chosen = choose_multiple_weighted(
            vals.iter().copied().zip(weights.iter().copied()),
            &mut rng,
            items_count,
        );
        chosen.sort();
        assert_eq!(chosen, vals);

        // Choose items_count + 1 items.
        let mut chosen = choose_multiple_weighted(
            vals.iter().copied().zip(weights.iter().copied()),
            &mut rng,
            items_count + 1,
        );
        chosen.sort();
        assert_eq!(chosen, vals);

        // Choose items_count / 2 items.
        let count_to_choose = items_count / 2;
        let chosen = choose_multiple_weighted(
            vals.iter().copied().zip(weights.iter().copied()),
            &mut rng,
            count_to_choose,
        );
        assert_eq!(chosen.len(), count_to_choose);
        assert!(chosen.iter().all(|item| { *item >= start_val && *item < end_val }));
    }

    // Corner case - the iterator is empty.
    #[test]
    fn choose_from_zero_elements() {
        let mut rng = make_seedable_rng(Seed(123));

        let chosen: Vec<i32> = choose_multiple_weighted(std::iter::empty(), &mut rng, 0);
        assert!(chosen.is_empty());

        let chosen: Vec<i32> = choose_multiple_weighted(std::iter::empty(), &mut rng, 1);
        assert!(chosen.is_empty());
    }

    // Check that the items selection actually reflects their wights.
    // Note that this test can't be random, so we choose a predefined seed for it and repeat the
    // body several times.
    // The `use_small_weights` parameter makes the test use weights that are less then 1 to make
    // sure that only the ratio between the weights matters.
    #[rstest]
    fn values_test(#[values(true, false)] use_small_weights: bool) {
        let mut rng = make_seedable_rng(Seed(123));

        for _ in 0..3 {
            let start_val = 0;
            let end_val = 1000;
            let vals: Vec<i32> = (start_val..end_val).collect();

            let weight_divisor = if use_small_weights { 100.0 } else { 1.0 };
            let even_weight = 30.0 / weight_divisor;
            let odd_weight = 10.0 / weight_divisor;
            let expected_even_items_ratio = 0.7;
            let weights: Vec<f64> = vals
                .iter()
                .map(|val| {
                    if val % 2 == 0 {
                        even_weight
                    } else {
                        odd_weight
                    }
                })
                .collect();

            let mut total_items_count = 0;
            let mut total_even_items_count = 0;
            let iter_count = 100;

            for _ in 0..iter_count {
                let count_to_choose = rng.gen_range(50..100);
                let chosen = choose_multiple_weighted(
                    vals.iter().copied().zip(weights.iter().copied()),
                    &mut rng,
                    count_to_choose,
                );

                assert_eq!(chosen.len(), count_to_choose);
                let even_items_count = chosen.iter().filter(|val| *val % 2 == 0).count();

                total_items_count += count_to_choose;
                total_even_items_count += even_items_count;
            }

            assert!(
                total_even_items_count as f64
                    >= total_items_count as f64 * expected_even_items_ratio
            );
        }
    }
}
