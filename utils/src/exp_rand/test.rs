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

use rstest::rstest;

use test_utils::random::{Seed, StepRng, make_seedable_rng};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_average_value(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let count = 1000;
    let sum: f64 = (0..count)
        .map(|_| {
            let val = exponential_rand(&mut rng);
            assert!(val < EXPONENTIAL_RAND_UPPER_LIMIT as f64);
            val
        })
        .sum();
    let average = sum / count as f64;
    assert!(0.8 < average && average < 1.2);
}

#[test]
fn expect_finite_values_in_degenerate_cases() {
    let mut always_zero_rng = StepRng::new(0, 0);
    let val = exponential_rand(&mut always_zero_rng);
    assert!(val.is_finite());
    assert!(val < EXPONENTIAL_RAND_UPPER_LIMIT as f64);

    let mut always_max_rng = StepRng::new(u64::MAX, 0);
    let val = exponential_rand(&mut always_max_rng);
    assert!(val.is_finite());
    assert!(val < EXPONENTIAL_RAND_UPPER_LIMIT as f64);
}
