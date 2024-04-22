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

use randomness::Rng;
use test_utils::random::Seed;

use super::rolling_bloom_filter::RollingBloomFilter;

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_rolling_bloom_filter(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let mut filter = RollingBloomFilter::<u128>::new(100, 0.01, &mut rng);
    for i in 0..400 {
        filter.insert(&i, &mut rng);

        // Last 100 must be remembered, select random number from all recently added
        let num = rng.gen_range((i.saturating_sub(99))..=i);
        assert!(filter.contains(&num), "not found {num}, i: {i}");
    }

    // Last 100 guaranteed to be remembered
    for i in 300..400 {
        assert!(filter.contains(&i));
    }

    let mut fp = 0;
    for i in 400..10400 {
        if filter.contains(&i) {
            fp += 1;
        }
    }
    // Expect about 100 false positives (tests showed results in [26..142] range)
    assert!(fp > 10 && fp < 200, "invalid fp value: {fp}");
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_rolling_bloom_filter_2(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let mut filter = RollingBloomFilter::<u128>::new(1000, 0.001, &mut rng);
    for i in 0..2000 {
        filter.insert(&i, &mut rng);

        // Last 1000 must be remembered, select random number from all recently added
        let num = rng.gen_range((i.saturating_sub(999))..=i);
        assert!(filter.contains(&num), "not found {num}, i: {i}");
    }

    // Last 1000 guaranteed to be remembered
    for i in 1000..2000 {
        assert!(filter.contains(&i));
    }

    let mut fp = 0;
    for i in 2000..12000 {
        if filter.contains(&i) {
            fp += 1;
        }
    }
    // Expect about 10 false positives (tests showed results in [0..18] range)
    assert!(fp < 30, "invalid fp value: {fp}");
}
