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

fn run_test(seconds: u32, rate: f64, initial_tokens: u32, bucket: u32, expected: u32) {
    let now = Duration::from_secs(0);
    let mut rate_limiter = RateLimiter::new(now, rate, initial_tokens, bucket);
    let mut actual = 0;
    for i in 0..=seconds {
        let now = Duration::from_secs(i.into());
        while rate_limiter.accept(now) {
            actual += 1;
        }
        // Check that RateLimiter is consistent
        assert!(!rate_limiter.accept(now));
    }
    assert_eq!(
        actual, expected,
        "test failed, seconds: {seconds}, rate: {rate}, initial_tokens: {initial_tokens}, bucket: {bucket}, actual: {actual}, expected: {expected}"
    );
}

#[test]
fn rate_limiter_basic() {
    // expected = seconds * rate + initial_bucket (normal fill rate)
    run_test(120, 0.1, 0, 10, 12);
    run_test(120, 1.0, 0, 10, 120);
    run_test(120, 0.1, 10, 10, 22);
    run_test(120, 1.0, 20, 20, 140);
    run_test(120, 3.0, 0, 10, 360);
    run_test(120, 10.0, 40, 40, 1240);

    // expected = seconds * bucket (rate is limited by the bucket size)
    run_test(60, 10.0, 0, 3, 180);
    run_test(120, 100.0, 0, 5, 600);
}
