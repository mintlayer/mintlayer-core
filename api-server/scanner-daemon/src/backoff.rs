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

//! The exponential backoff used between the attempts to (re-)establish the connection to the
//! node: the delay starts at a configured value, doubles on every attempt up to a configured
//! maximum, and is jittered by up to ±20% so that a group of clients does not retry in
//! lock-step. A successful connection resets the schedule.

use std::time::Duration;

use randomness::{Rng, RngExt as _};

/// The relative jitter applied to every delay: the actual delay is in
/// `[delay * (1 - JITTER), delay * (1 + JITTER)]`.
const JITTER: f64 = 0.2;

/// The exponential backoff schedule between connection attempts.
#[derive(Debug)]
pub struct ReconnectBackoff {
    initial_delay: Duration,
    max_delay: Duration,
    /// The delay for the next attempt, before the jitter is applied; it doubles on every call
    /// to [`Self::next_delay`], up to [`Self::max_delay`].
    next_delay: Duration,
}

impl ReconnectBackoff {
    /// Creates a new schedule; `initial_delay` and `max_delay` must be non-zero.
    pub fn new(initial_delay: Duration, max_delay: Duration) -> Self {
        assert_ne!(
            initial_delay,
            Duration::ZERO,
            "The initial delay must not be zero"
        );
        assert_ne!(
            max_delay,
            Duration::ZERO,
            "The maximum delay must not be zero"
        );
        assert!(
            max_delay >= initial_delay,
            "The maximum delay ({max_delay:?}) must not be smaller than the initial delay \
            ({initial_delay:?})"
        );

        Self {
            initial_delay,
            max_delay,
            next_delay: initial_delay,
        }
    }

    /// Restarts the schedule from the beginning; to be called after a successful connection.
    pub fn reset(&mut self) {
        self.next_delay = self.initial_delay;
    }

    /// Returns the delay to wait before the next connection attempt and advances the schedule
    /// (doubling it, up to the maximum). The returned delay is jittered by ±[`JITTER`], so the
    /// returned value can exceed `max_delay` by up to 20%.
    pub fn next_delay(&mut self, rng: &mut impl Rng) -> Duration {
        let base_delay = self.next_delay;
        self.next_delay = std::cmp::min(base_delay * 2, self.max_delay);
        apply_jitter(base_delay, rng)
    }
}

/// Jitter the given delay by a uniformly random factor in `[1 - JITTER, 1 + JITTER]`.
fn apply_jitter(delay: Duration, rng: &mut impl Rng) -> Duration {
    let jitter_fraction = rng.random_range(-JITTER..=JITTER);
    delay.mul_f64(1.0 + jitter_fraction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::random::{Seed, make_seedable_rng};

    const INITIAL_DELAY: Duration = Duration::from_secs(1);
    const MAX_DELAY: Duration = Duration::from_secs(60);

    fn jitter_bounds(delay: Duration) -> (Duration, Duration) {
        (delay.mul_f64(1.0 - JITTER), delay.mul_f64(1.0 + JITTER))
    }

    #[track_caller]
    fn assert_in_bounds(actual: Duration, expected_base: Duration) {
        let (min, max) = jitter_bounds(expected_base);
        assert!(
            actual >= min && actual <= max,
            "Delay {actual:?} is out of the jittered bounds of the base delay {expected_base:?} \
            ({min:?}..{max:?})"
        );
    }

    #[test]
    fn delays_grow_exponentially_up_to_the_maximum() {
        let mut rng = make_seedable_rng(Seed::from_entropy());
        let mut backoff = ReconnectBackoff::new(INITIAL_DELAY, MAX_DELAY);

        // The base delay doubles on every attempt: 1s, 2s, 4s, ..., capped at 60s.
        for expected_base in [1, 2, 4, 8, 16, 32, 60, 60, 60] {
            let actual = backoff.next_delay(&mut rng);
            assert_in_bounds(actual, Duration::from_secs(expected_base));
        }
    }

    #[test]
    fn jitter_is_bounded() {
        let mut rng = make_seedable_rng(Seed::from_entropy());
        let mut backoff = ReconnectBackoff::new(MAX_DELAY, MAX_DELAY);

        for _ in 0..1000 {
            let delay = backoff.next_delay(&mut rng);
            // The base delay is always the maximum here, so the jitter must never leave
            // [0.8 * max, 1.2 * max].
            assert_in_bounds(delay, MAX_DELAY);
        }
    }

    #[test]
    fn reset_restarts_the_schedule() {
        let mut rng = make_seedable_rng(Seed::from_entropy());
        let mut backoff = ReconnectBackoff::new(INITIAL_DELAY, MAX_DELAY);

        for _ in 0..10 {
            backoff.next_delay(&mut rng);
        }

        // A successful connection resets the schedule, so the next delay must be the initial
        // one (plus jitter) again.
        backoff.reset();
        assert_in_bounds(backoff.next_delay(&mut rng), INITIAL_DELAY);
    }

    #[test]
    fn delays_never_collapse_to_zero() {
        let mut rng = make_seedable_rng(Seed::from_entropy());
        let mut backoff = ReconnectBackoff::new(Duration::from_millis(10), Duration::from_secs(1));

        for _ in 0..100 {
            assert!(backoff.next_delay(&mut rng) > Duration::ZERO);
        }
    }
}
