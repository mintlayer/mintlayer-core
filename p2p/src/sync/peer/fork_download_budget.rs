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

//! A per-peer budget limiting the amount of block downloads that announced headers can
//! trigger.
//!
//! Downloading and validating block bodies is expensive. The peer synchronization manager
//! already limits how many blocks can be requested at once, but that does not bound the
//! total amount of work a peer can cause over time: a peer that keeps announcing header
//! lists can, in principle, make us download and process an unlimited number of blocks,
//! one bounded request at a time.
//!
//! This budget bounds that cumulative work: every header list a peer sends us consumes
//! tokens from the peer's bucket; when the bucket is empty, further header lists are
//! deferred (with no error and no ban score) until tokens are refilled. The budget is not
//! spent during the initial block download, so that node bootstrap cannot be stalled.
//! Honest announcement traffic is tiny compared to the budget capacity (a few headers per
//! newly produced block), so regular block propagation is unaffected.

use std::time::Duration;

use common::primitives::time::Time;

#[derive(Debug, Clone)]
pub struct ForkDownloadBudget {
    /// Total number of tokens (block downloads) the bucket can hold.
    capacity: u64,
    /// How often the full capacity is refilled.
    refill_interval: Duration,
    /// Currently available tokens.
    tokens: u64,
    /// Time at which the last refill (partial or full) happened.
    last_refill: Time,
}

impl ForkDownloadBudget {
    pub fn new(capacity: usize, refill_interval: Duration, now: Time) -> Self {
        let capacity = capacity as u64;
        Self {
            capacity,
            refill_interval,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Time) {
        if self.tokens >= self.capacity {
            self.last_refill = now;
            return;
        }

        let interval_secs = self.refill_interval.as_secs();
        if interval_secs == 0 {
            // Degenerate configuration: refill instantly.
            self.tokens = self.capacity;
            self.last_refill = now;
            return;
        }

        let elapsed = now.saturating_sub(self.last_refill);
        // Tokens gained since the last refill. Use u128 to avoid overflow for very long
        // elapsed times.
        let gained = (elapsed.as_secs() as u128)
            .checked_mul(self.capacity as u128)
            .and_then(|v| v.checked_div(interval_secs as u128))
            .unwrap_or(u128::MAX);

        if gained == 0 {
            return;
        }

        // Advance the refill time by the amount of time that corresponds to the granted
        // tokens, so that remainders are not lost across calls.
        let granted = gained.min(u64::MAX as u128) as u64;
        self.tokens = self.tokens.saturating_add(granted).min(self.capacity);
        let consumed_secs = (granted as u128)
            .checked_mul(interval_secs as u128)
            .and_then(|v| v.checked_div(self.capacity as u128))
            .unwrap_or(0);
        self.last_refill = self
            .last_refill
            .saturating_duration_add(Duration::from_secs(consumed_secs as u64));
    }

    /// Try to consume `amount` tokens at time `now`. Returns `false` if the budget is
    /// exhausted, in which case nothing is consumed.
    pub fn try_take(&mut self, amount: usize, now: Time) -> bool {
        self.refill(now);

        if self.tokens >= amount as u64 {
            self.tokens -= amount as u64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use common::primitives::time::Time;

    use super::*;

    fn t(secs: u64) -> Time {
        Time::from_secs_since_epoch(secs)
    }

    #[test]
    fn starts_full() {
        let mut budget = ForkDownloadBudget::new(10, Duration::from_secs(100), t(0));
        assert!(budget.try_take(10, t(0)));
        assert!(!budget.try_take(1, t(0)));
    }

    #[test]
    fn exhausts_and_refills_over_time() {
        // Rate: 10 tokens per 100 seconds.
        let mut budget = ForkDownloadBudget::new(10, Duration::from_secs(100), t(0));
        assert!(budget.try_take(10, t(0)));
        // No time passed - nothing to refill.
        assert!(!budget.try_take(1, t(0)));
        // Half of the interval passed - half of the capacity refilled.
        assert!(budget.try_take(5, t(50)));
        assert!(!budget.try_take(1, t(50)));
        // Another half of the interval passed - another half of the capacity refilled.
        assert!(budget.try_take(5, t(100)));
        assert!(!budget.try_take(6, t(100)));
        // At t(150) the bucket holds another 5 tokens, i.e. it has been refilled at a
        // constant rate all along.
        assert!(budget.try_take(5, t(150)));
        assert!(!budget.try_take(1, t(150)));
    }

    #[test]
    fn remainders_are_not_lost() {
        // 4 tokens per 8 seconds => 0.5 tokens per second. Frequent small calls must
        // accumulate fractional refills instead of discarding them.
        let mut budget = ForkDownloadBudget::new(4, Duration::from_secs(8), t(0));
        assert!(budget.try_take(4, t(0)));
        // After 1 second only 0.5 tokens have accumulated - not enough.
        assert!(!budget.try_take(1, t(1)));
        // After 2 seconds a whole token has accumulated.
        assert!(budget.try_take(1, t(2)));
        assert!(!budget.try_take(1, t(3)));
        // After 4 seconds, another token has accumulated.
        assert!(budget.try_take(1, t(4)));
        assert!(!budget.try_take(1, t(5)));
        // And so on at a constant 0.5 tokens per second.
        assert!(budget.try_take(1, t(6)));
        assert!(!budget.try_take(1, t(7)));
    }

    #[test]
    fn overdraw_is_rejected_atomically() {
        let mut budget = ForkDownloadBudget::new(10, Duration::from_secs(100), t(0));
        assert!(!budget.try_take(11, t(0)));
        // The rejected request must not consume anything.
        assert!(budget.try_take(10, t(0)));
    }

    #[test]
    fn zero_interval_refills_instantly() {
        let mut budget = ForkDownloadBudget::new(10, Duration::from_secs(0), t(0));
        assert!(budget.try_take(10, t(0)));
        assert!(budget.try_take(10, t(0)));
    }

    #[test]
    fn time_going_backwards_is_safe() {
        let mut budget = ForkDownloadBudget::new(10, Duration::from_secs(100), t(1000));
        assert!(budget.try_take(10, t(1000)));
        // Refill time in the future: saturating arithmetic must not panic nor over-refill.
        assert!(!budget.try_take(1, t(0)));
    }
}
