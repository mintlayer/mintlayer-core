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

#![allow(clippy::float_arithmetic)]

use common::primitives::time::Time;

/// Token bucket based rate limiter
///
/// See https://en.wikipedia.org/wiki/Token_bucket
#[derive(Debug)]
pub struct RateLimiter {
    rate: f64,
    tokens: f64,
    bucket: u32,
    last_time: Time,
}

impl RateLimiter {
    /// Construct new RateLimiter
    ///
    /// # Arguments
    /// `now` - Current time
    /// `rate` - Tokens per second
    /// `initial_tokens` - Token count after the start
    /// `bucket` - Bucket size
    pub fn new(now: Time, rate: f64, initial_tokens: u32, bucket: u32) -> Self {
        assert!(rate >= 0.0);
        assert!(initial_tokens <= bucket);
        assert!(bucket >= 1);
        RateLimiter {
            rate,
            tokens: initial_tokens.into(),
            bucket,
            last_time: now,
        }
    }

    /// Check if the new request is within the allowed rate at the current time (updating the state)
    ///
    /// # Arguments
    /// `now` - Current time
    pub fn accept(&mut self, now: Time) -> bool {
        let seconds = (now - self.last_time).unwrap_or_default().as_secs_f64();
        self.last_time = now;
        self.tokens = f64::min(self.tokens + self.rate * seconds, self.bucket.into());
        // Use a value slightly less than 1.0 to account for f64 rounding errors (makes unit testing easier)
        if self.tokens >= 0.99999 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;
