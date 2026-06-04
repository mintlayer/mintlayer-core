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

use randomness::{Rng, RngExt as _, distributions::Open01};

/// Returns a value sampled from an exponential distribution with a mean of 1.0.
///
/// The result will be in the range (0, max], where max = -ln(f64::EPSILON/2) ~= 36.7368.
pub fn exponential_rand(rng: &mut impl Rng) -> f64 {
    // This generates a number uniformly distributed in (0, 1) and having the form `n * ε + ε/2`,
    // where n is a 52-bit number and ε is f64::EPSILON, which is roughly 1/2^52.
    let random_f64: f64 = rng.sample(Open01);

    #[allow(clippy::float_arithmetic)]
    -random_f64.ln()
}

/// `exponential_rand` will always return values smaller than this.
///
/// This is mainly intended for testing.
pub const EXPONENTIAL_RAND_UPPER_LIMIT: u32 = 37;

#[cfg(test)]
mod test;
