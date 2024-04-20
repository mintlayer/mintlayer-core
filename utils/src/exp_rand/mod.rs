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

/// Returns a value sampled from an exponential distribution with a mean of 1.0
pub fn exponential_rand(rng: &mut impl Rng) -> f64 {
    let mut random_f64 = rng.gen::<f64>();
    // The generated number will be in the range [0, 1). Turn it into (0, 1) to avoid
    // infinity when taking the logarithm.
    if random_f64 == 0.0 {
        random_f64 = f64::MIN_POSITIVE;
    }

    #[allow(clippy::float_arithmetic)]
    -random_f64.ln()
}

#[cfg(test)]
mod test;
