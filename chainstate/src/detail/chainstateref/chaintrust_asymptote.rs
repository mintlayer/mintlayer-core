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

use mockall::lazy_static;

/// An asymptote that with its limit to infinity, reaches the value one.
/// The function is normalized so that the limit as t goes to infinity is one.
///
/// Creation:
/// This function is created by integrating the function `alpha * exp(-alpha * x) dx` from 0 to t.
/// The parameter alpha controls the steepness of the curve; i.e., how fast the function converges.
///
/// Benefits:
/// This function is to be used to compute the accumulated trust of a chain for chain selection.
/// Having an asymptotic function that tends to one means that no matter how many empty time-slots
/// are in the chain, the weight will always be less than one, which is the weight of a single block.
/// This function can be used to programmatically prefer chains that have denser blocks in time.
fn asymptote_to_infinity_to_one<F>(t: u64, alpha: F) -> F
where
    F: num::Float + num::cast::FromPrimitive,
{
    let t = F::from_u64(t).expect("Cannot fail to convert u64 to F");
    let one = F::from_u64(1).expect("Cannot fail to create 1 as F");
    one - (-alpha * t).exp()
}

// The value of alpha, 0.025, is chosen such that when a block time is hit (120 seconds), there's 5% of the range of the asymptote left.
const ALPHA: f64 = 0.025;

// We scale the weights by this factor to ensure that they are resolvable as integers, to avoid using floating-point numbers.
const SCALING_FACTOR: f64 = 1000000000.;

// The size of the precomputed weights
const VEC_SIZE: u64 = 240;

fn precompute_asymptote_to_infinity_to_one<F>(alpha: F, size: u64) -> Vec<F>
where
    F: num::Float + num::cast::FromPrimitive,
{
    (0..size).map(|t| asymptote_to_infinity_to_one(t, alpha)).collect()
}

lazy_static! {
    static ref TIMESLOTS_WEIGHTS: Vec<f64> =
        precompute_asymptote_to_infinity_to_one(ALPHA, VEC_SIZE);
}

// A look-up table for the weights of the time-slots.
pub fn get_weight_for_timeslot(timeslot: u64) -> u64 {
    let timeslot = timeslot as usize;

    #[allow(clippy::float_arithmetic)]
    if timeslot >= TIMESLOTS_WEIGHTS.len() {
        // This is basically 1 times the scaling factor (minus epsilon), where the other branch has everything < 1
        // We subtract epsilon (smallest positive value) to ensure that blocks, no matter with how many slots, will have a weight > 0
        SCALING_FACTOR as u64 - 1
    } else {
        (TIMESLOTS_WEIGHTS[timeslot] * SCALING_FACTOR) as u64
    }
}

pub fn get_weight_for_block() -> u64 {
    SCALING_FACTOR as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_weight_is_zero() {
        assert_eq!(get_weight_for_timeslot(0), 0);
    }

    #[test]
    fn weight_at_infinity_is_one() {
        let t = 100000000; // a really large value
        let weight = asymptote_to_infinity_to_one(t, ALPHA);
        assert_eq!(weight, 1.);
    }

    #[test]
    fn int_conversion() {
        // In this test, we ensure that the scaling factor, combined with alpha, is large enough to ensure
        // that the weights are resolvable as integers.

        let int_weights = TIMESLOTS_WEIGHTS
            .iter()
            .map(|v| (v * SCALING_FACTOR) as u64)
            .collect::<Vec<_>>();

        let diffs = int_weights
            .iter()
            .zip(int_weights.iter().skip(1))
            .map(|(a, b)| b - a)
            .collect::<Vec<_>>();

        // Differences between every value and the next one should be positive, otherwise the weights are not resolvable as integers.
        assert!(
            diffs.iter().all(|v| *v > 0),
            "The weights be resolvable as integers after scaling"
        );
    }

    #[test]
    fn final_weights_resolvable() {
        let int_weights = (0..(VEC_SIZE as usize))
            .map(|t| get_weight_for_timeslot(t as u64))
            .collect::<Vec<_>>();

        let diffs = int_weights
            .iter()
            .zip(int_weights.iter().skip(1))
            .map(|(a, b)| b - a)
            .collect::<Vec<_>>();

        // Differences between every value and the next one should be positive, otherwise the weights are not resolvable as integers.
        assert!(
            diffs.iter().all(|v| *v > 0),
            "The weights be resolvable as integers after scaling"
        );
    }
}
