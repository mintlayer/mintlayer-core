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

use crypto::random::{
    distributions::{Distribution, WeightedIndex},
    Rng,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::*;

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let started_at = Instant::now();

    let weights = [100, 100, 100, 10, 10];
    assert_eq!(weights.len(), ALL_TRANSITIONS.len());
    let weights = WeightedIndex::new(weights).unwrap();

    for _ in 0..100 {
        let was_reachable = rng.gen_bool(0.2);
        let reserved = rng.gen_bool(0.1);

        let mut address_data = AddressData::new(was_reachable, reserved, started_at);

        for _ in 0..1000 {
            let transition = ALL_TRANSITIONS[weights.sample(&mut rng)];

            let is_valid_transition = match transition {
                AddressStateTransitionTo::Connected => !address_data.is_connected(),
                AddressStateTransitionTo::Disconnected => address_data.is_connected(),
                AddressStateTransitionTo::ConnectionFailed => !address_data.is_connected(),
                AddressStateTransitionTo::SetReserved => true,
                AddressStateTransitionTo::UnsetReserved => true,
            };

            if is_valid_transition {
                address_data.transition_to(transition, started_at);
            }
        }
    }
}
