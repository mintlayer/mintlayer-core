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
    let started_at = Duration::ZERO;

    let weights = [100, 100, 100, 100, 10, 10];
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
                AddressStateTransitionTo::DisconnectedByUser => address_data.is_connected(),
                AddressStateTransitionTo::ConnectionFailed => !address_data.is_connected(),
                AddressStateTransitionTo::SetReserved => true,
                AddressStateTransitionTo::UnsetReserved => true,
            };

            if is_valid_transition {
                address_data.transition_to(transition, started_at, &mut rng);
            }
        }
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reachable_reconnects(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let started_at = Duration::from_secs(1600000000);
    let mut now = started_at;
    let mut address = AddressData::new(true, false, started_at);
    let mut connection_attempts = 0;

    loop {
        if address.is_unreachable() {
            break;
        }
        if address.connect_now(now) {
            address.transition_to(AddressStateTransitionTo::ConnectionFailed, now, &mut rng);
            connection_attempts += 1;
        }
        now += Duration::from_secs(60);
    }

    // Reachable addresses should be tried for reconnect for a long time
    let time_until_removed = now - started_at;
    assert_eq!(connection_attempts, PURGE_REACHABLE_FAIL_COUNT);
    let week = Duration::from_secs(3600 * 24 * 7);
    assert!(
        time_until_removed >= 2 * week && time_until_removed <= 6 * week,
        "invalid time until removed: {time_until_removed:?}"
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), AddressStateTransitionTo::DisconnectedByUser, false)]
#[case(Seed::from_entropy(), AddressStateTransitionTo::Disconnected, true)]
fn no_reconnects_after_manual_disconnect(
    #[case] seed: Seed,
    #[case] reason: AddressStateTransitionTo,
    #[case] expected_reconnect: bool,
) {
    let mut rng = make_seedable_rng(seed);
    let now = Duration::from_secs(1600000000);

    let mut address = AddressData::new(true, false, now);
    address.transition_to(AddressStateTransitionTo::Connected, now, &mut rng);
    address.transition_to(reason, now, &mut rng);
    let reconnect = address.connect_now(now + Duration::from_secs(100 * 24 * 3600));
    // Test that there are no reconnection attempts to peers that were disconnected by RPC
    assert_eq!(reconnect, expected_reconnect);
}
