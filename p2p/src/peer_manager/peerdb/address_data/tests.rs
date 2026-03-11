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

use rstest::rstest;
use strum::IntoEnumIterator as _;

use logging::log;
use randomness::{
    distributions::{Distribution, WeightedIndex},
    rngs::StepRng,
    seq::IteratorRandom as _,
    Rng,
};
use test_utils::random::{make_seedable_rng, Seed};

use super::*;

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn randomized(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let started_at = Time::from_duration_since_epoch(Duration::ZERO);

    let weights = [100, 100, 100, 100, 10, 10];
    let all_transition_tags = AddressStateTransitionToTag::iter().collect::<Vec<_>>();
    assert_eq!(weights.len(), all_transition_tags.len());
    let weights = WeightedIndex::new(weights).unwrap();

    for _ in 0..100 {
        let was_reachable = rng.gen_bool(0.2);
        let reserved = rng.gen_bool(0.1);

        let mut address_data = AddressData::new(was_reachable, reserved, started_at);

        for _ in 0..1000 {
            let transition_tag = all_transition_tags[weights.sample(&mut rng)];

            let transition = match transition_tag {
                AddressStateTransitionToTag::Connected => AddressStateTransitionTo::Connected {
                    peer_role: OutboundPeerRole::iter().choose(&mut rng).unwrap(),
                },
                AddressStateTransitionToTag::HasActivity => AddressStateTransitionTo::HasActivity,
                AddressStateTransitionToTag::Disconnected => AddressStateTransitionTo::Disconnected,
                AddressStateTransitionToTag::ConnectionFailed => {
                    AddressStateTransitionTo::ConnectionFailed
                }
                AddressStateTransitionToTag::SetReserved => AddressStateTransitionTo::SetReserved,
                AddressStateTransitionToTag::UnsetReserved => {
                    AddressStateTransitionTo::UnsetReserved
                }
            };

            let is_valid_transition = match transition {
                AddressStateTransitionTo::Connected { peer_role: _ } => {
                    !address_data.is_connected()
                }
                AddressStateTransitionTo::HasActivity => address_data.is_connected(),
                AddressStateTransitionTo::Disconnected => address_data.is_connected(),
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

#[tracing::instrument(skip(seed))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn reachable_reconnects(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let started_at = Time::from_secs_since_epoch(1600000000);
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
        now = (now + Duration::from_secs(60)).unwrap();
    }

    // Reachable addresses should be tried for reconnect for a long time
    let time_until_removed = (now - started_at).unwrap();
    assert_eq!(connection_attempts, PURGE_REACHABLE_FAIL_COUNT);
    let week = Duration::from_secs(3600 * 24 * 7);
    assert!(
        time_until_removed >= 2 * week && time_until_removed <= 6 * week,
        "invalid time until removed: {time_until_removed:?}"
    );
}

fn next_connect_time_test_impl(rng: &mut impl Rng) {
    let limit_reserved = MAX_DELAY_RESERVED * MAX_DELAY_FACTOR;
    let limit_reachable = MAX_DELAY_REACHABLE * MAX_DELAY_FACTOR;

    let start_time = Time::from_secs_since_epoch(0);
    let max_time_reserved = (start_time + limit_reserved).unwrap();
    let max_time_reachable = (start_time + limit_reachable).unwrap();

    for fail_count in [0, u32::MAX] {
        for connections_without_activity_count in [0, u32::MAX] {
            log::debug!("fail_count = {fail_count}, connections_without_activity_count = {connections_without_activity_count}");

            let time = AddressData::next_connect_time(
                start_time,
                fail_count,
                connections_without_activity_count,
                true,
                rng,
            );
            assert!(time <= max_time_reserved);

            let time = AddressData::next_connect_time(
                start_time,
                fail_count,
                connections_without_activity_count,
                false,
                rng,
            );
            assert!(time <= max_time_reachable);
        }
    }
}

#[test]
fn next_connect_time() {
    let mut always_zero_rng = StepRng::new(0, 0);
    next_connect_time_test_impl(&mut always_zero_rng);

    let mut always_max_rng = StepRng::new(u64::MAX, 0);
    next_connect_time_test_impl(&mut always_max_rng);
}
