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

use std::time::Duration;

use common::primitives::time::Time;
use randomness::Rng;

/// Maximum delay between reconnection attempts to reserved nodes
const MAX_DELAY_RESERVED: Duration = Duration::from_secs(360);

/// Maximum delay between reconnection attempts to previously reachable nodes
pub const MAX_DELAY_REACHABLE: Duration = Duration::from_secs(3600);

/// When the node drops the unreachable node address. Used for negative caching.
pub const PURGE_UNREACHABLE_TIME: Duration = Duration::from_secs(3600);

/// When the server drops the unreachable node address that was once reachable. This should take about a month.
/// Such a long time is useful if the node itself has prolonged connectivity problems.
const PURGE_REACHABLE_TIME: Duration = Duration::from_secs(3600 * 24 * 7 * 4);

// TODO: this is 672 currently, which is too much.
pub const PURGE_REACHABLE_FAIL_COUNT: u32 =
    (PURGE_REACHABLE_TIME.as_secs() / MAX_DELAY_REACHABLE.as_secs()) as u32;

/// The maximum value for the random factor by which reconnection delays will be multiplied.
///
/// Note that the value was chosen based on bitcoin's implementation of GetExponentialRand
/// (https://github.com/bitcoin/bitcoin/blob/5bbf735defac20f58133bea95226e13a5d8209bc/src/random.cpp#L689)
/// which they use to scale delays. In their implementation, the maximum scale factor will be
/// -ln(0.0000000000000035527136788) which is about 33.
const MAX_DELAY_FACTOR: u32 = 30;

#[derive(Debug, Clone)]
pub enum AddressState {
    Connected {},

    Disconnected {
        /// Whether the address was reachable at least once.
        /// Addresses that were once reachable are stored in the DB.
        was_reachable: bool,

        /// The number of consecutive failed connection attempts.
        /// New connection attempts are made after a progressive backoff time.
        fail_count: u32,

        /// Next time connect to the peer
        next_connect_after: Time,
    },

    Unreachable {
        /// At which time the address would be removed from memory
        erase_after: Time,
    },
}

#[derive(Copy, Clone, Debug)]
// Update `ALL_TRANSITIONS` if a new transition is added!
pub enum AddressStateTransitionTo {
    Connected,
    Disconnected,
    ConnectionFailed,
    SetReserved,
    UnsetReserved,
}

#[cfg(test)]
pub const ALL_TRANSITIONS: [AddressStateTransitionTo; 5] = [
    AddressStateTransitionTo::Connected,
    AddressStateTransitionTo::Disconnected,
    AddressStateTransitionTo::ConnectionFailed,
    AddressStateTransitionTo::SetReserved,
    AddressStateTransitionTo::UnsetReserved,
];

#[derive(Debug)]
pub struct AddressData {
    state: AddressState,

    reserved: bool,
}

impl AddressData {
    pub fn new(was_reachable: bool, reserved: bool, now: Time) -> Self {
        AddressData {
            state: AddressState::Disconnected {
                was_reachable,
                fail_count: 0,
                next_connect_after: now,
            },
            reserved,
        }
    }

    pub fn state(&self) -> &AddressState {
        &self.state
    }

    pub fn reserved(&self) -> bool {
        self.reserved
    }

    /// Returns true when it is time to attempt a new outbound connection
    pub fn connect_now(&self, now: Time) -> bool {
        match self.state {
            AddressState::Connected {} => false,

            // Once a peer is disconnected by the RPC command, it should remain disconnected
            // (at least until the RPC requests to connect). Otherwise, users may be surprised
            // to see the peer reconnect after some time (and may break functional tests).
            AddressState::Disconnected {
                fail_count: _,
                next_connect_after,
                was_reachable: _,
            } => now >= next_connect_after,

            AddressState::Unreachable { erase_after: _ } => false,
        }
    }

    /// Returns true if the address should be kept in memory
    pub fn retain(&self, now: Time) -> bool {
        match self.state {
            AddressState::Connected {} => true,
            AddressState::Disconnected {
                was_reachable: _,
                fail_count: _,
                next_connect_after: _,
            } => true,
            AddressState::Unreachable { erase_after } => erase_after > now,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, AddressState::Connected { .. })
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self.state, AddressState::Unreachable { .. })
    }

    fn next_connect_delay(fail_count: u32, reserved: bool) -> Duration {
        let max_delay = if reserved {
            MAX_DELAY_RESERVED
        } else {
            MAX_DELAY_REACHABLE
        };

        // 10, 20, 40, 80... seconds
        std::cmp::min(
            Duration::from_secs(10).saturating_mul(2u32.saturating_pow(fail_count)),
            max_delay,
        )
    }

    fn next_connect_time(now: Time, fail_count: u32, reserved: bool, rng: &mut impl Rng) -> Time {
        let factor = utils::exp_rand::exponential_rand(rng).clamp(0.0, MAX_DELAY_FACTOR as f64);
        let offset = Self::next_connect_delay(fail_count, reserved).mul_f64(factor);
        (now + offset).expect("Unexpected time addition overflow")
    }

    pub fn transition_to(
        &mut self,
        transition: AddressStateTransitionTo,
        now: Time,
        rng: &mut impl Rng,
    ) {
        self.state = match transition {
            AddressStateTransitionTo::Connected => match self.state {
                AddressState::Connected {} => unreachable!(),
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                } => AddressState::Connected {},
                AddressState::Unreachable { erase_after: _ } => {
                    // Connection to an `Unreachable` node may be requested by RPC at any moment
                    AddressState::Connected {}
                }
            },

            AddressStateTransitionTo::Disconnected => match self.state {
                AddressState::Connected {} => AddressState::Disconnected {
                    fail_count: 0,
                    next_connect_after: Self::next_connect_time(now, 0, self.reserved, rng),
                    was_reachable: true,
                },
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                } => unreachable!(),
                AddressState::Unreachable { erase_after: _ } => unreachable!(),
            },

            AddressStateTransitionTo::ConnectionFailed => match self.state {
                AddressState::Connected {} => unreachable!(),
                AddressState::Disconnected {
                    fail_count,
                    next_connect_after: _,
                    was_reachable,
                } => {
                    if self.reserved {
                        AddressState::Disconnected {
                            fail_count: fail_count + 1,
                            next_connect_after: Self::next_connect_time(
                                now,
                                fail_count + 1,
                                self.reserved,
                                rng,
                            ),
                            was_reachable,
                        }
                    } else if !was_reachable {
                        AddressState::Unreachable {
                            erase_after: (now + PURGE_UNREACHABLE_TIME)
                                .expect("Overflow in PURGE_UNREACHABLE_TIME"),
                        }
                    } else if fail_count + 1 >= PURGE_REACHABLE_FAIL_COUNT {
                        AddressState::Unreachable { erase_after: now }
                    } else {
                        AddressState::Disconnected {
                            fail_count: fail_count + 1,
                            next_connect_after: Self::next_connect_time(
                                now,
                                fail_count + 1,
                                self.reserved,
                                rng,
                            ),
                            was_reachable,
                        }
                    }
                }
                AddressState::Unreachable { erase_after } => {
                    // Connection to an `Unreachable` node may be requested by RPC at any moment
                    AddressState::Unreachable { erase_after }
                }
            },

            AddressStateTransitionTo::SetReserved => {
                self.reserved = true;

                // Change to Disconnected if currently Unreachable
                match self.state {
                    AddressState::Connected {} => AddressState::Connected {},
                    AddressState::Disconnected {
                        was_reachable,
                        fail_count,
                        next_connect_after: _,
                    } => AddressState::Disconnected {
                        was_reachable,
                        fail_count,
                        next_connect_after: Self::next_connect_time(
                            now,
                            fail_count,
                            self.reserved,
                            rng,
                        ),
                    },
                    // Reserved nodes should not be in the `Unreachable` state
                    AddressState::Unreachable { erase_after: _ } => AddressState::Disconnected {
                        fail_count: 0,
                        next_connect_after: Self::next_connect_time(now, 0, self.reserved, rng),
                        was_reachable: false,
                    },
                }
            }

            AddressStateTransitionTo::UnsetReserved => {
                self.reserved = false;

                // Do not change the state
                match self.state {
                    AddressState::Connected {} => AddressState::Connected {},
                    AddressState::Disconnected {
                        was_reachable,
                        fail_count,
                        next_connect_after,
                    } => AddressState::Disconnected {
                        was_reachable,
                        fail_count,
                        next_connect_after,
                    },
                    AddressState::Unreachable { erase_after } => {
                        AddressState::Unreachable { erase_after }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
