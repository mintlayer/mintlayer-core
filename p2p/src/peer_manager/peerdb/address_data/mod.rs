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

use crypto::random::Rng;

/// Maximum delay between reconnection attempts to reserved nodes
const MAX_DELAY_RESERVED: Duration = Duration::from_secs(360);

/// Maximum delay between reconnection attempts to previously reachable nodes
const MAX_DELAY_REACHABLE: Duration = Duration::from_secs(3600);

/// When the node drops the unreachable node address. Used for negative caching.
const PURGE_UNREACHABLE_TIME: Duration = Duration::from_secs(3600);

/// When the server drops the unreachable node address that was once reachable. This should take about a month.
/// Such a long time is useful if the node itself has prolonged connectivity problems.
const PURGE_REACHABLE_TIME: Duration = Duration::from_secs(3600 * 24 * 7 * 4);

const PURGE_REACHABLE_FAIL_COUNT: u32 =
    (PURGE_REACHABLE_TIME.as_secs() / MAX_DELAY_REACHABLE.as_secs()) as u32;

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
        next_connect_after: Duration,

        /// Disconnect is done by requesting to do it.
        /// This flag ensures that p2p will not try to reconnect to the target node.
        disconnected_by_user: bool,
    },

    Unreachable {
        /// At which time the address would be removed from memory
        erase_after: Duration,
    },
}

#[derive(Copy, Clone, Debug)]
// Update `ALL_TRANSITIONS` if a new transition is added!
pub enum AddressStateTransitionTo {
    Connected,
    Disconnected,
    DisconnectedByUser,
    ConnectionFailed,
    SetReserved,
    UnsetReserved,
}

#[cfg(test)]
pub const ALL_TRANSITIONS: [AddressStateTransitionTo; 6] = [
    AddressStateTransitionTo::Connected,
    AddressStateTransitionTo::Disconnected,
    AddressStateTransitionTo::DisconnectedByUser,
    AddressStateTransitionTo::ConnectionFailed,
    AddressStateTransitionTo::SetReserved,
    AddressStateTransitionTo::UnsetReserved,
];

pub struct AddressData {
    state: AddressState,

    reserved: bool,
}

impl AddressData {
    pub fn new(was_reachable: bool, reserved: bool, now: Duration) -> Self {
        AddressData {
            state: AddressState::Disconnected {
                was_reachable,
                fail_count: 0,
                next_connect_after: now,
                disconnected_by_user: false,
            },
            reserved,
        }
    }

    pub fn reserved(&self) -> bool {
        self.reserved
    }

    /// Returns true when it is time to attempt a new outbound connection
    pub fn connect_now(&self, now: Duration) -> bool {
        match self.state {
            AddressState::Connected {} => false,

            // Once a peer is disconnected by the RPC command, it should remain disconnected
            // (at least until the RPC requests to connect). Otherwise, users may be surprised
            // to see the peer reconnect after some time (and may break functional tests).
            AddressState::Disconnected {
                fail_count: _,
                next_connect_after,
                was_reachable: _,
                disconnected_by_user,
            } => now >= next_connect_after && !disconnected_by_user,

            AddressState::Unreachable { erase_after: _ } => false,
        }
    }

    /// Returns true if the address should be kept in memory
    pub fn retain(&self, now: Duration) -> bool {
        match self.state {
            AddressState::Connected {} => true,
            AddressState::Disconnected {
                was_reachable: _,
                fail_count: _,
                next_connect_after: _,
                disconnected_by_user: _,
            } => true,
            AddressState::Unreachable { erase_after } => erase_after < now,
        }
    }

    /// Returns true if the address should be stored in the DB
    pub fn is_persistent(&self) -> bool {
        match self.state {
            AddressState::Connected {} => true,
            AddressState::Disconnected {
                fail_count: _,
                next_connect_after: _,
                was_reachable,
                disconnected_by_user: _,
            } => was_reachable,
            AddressState::Unreachable { erase_after: _ } => false,
        }
    }

    pub fn is_connected(&self) -> bool {
        matches!(self.state, AddressState::Connected { .. })
    }

    pub fn is_unreachable(&self) -> bool {
        matches!(self.state, AddressState::Unreachable { .. })
    }

    fn next_connect_delay(fail_count: u32, reserved: bool) -> Duration {
        let max_delay = if reserved { MAX_DELAY_RESERVED } else { MAX_DELAY_REACHABLE };

        // 10, 20, 40, 80... seconds
        std::cmp::min(
            Duration::from_secs(10).saturating_mul(2u32.saturating_pow(fail_count)),
            max_delay,
        )
    }

    fn next_connect_time(
        now: Duration,
        fail_count: u32,
        reserved: bool,
        rng: &mut impl Rng,
    ) -> Duration {
        now + Self::next_connect_delay(fail_count, reserved)
            .mul_f64(utils::exp_rand::exponential_rand(rng))
    }

    pub fn transition_to(
        &mut self,
        transition: AddressStateTransitionTo,
        now: Duration,
        rng: &mut impl Rng,
    ) {
        self.state = match transition {
            AddressStateTransitionTo::Connected => match self.state {
                AddressState::Connected {} => unreachable!(),
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                    disconnected_by_user: _,
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
                    disconnected_by_user: false,
                },
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                    disconnected_by_user: _,
                } => unreachable!(),
                AddressState::Unreachable { erase_after: _ } => unreachable!(),
            },

            AddressStateTransitionTo::DisconnectedByUser => match self.state {
                AddressState::Connected {} => AddressState::Disconnected {
                    fail_count: 0,
                    next_connect_after: Self::next_connect_time(now, 0, self.reserved, rng),
                    was_reachable: true,
                    disconnected_by_user: true,
                },
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                    disconnected_by_user: _,
                } => unreachable!(),
                AddressState::Unreachable { erase_after: _ } => unreachable!(),
            },

            AddressStateTransitionTo::ConnectionFailed => match self.state {
                AddressState::Connected {} => unreachable!(),
                AddressState::Disconnected {
                    fail_count,
                    next_connect_after: _,
                    was_reachable,
                    disconnected_by_user,
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
                            disconnected_by_user,
                        }
                    } else if !was_reachable {
                        AddressState::Unreachable { erase_after: now + PURGE_UNREACHABLE_TIME }
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
                            disconnected_by_user,
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
                        disconnected_by_user,
                    } => AddressState::Disconnected {
                        was_reachable,
                        fail_count,
                        next_connect_after: Self::next_connect_time(
                            now,
                            fail_count,
                            self.reserved,
                            rng,
                        ),
                        disconnected_by_user,
                    },
                    // Reserved nodes should not be in the `Unreachable` state
                    AddressState::Unreachable { erase_after: _ } => AddressState::Disconnected {
                        fail_count: 0,
                        next_connect_after: Self::next_connect_time(now, 0, self.reserved, rng),
                        was_reachable: false,
                        disconnected_by_user: false,
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
                        disconnected_by_user,
                    } => AddressState::Disconnected {
                        was_reachable,
                        fail_count,
                        next_connect_after,
                        disconnected_by_user,
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
