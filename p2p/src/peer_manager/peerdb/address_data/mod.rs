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
use utils::debug_panic_or_log;

use crate::net::types::OutboundPeerRole;

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

// Note: AddressState/AddressData only track outbound connections, so if an inbound connection exists
// from a given address, its AddressState may still be Disconnected or even Unreachable.
#[derive(Debug, Clone)]
pub enum AddressState {
    Connected {
        /// Whether the peer has shown some activity (i.e. sent us any message except for WillDisconnect)
        /// during this connection.
        had_activity: bool,

        peer_role: OutboundPeerRole,
    },

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

#[derive(Copy, Clone, Debug, strum::EnumDiscriminants)]
#[strum_discriminants(name(AddressStateTransitionToTag), derive(strum::EnumIter))]
pub enum AddressStateTransitionTo {
    Connected { peer_role: OutboundPeerRole },
    HadActivity,
    Disconnected,
    ConnectionFailed,
    SetReserved,
    UnsetReserved,
}

#[derive(Debug, Clone)]
pub struct AddressData {
    state: AddressState,

    reserved: bool,

    /// The number of consecutive successful completed connections during which the peer had no activity
    /// (i.e. hadn't sent us any message except for WillDisconnect).
    connections_without_activity_count: u32,
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
            connections_without_activity_count: 0,
        }
    }

    pub fn state(&self) -> &AddressState {
        &self.state
    }

    #[cfg(test)]
    pub fn state_mut(&mut self) -> &mut AddressState {
        &mut self.state
    }

    pub fn reserved(&self) -> bool {
        self.reserved
    }

    pub fn connections_without_activity_count(&self) -> u32 {
        self.connections_without_activity_count
    }

    /// Returns true when it is time to attempt a new outbound connection
    pub fn connect_now(&self, now: Time) -> bool {
        match self.state {
            AddressState::Connected {
                had_activity: _,
                peer_role: _,
            } => false,

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
            AddressState::Connected {
                had_activity: _,
                peer_role: _,
            } => true,
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

    fn next_connect_delay(effective_fail_count: u32, reserved: bool) -> Duration {
        let max_delay = if reserved {
            MAX_DELAY_RESERVED
        } else {
            MAX_DELAY_REACHABLE
        };

        // 10, 20, 40, 80... seconds
        std::cmp::min(
            Duration::from_secs(10).saturating_mul(2u32.saturating_pow(effective_fail_count)),
            max_delay,
        )
    }

    fn next_connect_time(
        now: Time,
        fail_count: u32,
        connections_without_activity_count: u32,
        reserved: bool,
        rng: &mut impl Rng,
    ) -> Time {
        // Note: fail_count is reset whenever any successful outbound connection is made, but
        // connections_without_activity_count is not reset when an outbound connection fails,
        // so it's possible for both of them to be non-zero.
        let effective_fail_count = std::cmp::max(fail_count, connections_without_activity_count);

        let factor = utils::exp_rand::exponential_rand(rng).clamp(0.0, MAX_DELAY_FACTOR as f64);
        let offset = Self::next_connect_delay(effective_fail_count, reserved).mul_f64(factor);
        (now + offset).expect("Unexpected time addition overflow")
    }

    pub fn transition_to(
        &mut self,
        transition: AddressStateTransitionTo,
        now: Time,
        rng: &mut impl Rng,
    ) {
        self.state = match transition {
            AddressStateTransitionTo::Connected { peer_role } => match self.state {
                AddressState::Connected {
                    had_activity: _,
                    peer_role: _,
                } => {
                    debug_panic_or_log!(
                        "Unexpected address state transition: Connected -> Connected"
                    );
                    self.state.clone()
                }
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                } => AddressState::Connected {
                    had_activity: false,
                    peer_role,
                },
                AddressState::Unreachable { erase_after: _ } => {
                    // Connection to an `Unreachable` node may be requested by RPC at any moment
                    AddressState::Connected {
                        had_activity: false,
                        peer_role,
                    }
                }
            },

            AddressStateTransitionTo::HadActivity => match self.state {
                AddressState::Connected {
                    had_activity: _,
                    peer_role,
                } => AddressState::Connected {
                    had_activity: true,
                    peer_role,
                },
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                } => {
                    debug_panic_or_log!(
                        "Unexpected address state transition: Disconnected -> HadActivity"
                    );
                    self.state.clone()
                }
                AddressState::Unreachable { erase_after: _ } => {
                    debug_panic_or_log!(
                        "Unexpected address state transition: Unreachable -> HadActivity"
                    );
                    self.state.clone()
                }
            },

            AddressStateTransitionTo::Disconnected => match self.state {
                AddressState::Connected {
                    had_activity,
                    peer_role,
                } => {
                    if had_activity {
                        self.connections_without_activity_count = 0;
                    } else {
                        // Note:
                        // 1) We don't increase the counter for manual connections.
                        // 2) Since `is_message_exchange_expected` doesn't know the actual services
                        //    that the peer provides, it's technically possible to punish an
                        //    "innocent" peer here, e.g. when the connection type is supposed to involve
                        //    block exchange, but the peer's actual services don't include Blocks.
                        //    However:
                        //    a) The worst punishment it can get is that the next connection will be
                        //       postponed for (roughly) MAX_DELAY_REACHABLE, which is currently 1 hour.
                        //    b) Such a peer will be rather useless anyway.
                        //    c) The connection has to be short enough, so that even a single PingRequest message
                        //       (which requires a response) could not be sent.
                        //    So it's not a big deal.
                        if peer_role.is_message_exchange_expected() && !peer_role.is_manual() {
                            self.connections_without_activity_count += 1;
                        }
                    }

                    AddressState::Disconnected {
                        fail_count: 0,
                        next_connect_after: Self::next_connect_time(
                            now,
                            0,
                            self.connections_without_activity_count,
                            self.reserved,
                            rng,
                        ),
                        was_reachable: true,
                    }
                }
                AddressState::Disconnected {
                    fail_count: _,
                    next_connect_after: _,
                    was_reachable: _,
                } => {
                    debug_panic_or_log!(
                        "Unexpected address state transition: Disconnected -> Disconnected"
                    );
                    self.state.clone()
                }
                AddressState::Unreachable { erase_after: _ } => {
                    debug_panic_or_log!(
                        "Unexpected address state transition: Unreachable -> Disconnected"
                    );
                    self.state.clone()
                }
            },

            AddressStateTransitionTo::ConnectionFailed => match self.state {
                AddressState::Connected {
                    had_activity: _,
                    peer_role: _,
                } => {
                    debug_panic_or_log!(
                        "Unexpected address state transition: Connected -> ConnectionFailed"
                    );
                    self.state.clone()
                }
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
                                self.connections_without_activity_count,
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
                                self.connections_without_activity_count,
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
                    AddressState::Connected {
                        had_activity,
                        peer_role,
                    } => AddressState::Connected {
                        had_activity,
                        peer_role,
                    },
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
                            self.connections_without_activity_count,
                            self.reserved,
                            rng,
                        ),
                    },
                    // Reserved nodes should not be in the `Unreachable` state
                    AddressState::Unreachable { erase_after: _ } => AddressState::Disconnected {
                        fail_count: 0,
                        next_connect_after: Self::next_connect_time(
                            now,
                            0,
                            self.connections_without_activity_count,
                            self.reserved,
                            rng,
                        ),
                        was_reachable: false,
                    },
                }
            }

            AddressStateTransitionTo::UnsetReserved => {
                self.reserved = false;

                // Do not change the state
                match self.state {
                    AddressState::Connected {
                        had_activity,
                        peer_role,
                    } => AddressState::Connected {
                        had_activity,
                        peer_role,
                    },
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
