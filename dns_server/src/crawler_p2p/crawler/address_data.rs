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

use utils::const_value::ConstValue;

/// Address state transition
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressStateTransitionTo {
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
}

/// When the server drops the unreachable node address. Used for negative caching.
pub const PURGE_UNREACHABLE_TIME: Duration = Duration::from_secs(3600);

/// When the server drops the unreachable node address that was once reachable. This should take about a month.
/// Such a long time is useful if the server itself has prolonged connectivity problems.
pub const PURGE_REACHABLE_FAIL_COUNT: u32 = 35;

/// Connection state of a potential node address (outbound only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressState {
    Connecting {
        /// The number of consecutive failed connection attempts.
        /// New connection attempts are made after a progressive backoff time.
        fail_count: u32,

        /// Whether the address was reachable at least once.
        /// Addresses that were once reachable are stored in the DB.
        was_reachable: bool,
    },

    Connected {},

    Disconnecting {
        /// Same as above
        fail_count: u32,

        /// Same as above
        was_reachable: bool,
    },

    Disconnected {
        /// Same as above
        fail_count: u32,

        /// Same as above
        was_reachable: bool,

        /// The time when the address went into the disconnected state
        disconnected_at: Duration,
    },

    /// This is a final state where an address is marked as unreachable and there will be no more attempts to connect to it.
    /// After erase_after time it would be removed from memory and can be added as new after that.
    Unreachable {
        /// Same as above
        fail_count: u32,

        /// Same as above
        was_reachable: bool,

        /// At which time the address would be removed from memory
        erase_after: Duration,
    },
}

/// Additional state of a potential node address
pub struct AddressData {
    /// Connection state
    pub state: AddressState,

    /// Whether the address was specified from the command line as reserved_node
    pub reserved: ConstValue<bool>,
}

impl AddressState {
    fn fail_count(&self) -> u32 {
        match self {
            AddressState::Connecting {
                fail_count,
                was_reachable: _,
            } => *fail_count,
            AddressState::Connected {} => 0,
            AddressState::Disconnecting {
                fail_count,
                was_reachable: _,
            } => *fail_count,
            AddressState::Disconnected {
                fail_count,
                was_reachable: _,
                disconnected_at: _,
            } => *fail_count,
            AddressState::Unreachable {
                fail_count,
                erase_after: _,
                was_reachable: _,
            } => *fail_count,
        }
    }

    fn was_reachable(&self) -> bool {
        match self {
            AddressState::Connecting {
                fail_count: _,
                was_reachable,
            } => *was_reachable,
            AddressState::Connected {} => true,
            AddressState::Disconnecting {
                fail_count: _,
                was_reachable,
            } => *was_reachable,
            AddressState::Disconnected {
                fail_count: _,
                was_reachable,
                disconnected_at: _,
            } => *was_reachable,
            AddressState::Unreachable {
                erase_after: _,
                was_reachable,
                fail_count: _,
            } => *was_reachable,
        }
    }

    /// Whether the address is currently recognized as reachable (available from DNS)
    pub fn is_reachable(&self) -> bool {
        match self {
            AddressState::Connecting {
                fail_count: _,
                was_reachable: _,
            } => false,
            AddressState::Connected {} => true,
            AddressState::Disconnecting {
                fail_count: _,
                was_reachable: _,
            } => false,
            AddressState::Disconnected {
                fail_count: _,
                was_reachable: _,
                disconnected_at: _,
            } => false,
            AddressState::Unreachable {
                fail_count: _,
                was_reachable: _,
                erase_after: _,
            } => false,
        }
    }

    /// Whether to retain the address between node restarts (stored in DB).
    pub fn is_persistent(&self) -> bool {
        match self {
            AddressState::Connecting {
                fail_count: _,
                was_reachable,
            } => *was_reachable,
            AddressState::Connected {} => true,
            AddressState::Disconnecting {
                fail_count: _,
                was_reachable,
            } => *was_reachable,
            AddressState::Disconnected {
                fail_count: _,
                was_reachable,
                disconnected_at: _,
            } => *was_reachable,
            AddressState::Unreachable {
                fail_count: _,
                was_reachable: _,
                erase_after: _,
            } => false,
        }
    }
}

impl AddressData {
    /// Returns true when it is time to attempt a new outbound connection
    pub fn connect_now(&self, now: Duration) -> bool {
        match self.state {
            AddressState::Connected {}
            | AddressState::Connecting {
                fail_count: _,
                was_reachable: _,
            }
            | AddressState::Disconnecting {
                fail_count: _,
                was_reachable: _,
            }
            | AddressState::Unreachable {
                fail_count: _,
                was_reachable: _,
                erase_after: _,
            } => false,

            AddressState::Disconnected {
                fail_count,
                was_reachable,
                disconnected_at,
            } => {
                let age = now - disconnected_at;
                if *self.reserved {
                    // Try to connect to the reserved nodes more often
                    let age = now - disconnected_at;
                    match fail_count {
                        0 => true,
                        1 => age > Duration::from_secs(60),
                        2 => age > Duration::from_secs(360),
                        _ => age > Duration::from_secs(3600),
                    }
                } else if was_reachable {
                    match fail_count {
                        0 => true,
                        1 => age > Duration::from_secs(60),
                        2 => age > Duration::from_secs(360),
                        3 => age > Duration::from_secs(3600),
                        4 => age > Duration::from_secs(3 * 3600),
                        5 => age > Duration::from_secs(6 * 3600),
                        6 => age > Duration::from_secs(12 * 3600),
                        _ => age > Duration::from_secs(24 * 3600),
                    }
                } else {
                    // The address was never reachable, try to connect just once
                    fail_count == 0
                }
            }
        }
    }

    /// Returns true if the address should be kept in memory
    pub fn retain(&self, now: Duration) -> bool {
        match self.state {
            // Always keep user added addresses
            AddressState::Unreachable {
                erase_after,
                fail_count: _,
                was_reachable: _,
            } if erase_after >= now => false,
            _ => true,
        }
    }

    pub fn transition_to(&mut self, transition: AddressStateTransitionTo, now: Duration) {
        match transition {
            AddressStateTransitionTo::Connecting => {
                assert!(matches!(self.state, AddressState::Disconnected { .. }));

                self.state = AddressState::Connecting {
                    fail_count: self.state.fail_count(),
                    was_reachable: self.state.was_reachable(),
                };
            }

            AddressStateTransitionTo::Connected => {
                assert!(matches!(self.state, AddressState::Connecting { .. }));

                self.state = AddressState::Connected {};
            }

            AddressStateTransitionTo::Disconnecting => {
                assert!(matches!(
                    self.state,
                    AddressState::Connecting { .. } | AddressState::Connected { .. }
                ));

                self.state = AddressState::Disconnecting {
                    fail_count: self.state.fail_count(),
                    was_reachable: self.state.was_reachable(),
                };
            }

            AddressStateTransitionTo::Disconnected => {
                assert!(
                    matches!(self.state, AddressState::Connecting { .. })
                        || matches!(self.state, AddressState::Connected { .. })
                        || matches!(self.state, AddressState::Disconnecting { .. })
                );

                self.state = match (*self.reserved, self.state.was_reachable()) {
                    (false, true) if self.state.fail_count() + 1 >= PURGE_REACHABLE_FAIL_COUNT => {
                        AddressState::Unreachable {
                            fail_count: self.state.fail_count() + 1,
                            was_reachable: self.state.was_reachable(),
                            erase_after: now,
                        }
                    }
                    (false, false) => AddressState::Unreachable {
                        fail_count: self.state.fail_count() + 1,
                        was_reachable: self.state.was_reachable(),
                        erase_after: now + PURGE_UNREACHABLE_TIME,
                    },
                    _ => AddressState::Disconnected {
                        fail_count: self.state.fail_count() + 1,
                        was_reachable: self.state.was_reachable(),
                        disconnected_at: now,
                    },
                };
            }
        }
    }
}
