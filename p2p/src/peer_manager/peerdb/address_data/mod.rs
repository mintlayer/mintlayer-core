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

use std::time::{Duration, Instant};

use utils::const_value::ConstValue;

/// When the server drops the unreachable node address. Used for negative caching.
pub const PURGE_UNREACHABLE_TIME: Duration = Duration::from_secs(3600);

/// When the server drops the unreachable node address that was once reachable. This should take about a month.
/// Such a long time is useful if the server itself has prolonged connectivity problems.
pub const PURGE_REACHABLE_FAIL_COUNT: u32 = 35;

pub enum AddressState {
    Connected {},
    Disconnected {
        was_reachable: bool,
        fail_count: u32,
        disconnected_at: Instant,
    },
    Unreachable {
        erase_after: Instant,
    },
}

pub enum AddressStateTransitionTo {
    Connected,
    Disconnected,
    ConnectionFailed,
}

pub struct AddressData {
    state: AddressState,

    user_added: ConstValue<bool>,
}

impl AddressData {
    pub fn new(was_reachable: bool, user_added: bool, now: Instant) -> Self {
        AddressData {
            state: AddressState::Disconnected {
                was_reachable,
                fail_count: 0,
                disconnected_at: now,
            },
            user_added: user_added.into(),
        }
    }

    /// Returns true when it is time to attempt a new outbound connection
    pub fn connect_now(&self, now: Instant) -> bool {
        match self.state {
            AddressState::Connected {} => false,

            AddressState::Disconnected {
                fail_count,
                disconnected_at,
                was_reachable,
            } => {
                let age = now.duration_since(disconnected_at);
                if *self.user_added {
                    // Try to connect to the user added nodes more often
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
                    fail_count == 0
                }
            }

            AddressState::Unreachable { erase_after: _ } => false,
        }
    }

    /// Returns true if the address should be kept in memory
    pub fn retain(&self, now: Instant) -> bool {
        match self.state {
            AddressState::Connected {} => true,
            AddressState::Disconnected {
                was_reachable: _,
                fail_count: _,
                disconnected_at: _,
            } => true,
            AddressState::Unreachable { erase_after } => erase_after < now,
        }
    }

    pub fn is_persistent(&self) -> bool {
        match self.state {
            AddressState::Connected {} => true,
            AddressState::Disconnected {
                fail_count: _,
                disconnected_at: _,
                was_reachable,
            } => was_reachable,
            AddressState::Unreachable { erase_after: _ } => false,
        }
    }

    pub fn transition_to(&mut self, transition: AddressStateTransitionTo, now: Instant) {
        self.state = match transition {
            AddressStateTransitionTo::Connected => match self.state {
                AddressState::Connected {} => unreachable!(),
                AddressState::Disconnected {
                    fail_count: _,
                    disconnected_at: _,
                    was_reachable: _,
                } => AddressState::Connected {},
                AddressState::Unreachable { erase_after: _ } => unreachable!(),
            },

            AddressStateTransitionTo::Disconnected => match self.state {
                AddressState::Connected {} => AddressState::Disconnected {
                    fail_count: 0,
                    disconnected_at: now,
                    was_reachable: true,
                },
                AddressState::Disconnected {
                    fail_count: _,
                    disconnected_at: _,
                    was_reachable: _,
                } => unreachable!(),
                AddressState::Unreachable { erase_after: _ } => unreachable!(),
            },

            AddressStateTransitionTo::ConnectionFailed => match self.state {
                AddressState::Connected {} => unreachable!(),
                AddressState::Disconnected {
                    fail_count,
                    disconnected_at: _,
                    was_reachable,
                } => {
                    if *self.user_added {
                        AddressState::Disconnected {
                            fail_count: fail_count + 1,
                            disconnected_at: now,
                            was_reachable,
                        }
                    } else if !was_reachable {
                        AddressState::Unreachable {
                            erase_after: now + PURGE_UNREACHABLE_TIME,
                        }
                    } else if fail_count + 1 >= PURGE_REACHABLE_FAIL_COUNT {
                        AddressState::Unreachable { erase_after: now }
                    } else {
                        AddressState::Disconnected {
                            fail_count: fail_count + 1,
                            disconnected_at: now,
                            was_reachable,
                        }
                    }
                }
                AddressState::Unreachable { erase_after: _ } => {
                    unreachable!()
                }
            },
        }
    }
}
