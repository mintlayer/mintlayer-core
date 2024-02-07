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

use common::{
    chain::ChainConfig,
    primitives::{
        semver::SemVer,
        time::Time,
        user_agent::{mintlayer_core_user_agent, UserAgent},
    },
};
use serialization::{Decode, Encode};
use utils::const_value::ConstValue;

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq, Ord, PartialOrd)]
pub struct SoftwareInfo {
    pub user_agent: UserAgent,
    pub version: SemVer,
}

impl SoftwareInfo {
    pub fn current(chain_config: &ChainConfig) -> Self {
        Self {
            user_agent: mintlayer_core_user_agent(),
            version: *chain_config.software_version(),
        }
    }
}

/// Address state transition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressStateTransitionTo {
    Connecting,
    Connected {
        /// Peer's software info.
        peer_software_info: SoftwareInfo,
        /// `True` means that address list request will be sent to the peer immediately;
        /// this is a signal to update ConnectionInfo's last_addr_list_request_time.
        will_request_addr_list_now: bool,
    },
    Disconnecting,
    Disconnected,
}

/// When the server drops the unreachable node address. Used for negative caching.
pub const PURGE_UNREACHABLE_TIME: Duration = Duration::from_secs(3600);

/// When the server drops the unreachable node address that was once reachable. This should take about a month.
/// Such a long time is useful if the server itself has prolonged connectivity problems.
pub const PURGE_REACHABLE_FAIL_COUNT: u32 = 35;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// Peer's software info
    pub peer_software_info: SoftwareInfo,
    /// Last time we've requested addresses from this peer.
    pub last_addr_list_request_time: Option<Time>,
}

/// Connection state of a potential node address (outbound only)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressState {
    Connecting {
        /// The number of consecutive failed connection attempts.
        /// New connection attempts are made after a progressive backoff time.
        fail_count: u32,

        /// If the address was reachable at least once, this field will contain the information
        /// about the last connection.
        /// Addresses that were once reachable are stored in the DB.
        last_connection_info: Option<ConnectionInfo>,
    },

    Connected {
        /// Current connection info
        connection_info: ConnectionInfo,
    },

    Disconnecting {
        /// Same as above
        fail_count: u32,

        /// Last connection info.
        last_connection_info: Option<ConnectionInfo>,
    },

    Disconnected {
        /// Same as above
        fail_count: u32,

        /// Last connection info.
        last_connection_info: Option<ConnectionInfo>,

        /// The time when the address went into the disconnected state.
        disconnected_at: Time,
    },

    /// This is a final state where an address is marked as unreachable and there will be no more attempts to connect to it.
    /// After erase_after time it would be removed from memory and can be added as new after that.
    Unreachable {
        /// Same as above
        fail_count: u32,

        /// Last connection info.
        last_connection_info: Option<ConnectionInfo>,

        /// At which time the address would be removed from memory
        erase_after: Time,
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
                last_connection_info: _,
            } => *fail_count,
            AddressState::Connected { connection_info: _ } => 0,
            AddressState::Disconnecting {
                fail_count,
                last_connection_info: _,
            } => *fail_count,
            AddressState::Disconnected {
                fail_count,
                last_connection_info: _,
                disconnected_at: _,
            } => *fail_count,
            AddressState::Unreachable {
                fail_count,
                erase_after: _,
                last_connection_info: _,
            } => *fail_count,
        }
    }

    fn was_reachable(&self) -> bool {
        match self {
            AddressState::Connecting {
                fail_count: _,
                last_connection_info,
            } => last_connection_info.is_some(),
            AddressState::Connected { connection_info: _ } => true,
            AddressState::Disconnecting {
                fail_count: _,
                last_connection_info,
            } => last_connection_info.is_some(),
            AddressState::Disconnected {
                fail_count: _,
                last_connection_info,
                disconnected_at: _,
            } => last_connection_info.is_some(),
            AddressState::Unreachable {
                erase_after: _,
                last_connection_info,
                fail_count: _,
            } => last_connection_info.is_some(),
        }
    }

    /// Whether the address is currently recognized as reachable (available from DNS)
    pub fn is_reachable(&self) -> bool {
        match self {
            AddressState::Connecting {
                fail_count: _,
                last_connection_info: _,
            } => false,
            AddressState::Connected { connection_info: _ } => true,
            AddressState::Disconnecting {
                fail_count: _,
                last_connection_info: _,
            } => false,
            AddressState::Disconnected {
                fail_count: _,
                last_connection_info: _,
                disconnected_at: _,
            } => false,
            AddressState::Unreachable {
                fail_count: _,
                last_connection_info: _,
                erase_after: _,
            } => false,
        }
    }

    /// Whether to retain the address between node restarts (stored in DB).
    pub fn is_persistent(&self) -> bool {
        match self {
            AddressState::Connecting {
                fail_count: _,
                last_connection_info,
            } => last_connection_info.is_some(),
            AddressState::Connected { connection_info: _ } => true,
            AddressState::Disconnecting {
                fail_count: _,
                last_connection_info,
            } => last_connection_info.is_some(),
            AddressState::Disconnected {
                fail_count: _,
                last_connection_info,
                disconnected_at: _,
            } => last_connection_info.is_some(),
            AddressState::Unreachable {
                fail_count: _,
                last_connection_info: _,
                erase_after: _,
            } => false,
        }
    }

    /// Returns the latest known connection info for this address.
    pub fn connection_info(&self) -> Option<&ConnectionInfo> {
        match self {
            AddressState::Connecting {
                fail_count: _,
                last_connection_info,
            } => last_connection_info.as_ref(),
            AddressState::Connected { connection_info } => Some(connection_info),
            AddressState::Disconnecting {
                fail_count: _,
                last_connection_info,
            } => last_connection_info.as_ref(),
            AddressState::Disconnected {
                fail_count: _,
                last_connection_info,
                disconnected_at: _,
            } => last_connection_info.as_ref(),
            AddressState::Unreachable {
                fail_count: _,
                last_connection_info,
                erase_after: _,
            } => last_connection_info.as_ref(),
        }
    }
}

impl AddressData {
    /// Returns true when it is time to attempt a new outbound connection
    pub fn connect_now(&self, now: Time) -> bool {
        match &self.state {
            AddressState::Connected { connection_info: _ }
            | AddressState::Connecting {
                fail_count: _,
                last_connection_info: _,
            }
            | AddressState::Disconnecting {
                fail_count: _,
                last_connection_info: _,
            }
            | AddressState::Unreachable {
                fail_count: _,
                last_connection_info: _,
                erase_after: _,
            } => false,

            AddressState::Disconnected {
                fail_count,
                last_connection_info,
                disconnected_at,
            } => {
                let age = (now - *disconnected_at).expect("Must work");
                if *self.reserved {
                    // Try to connect to the reserved nodes more often
                    match fail_count {
                        0 => true,
                        1 => age > Duration::from_secs(60),
                        2 => age > Duration::from_secs(360),
                        _ => age > Duration::from_secs(3600),
                    }
                } else if last_connection_info.is_some() {
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
                    *fail_count == 0
                }
            }
        }
    }

    /// Returns true if the address should be kept in memory
    pub fn retain(&self, now: Time) -> bool {
        match self.state {
            // Always keep user added addresses
            AddressState::Unreachable {
                erase_after,
                fail_count: _,
                last_connection_info: _,
            } if erase_after >= now => false,
            _ => true,
        }
    }

    pub fn transition_to(&mut self, transition: AddressStateTransitionTo, now: Time) {
        match transition {
            AddressStateTransitionTo::Connecting => {
                assert!(matches!(self.state, AddressState::Disconnected { .. }));

                self.state = AddressState::Connecting {
                    fail_count: self.state.fail_count(),
                    last_connection_info: self.state.connection_info().cloned(),
                };
            }

            AddressStateTransitionTo::Connected {
                peer_software_info,
                will_request_addr_list_now,
            } => {
                assert!(matches!(self.state, AddressState::Connecting { .. }));

                let last_addr_list_request_time = if will_request_addr_list_now {
                    Some(now)
                } else {
                    self.state
                        .connection_info()
                        .and_then(|conn_info| conn_info.last_addr_list_request_time)
                };

                self.state = AddressState::Connected {
                    connection_info: ConnectionInfo {
                        peer_software_info,
                        last_addr_list_request_time,
                    },
                };
            }

            AddressStateTransitionTo::Disconnecting => {
                assert!(matches!(
                    self.state,
                    AddressState::Connecting { .. } | AddressState::Connected { .. }
                ));

                self.state = AddressState::Disconnecting {
                    fail_count: self.state.fail_count(),
                    last_connection_info: self.state.connection_info().cloned(),
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
                            last_connection_info: self.state.connection_info().cloned(),
                            erase_after: now,
                        }
                    }
                    (false, false) => AddressState::Unreachable {
                        fail_count: self.state.fail_count() + 1,
                        last_connection_info: self.state.connection_info().cloned(),
                        erase_after: (now + PURGE_UNREACHABLE_TIME)
                            .expect("All from local clocks; cannot fail"),
                    },
                    _ => AddressState::Disconnected {
                        fail_count: self.state.fail_count() + 1,
                        last_connection_info: self.state.connection_info().cloned(),
                        disconnected_at: now,
                    },
                };
            }
        }
    }
}
