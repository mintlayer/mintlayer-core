// Copyright (c) 2021-2023 RBB S.r.l
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

use p2p_types::socket_address::SocketAddress;

use self::table::Table;

use super::{config::PeerDbConfig, salt::Salt};

pub mod table;

/// `AddressTables` provides a way of limiting the number of addresses in the peer db. When an
/// address is added to it, an older one may be discarded at the same time.
///
/// `AddressTables` doesn't manage the actual `AddressData` itself. Instead, it just informs
/// the caller code that a certain address was discarded, at which point the caller is supposed
/// to update the corresponding collection.
///
/// As the name implies, the addresses are stored in tables. Two kinds of addresses exist and
/// each has its own separate table:
/// 1) "tried" addresses are those to which at least one successful outbound connection was
///    established at some point;
/// 2) "new" addresses are basically everything else.
///
/// Note that since `AddressTables` knows nothing about connections, it's the caller who defines
/// what "new" and "tried" actually mean. E.g. "new" may include not only freshly discovered
/// addresses, but also those that we've already tried to connect to, but failed.
///
/// Each table is represented by the `Table` struct, which consists of a fixed number of buckets
/// each of which contains a fixed number of slots; the maximum number of addresses that a table
/// can hold is the product of those numbers.
/// The indices of a bucket and of a slot that an address will be put into are determined by
/// hashing the address (to be more precise, different parts of the address are hashed separately
/// and then combined together; this allows to ensure, for example, that addresses from a certain
/// "address group" can be spread over only a very limited number of buckets).
///
/// `Table` has a constant memory overhead equal to `buckets_count*bucket_size*size_of(u32)`,
/// so using big numbers for the bucket size and count is not a good idea. On the other hand,
/// choosing small values might not be a good idea either, because potentially useful addresses
/// may start evicting each other due to hash collisions.
pub struct AddressTables {
    new_addr_table: Table,
    tried_addr_table: Table,
}

impl AddressTables {
    pub fn new(salt: Salt, peerdb_config: &PeerDbConfig) -> Self {
        let new_addr_table = Table::new(
            *peerdb_config.new_addr_table_bucket_count,
            *peerdb_config.addr_tables_bucket_size,
            salt.mix_with('n'),
        );
        let tried_addr_table = Table::new(
            *peerdb_config.tried_addr_table_bucket_count,
            *peerdb_config.addr_tables_bucket_size,
            salt.mix_with('t'),
        );

        Self {
            new_addr_table,
            tried_addr_table,
        }
    }

    /// Remove the specified address from "new" and put it into "tried".
    /// If an older "tried" address exists at the destination, move it into "new".
    //
    // TODO: in bitcoin they don't replace existing "tried" addresses right away; instead,
    // they check if the old address is still reachable and if yes, keep it (the passed address
    // stays in "new" in this case).
    // Should we do the same?
    #[must_use]
    pub fn move_to_tried(&mut self, addr: &SocketAddress) -> Option<MoveToTriedSideEffects> {
        self.new_addr_table.remove(addr);

        let prev_tried_addr = self.tried_addr_table.replace(addr);

        if let Some(prev_tried_addr) = prev_tried_addr {
            let discarded_new_addr = self.new_addr_table.replace(&prev_tried_addr);
            Some(MoveToTriedSideEffects {
                addr_moved_to_new: prev_tried_addr,
                discarded_new_addr,
            })
        } else {
            None
        }
    }

    /// Remove the specified address from "tried" and put it into "new".
    /// If an older address exists at the destination, only replace it if `can_replace` returns true.
    #[must_use]
    pub fn move_to_new<AddrPred>(
        &mut self,
        addr: &SocketAddress,
        can_replace: AddrPred,
    ) -> MoveToNewOutcome
    where
        AddrPred: Fn(/*existing_addr:*/ SocketAddress) -> bool,
    {
        self.tried_addr_table.remove(addr);
        let discared_addr = self.new_addr_table.replace_if(addr, can_replace);

        if discared_addr == Some(*addr) {
            MoveToNewOutcome::Cancelled
        } else {
            MoveToNewOutcome::Succeeded {
                prev_addr: discared_addr,
            }
        }
    }

    #[must_use]
    pub fn force_add_to_new(&mut self, addr: &SocketAddress) -> Option<SocketAddress> {
        self.new_addr_table.replace(addr)
    }

    #[must_use]
    pub fn force_add_to_tried(&mut self, addr: &SocketAddress) -> Option<SocketAddress> {
        self.tried_addr_table.replace(addr)
    }

    pub fn is_in_new(&self, addr: &SocketAddress) -> bool {
        self.new_addr_table.entry(addr) == Some(addr)
    }

    pub fn is_in_tried(&self, addr: &SocketAddress) -> bool {
        self.tried_addr_table.entry(addr) == Some(addr)
    }

    pub fn have_addr(&self, addr: &SocketAddress) -> bool {
        self.is_in_new(addr) || self.is_in_tried(addr)
    }

    pub fn remove(&mut self, addr: &SocketAddress) {
        self.new_addr_table.remove(addr);
        self.tried_addr_table.remove(addr);
    }

    pub fn new_addresses(&self) -> impl Iterator<Item = &SocketAddress> + '_ {
        self.new_addr_table.addr_iter()
    }

    pub fn tried_addresses(&self) -> impl Iterator<Item = &SocketAddress> + '_ {
        self.tried_addr_table.addr_iter()
    }

    #[cfg(test)]
    pub fn new_addr_table(&self) -> &Table {
        &self.new_addr_table
    }

    #[cfg(test)]
    pub fn tried_addr_table(&self) -> &Table {
        &self.tried_addr_table
    }

    #[cfg(test)]
    pub fn set_should_check_consistency(&mut self, val: bool) {
        self.new_addr_table.set_should_check_consistency(val);
        self.tried_addr_table.set_should_check_consistency(val);
    }
}

/// Optional side effects of `move_to_tried` (the additional addresses that it had to move).
pub struct MoveToTriedSideEffects {
    /// A "tried" address that had to be moved to "new".
    pub addr_moved_to_new: SocketAddress,
    /// The address that was removed from "new" and is no longer in the tables.
    pub discarded_new_addr: Option<SocketAddress>,
}

/// The outcome of `move_to_new`.
pub enum MoveToNewOutcome {
    /// The address was successfully put into the "new" table.
    Succeeded {
        /// The previous address that existed at the corresponding slot.
        prev_addr: Option<SocketAddress>,
    },
    /// `move_to_new` didn't do anything, because the address that already exists
    /// at the corresponding slot is better.
    Cancelled,
}

#[cfg(test)]
pub mod test_utils {
    pub use super::table::test_utils::*;
}
