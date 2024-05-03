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

use std::collections::{btree_map, BTreeMap};

use p2p_types::socket_address::SocketAddress;
use utils::array_2d::Array2d;

use crate::peer_manager::{address_groups::AddressGroup, peerdb::salt::calc_hash64};

use super::Salt;

const BUCKETS_PER_GROUP: u64 = 8;

type EntryId = u32;

pub struct Table {
    /// The array of buckets, each of which is (logically) an array of addresses. Since the array
    /// has a fixed size that can be rather large (e.g. 64k items), we don't store addresses
    /// directly. Instead, addresses are stored in a map indexed by a monotonously increasing
    /// ids and the array only contains the ids.
    buckets: Array2d<EntryId>,
    /// The addresses map.
    addresses: BTreeMap<EntryId, SocketAddress>,
    /// The maximum value of an id plus one. This value will be stored in `buckets` to indicate
    /// that the entry is unoccupied. Normally, it will be equal to EntryId::MAX, but we allow
    /// to override it for testing.
    id_max: EntryId,
    /// Arbitrary value; this is used as an additional "key" to randomize bucket selection.
    salt: Salt,
    /// This is used to turn off consistency checks, which can be too heavy for some tests.
    #[cfg(test)]
    should_check_consistency: bool,
}

impl Table {
    pub fn new(bucket_count: usize, bucket_size: usize, salt: Salt) -> Self {
        Self::new_generic(bucket_count, bucket_size, salt, EntryId::MAX)
    }

    fn new_generic(bucket_count: usize, bucket_size: usize, salt: Salt, id_max: EntryId) -> Self {
        assert!(id_max as usize >= bucket_count * bucket_size);

        Self {
            // Fill "buckets" with "id_max" initially.
            buckets: Array2d::new(bucket_count, bucket_size, id_max),
            addresses: BTreeMap::new(),
            salt,
            id_max,
            #[cfg(test)]
            should_check_consistency: true,
        }
    }

    // TODO: in bitcoin the "new" table bucket index is calculated differently from
    // the "tried" one:
    // 1) They also hash the "source", i.e. the address of the peer or dns seed
    // that advertised this address. This results in the same address being added
    // to the table multiple times if it was advertised by multiple sources, so
    // addresses that are advertised more have more chances to stay in the table.
    // 2) Only the "addr group" part of the address is included in the hash, so all
    // addresses from the same addr group will end up in the same bucket.
    // Should we do something similar?
    fn bucket_idx(&self, addr: &SocketAddress) -> usize {
        let addr_hash = calc_hash64(&(self.salt, addr));
        let addr_group = AddressGroup::from_peer_address(&addr.as_peer_address());

        // Note: addresses from a certain address group can be spread over at most BUCKETS_PER_GROUP
        // buckets.
        let final_hash = calc_hash64(&(self.salt, addr_group, addr_hash % BUCKETS_PER_GROUP));

        (final_hash % self.buckets.rows_count() as u64) as usize
    }

    fn bucket_pos(&self, addr: &SocketAddress, bucket_idx: usize) -> usize {
        let hash = calc_hash64(&(self.salt, addr, bucket_idx));
        (hash % self.buckets.cols_count() as u64) as usize
    }

    fn bucket_coords(&self, addr: &SocketAddress) -> (usize, usize) {
        let bucket_idx = self.bucket_idx(addr);
        let bucket_pos = self.bucket_pos(addr, bucket_idx);
        (bucket_idx, bucket_pos)
    }

    /// Get the table "entry" corresponding to the passed address.
    pub fn entry(&self, addr: &SocketAddress) -> Option<&SocketAddress> {
        let (bucket_idx, bucket_pos) = self.bucket_coords(addr);
        let entry_id = self.buckets[bucket_idx][bucket_pos];
        // No need to check if the id is less than id_max; if it's not,
        // it won't be in the table.
        self.addresses.get(&entry_id)
    }

    /// A-low level function for creating entries.
    // Note: the caller must make sure that the address that will be written to
    // the returned location has the same "bucket coordinates" as the passed address.
    fn get_or_create_entry(&mut self, addr: &SocketAddress) -> &mut SocketAddress {
        let (bucket_idx, bucket_pos) = self.bucket_coords(addr);

        if self.buckets[bucket_idx][bucket_pos] >= self.id_max {
            self.buckets[bucket_idx][bucket_pos] = self.allocate_id();
        }

        self.addresses.entry(self.buckets[bucket_idx][bucket_pos]).or_insert(*addr)
    }

    pub fn remove(&mut self, addr: &SocketAddress) {
        let (bucket_idx, bucket_pos) = self.bucket_coords(addr);
        let entry_id_ref = &mut self.buckets[bucket_idx][bucket_pos];

        match self.addresses.entry(*entry_id_ref) {
            btree_map::Entry::Vacant(_) => {
                assert!(*entry_id_ref >= self.id_max);
            }
            btree_map::Entry::Occupied(entry) => {
                if entry.get() == addr {
                    entry.remove();
                    *entry_id_ref = self.id_max;
                }
            }
        }

        self.check_consistency();
    }

    /// Overwrite the existing entry with the passed address; return the previous address.
    pub fn replace(&mut self, addr: &SocketAddress) -> Option<SocketAddress> {
        let entry = self.get_or_create_entry(addr);
        let existing_addr = *entry;

        let result = if existing_addr == *addr {
            None
        } else {
            *entry = *addr;
            Some(existing_addr)
        };

        self.check_consistency();
        result
    }

    /// Overwrite the existing entry with the passed address, but only if the entry is empty
    /// or the passed predicate returns true for the previous address.
    /// Return the previous address if it was overwritten; if it was kept, return the passed
    /// address.
    pub fn replace_if<AddrPred>(
        &mut self,
        addr: &SocketAddress,
        can_replace: AddrPred,
    ) -> Option<SocketAddress>
    where
        AddrPred: Fn(/*existing_addr:*/ SocketAddress) -> bool,
    {
        let entry = self.get_or_create_entry(addr);
        let existing_addr = *entry;

        let result = if existing_addr == *addr {
            None
        } else if can_replace(existing_addr) {
            *entry = *addr;
            Some(existing_addr)
        } else {
            Some(*addr)
        };

        self.check_consistency();
        result
    }

    #[allow(unused)]
    pub fn addr_count(&self) -> usize {
        self.addresses.len()
    }

    fn allocate_id(&mut self) -> EntryId {
        let mut next_id = self.next_id();

        if next_id >= self.id_max {
            self.rebuild_ids();
            next_id = self.next_id();
            assert!(next_id < self.id_max);
        }

        next_id
    }

    fn next_id(&self) -> EntryId {
        self.addresses.iter().last().map_or(0, |(id, _)| *id + 1)
    }

    fn rebuild_ids(&mut self) {
        let mut new_addresses = BTreeMap::new();
        let mut id_map = BTreeMap::new();

        for (next_id, (cur_id, addr)) in (0..).zip(self.addresses.iter()) {
            new_addresses.insert(next_id, *addr);
            id_map.insert(*cur_id, next_id);
        }

        self.addresses = new_addresses;

        for bucket in self.buckets.rows_mut() {
            for id in bucket {
                if *id < self.id_max {
                    *id = *id_map
                        .get(id)
                        .expect("An id referenced by buckets wasn't in addresses: {id}");
                }
            }
        }
    }

    #[cfg(test)]
    pub fn set_should_check_consistency(&mut self, val: bool) {
        self.should_check_consistency = val;
    }

    fn check_consistency(&self) {
        #[cfg(test)]
        if self.should_check_consistency {
            let mut entries_in_buckets = 0;
            for (bucket_idx, bucket) in self.buckets.rows().enumerate() {
                for (bucket_pos, id) in bucket.iter().enumerate() {
                    if *id < self.id_max {
                        let addr = self.addresses.get(id).expect("Id must be in the map");
                        let (actual_bucket_idx, actual_bucket_pos) = self.bucket_coords(addr);
                        assert_eq!(actual_bucket_idx, bucket_idx);
                        assert_eq!(actual_bucket_pos, bucket_pos);

                        entries_in_buckets += 1;
                    } else {
                        assert!(!self.addresses.contains_key(id));
                    }
                }
            }

            assert_eq!(entries_in_buckets, self.addresses.len());
        }
    }

    pub fn addr_iter(&self) -> impl Iterator<Item = &SocketAddress> + '_ {
        self.addresses.values()
    }
}

#[cfg(test)]
pub mod test_utils {
    use std::{
        collections::{btree_map::Entry, BTreeSet},
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    };

    use randomness::Rng;

    use super::*;

    pub fn make_random_address(rng: &mut impl Rng) -> SocketAddress {
        let addr_v4 = SocketAddrV4::new(
            Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen()),
            // Note: addresses with zero port are never considered discoverable
            // (PeerAddress::.as_discoverable_socket_address always returns None for them),
            // so some test may malfunction if such an address is generated.
            // On the other hand, in general, it doesn't make much sense to produce random socket
            // addresses with zero port, so we disable it on this level.
            rng.gen_range(1..=u16::MAX),
        );
        SocketAddress::new(SocketAddr::V4(addr_v4))
    }

    pub fn make_non_colliding_addresses(
        tables: &[&Table],
        count: usize,
        rng: &mut impl Rng,
    ) -> Vec<SocketAddress> {
        make_non_colliding_addresses_impl(tables, count, false, rng)
    }

    pub fn make_non_colliding_addresses_in_distinct_addr_groups(
        tables: &[&Table],
        count: usize,
        rng: &mut impl Rng,
    ) -> Vec<SocketAddress> {
        make_non_colliding_addresses_impl(tables, count, true, rng)
    }

    fn make_non_colliding_addresses_impl(
        tables: &[&Table],
        count: usize,
        in_distinct_addr_groups: bool,
        rng: &mut impl Rng,
    ) -> Vec<SocketAddress> {
        assert!(count != 0);

        let mut idx_set = BTreeSet::new();
        let mut addr_groups = BTreeSet::new();
        let mut result = Vec::with_capacity(count);

        loop {
            let addr = make_random_address(rng);
            let addr_group = AddressGroup::from_peer_address(&addr.as_peer_address());

            let non_colliding = tables.iter().enumerate().all(|(table_idx, table)| {
                let (bucket_idx, bucket_pos) = table.bucket_coords(&addr);
                !idx_set.contains(&(table_idx, bucket_idx, bucket_pos))
            });

            if non_colliding && (!in_distinct_addr_groups || !addr_groups.contains(&addr_group)) {
                result.push(addr);

                if result.len() == count {
                    break;
                }

                if in_distinct_addr_groups {
                    addr_groups.insert(addr_group);
                }

                for (table_idx, table) in tables.iter().enumerate() {
                    let (bucket_idx, bucket_pos) = table.bucket_coords(&addr);
                    idx_set.insert((table_idx, bucket_idx, bucket_pos));
                }
            }
        }

        result
    }

    pub fn filter_out_collisions(
        table: &Table,
        addresses: impl Iterator<Item = SocketAddress>,
    ) -> impl Iterator<Item = SocketAddress> {
        let mut map = BTreeMap::new();

        for addr in addresses {
            let (bucket_idx, bucket_pos) = table.bucket_coords(&addr);

            if let Entry::Vacant(entry) = map.entry((bucket_idx, bucket_pos)) {
                entry.insert(addr);
            }
        }

        map.into_values()
    }

    pub fn make_colliding_address(table: &Table, addr: &SocketAddress) -> SocketAddress {
        let (bucket_idx, bucket_pos) = table.bucket_coords(addr);

        const MAX_ATTEMPTS: u32 = 1_000_000;

        for i in 0..MAX_ATTEMPTS {
            let other_addr = SocketAddress::new(SocketAddr::V4(SocketAddrV4::new(i.into(), 0)));
            let (other_bucket_idx, other_bucket_pos) = table.bucket_coords(&other_addr);

            if (other_bucket_idx, other_bucket_pos) == (bucket_idx, bucket_pos) {
                return other_addr;
            }
        }

        panic!("No collision after traversing {MAX_ATTEMPTS} consecutive addresses");
    }

    pub fn assert_addresses_eq(table: &Table, expected_addrs: &[SocketAddress]) {
        let expected_addrs: BTreeSet<_> = expected_addrs.iter().collect();
        let actual_addrs: BTreeSet<_> = table.addresses.values().collect();
        assert_eq!(actual_addrs, expected_addrs);
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use ::test_utils::random::{make_seedable_rng, Seed};

    use super::{test_utils::*, *};

    fn get_id_of(table: &Table, addr: &SocketAddress) -> Option<EntryId> {
        table.addresses.iter().find_map(|(id, a)| (a == addr).then_some(*id))
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn basic_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut table = Table::new_generic(2, 2, Salt::from_u64(0), 4);

        let addr = make_random_address(&mut rng);
        let colliding_addr = make_colliding_address(&table, &addr);
        assert_ne!(colliding_addr, addr);

        // The table is empty
        assert!(table.entry(&addr).is_none());
        assert_addresses_eq(&table, &[]);

        // Get-or-create addr
        assert_eq!(*table.get_or_create_entry(&addr), addr);
        assert_addresses_eq(&table, &[addr]);
        assert_eq!(table.entry(&addr), Some(&addr));
        assert_eq!(table.entry(&colliding_addr), Some(&addr));

        // Get-or-create address colliding_addr, the result should be the same -
        // colliding_addr shouldn't be recorded anywhere.
        assert_eq!(*table.get_or_create_entry(&colliding_addr), addr);
        assert_addresses_eq(&table, &[addr]);
        assert_eq!(table.entry(&addr), Some(&addr));
        assert_eq!(table.entry(&colliding_addr), Some(&addr));

        // Try removing colliding_addr; again, this shouldn't change anything.
        table.remove(&colliding_addr);
        assert_addresses_eq(&table, &[addr]);
        assert_eq!(table.entry(&addr), Some(&addr));
        assert_eq!(table.entry(&colliding_addr), Some(&addr));

        // Remove addr, the table becomes empty
        table.remove(&addr);
        assert!(table.entry(&addr).is_none());
        assert!(table.entry(&colliding_addr).is_none());
        assert_addresses_eq(&table, &[]);
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_replace(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut table = Table::new_generic(2, 2, Salt::from_u64(0), 4);

        let addr = make_random_address(&mut rng);
        let colliding_addr = make_colliding_address(&table, &addr);
        assert_ne!(colliding_addr, addr);

        // Add addr via 'replace'
        assert_eq!(table.replace(&addr), None);
        assert_addresses_eq(&table, &[addr]);
        assert_eq!(table.entry(&addr), Some(&addr));
        assert_eq!(table.entry(&colliding_addr), Some(&addr));

        // Second 'replace' with the same address should also return None.
        assert_eq!(table.replace(&addr), None);

        // Calling 'replace' with colliding_addr actually replaces the address.
        assert_eq!(table.replace(&colliding_addr), Some(addr));
        assert_addresses_eq(&table, &[colliding_addr]);
        assert_eq!(table.entry(&addr), Some(&colliding_addr));
        assert_eq!(table.entry(&colliding_addr), Some(&colliding_addr));
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_replace_if(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut table = Table::new_generic(2, 2, Salt::from_u64(0), 4);

        let addr = make_random_address(&mut rng);
        let colliding_addr = make_colliding_address(&table, &addr);
        assert_ne!(colliding_addr, addr);

        // Add addr via 'replace_if'; it should behave just like 'replace'; the closure
        // shouldn't be called.
        assert_eq!(
            table.replace_if(&addr, |_| {
                unreachable!();
            }),
            None
        );
        assert_addresses_eq(&table, &[addr]);
        assert_eq!(table.entry(&addr), Some(&addr));
        assert_eq!(table.entry(&colliding_addr), Some(&addr));

        // Second 'replace' with the same address behaves the same.
        assert_eq!(
            table.replace_if(&addr, |_| {
                unreachable!();
            }),
            None
        );

        // Calling 'replace' with colliding_addr actually invokes the closure; returning false
        // from it won't change anything though.
        assert_eq!(
            table.replace_if(&colliding_addr, |existing_addr| {
                assert_eq!(existing_addr, addr);
                false
            }),
            Some(colliding_addr)
        );
        assert_addresses_eq(&table, &[addr]);
        assert_eq!(table.entry(&addr), Some(&addr));
        assert_eq!(table.entry(&colliding_addr), Some(&addr));

        // Now return true from the closure; the address is replaced.
        assert_eq!(
            table.replace_if(&colliding_addr, |existing_addr| {
                assert_eq!(existing_addr, addr);
                true
            }),
            Some(addr)
        );
        assert_addresses_eq(&table, &[colliding_addr]);
        assert_eq!(table.entry(&addr), Some(&colliding_addr));
        assert_eq!(table.entry(&colliding_addr), Some(&colliding_addr));
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_full_table(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut table = Table::new_generic(2, 2, Salt::from_u64(0), 4);

        let addrs = make_non_colliding_addresses(&[&table], 4, &mut rng);

        assert_eq!(*table.get_or_create_entry(&addrs[0]), addrs[0]);
        assert_eq!(*table.get_or_create_entry(&addrs[1]), addrs[1]);
        assert_eq!(*table.get_or_create_entry(&addrs[2]), addrs[2]);
        assert_eq!(*table.get_or_create_entry(&addrs[3]), addrs[3]);
        assert_addresses_eq(&table, &addrs);
    }

    #[tracing::instrument(skip(seed))]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_id_rebuilding(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let mut table = Table::new_generic(2, 2, Salt::from_u64(0), 4);

        let addrs = make_non_colliding_addresses(&[&table], 2, &mut rng);

        assert_eq!(table.next_id(), 0);

        table.replace(&addrs[0]);
        assert_eq!(table.next_id(), 1);

        table.replace(&addrs[1]);
        assert_eq!(table.next_id(), 2);

        assert_addresses_eq(&table, &addrs);
        assert_eq!(get_id_of(&table, &addrs[0]), Some(0));
        assert_eq!(get_id_of(&table, &addrs[1]), Some(1));

        table.remove(&addrs[0]);
        table.replace(&addrs[0]);
        assert_eq!(table.next_id(), 3);
        assert_eq!(get_id_of(&table, &addrs[0]), Some(2));
        assert_eq!(get_id_of(&table, &addrs[1]), Some(1));

        table.remove(&addrs[1]);
        table.replace(&addrs[1]);
        assert_eq!(table.next_id(), 4);
        assert_eq!(get_id_of(&table, &addrs[0]), Some(2));
        assert_eq!(get_id_of(&table, &addrs[1]), Some(3));

        table.remove(&addrs[0]);
        table.replace(&addrs[0]);
        assert_eq!(table.next_id(), 2);
        assert_eq!(get_id_of(&table, &addrs[0]), Some(1));
        assert_eq!(get_id_of(&table, &addrs[1]), Some(0));
    }
}
