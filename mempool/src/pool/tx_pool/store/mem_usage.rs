// Copyright (c) 2022 RBB S.r.l
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

//! Estimate and track memory usage taken by data structures.

use std::{cmp, mem};

use common::chain::{
    htlc::HashedTimelockContract,
    signature::inputsig::InputWitness,
    stakelock::StakePoolData,
    tokens::{NftIssuance, TokenIssuance},
    SignedTransaction, TxInput, TxOutput,
};
use logging::log;

use super::{TxDependency, TxMempoolEntry};

/// Structure that stores the current memory usage and keeps track of its changes
#[derive(Debug)]
pub struct MemUsageTracker {
    current_usage: usize,
    peak_usage: usize,
}

impl MemUsageTracker {
    pub fn new() -> Self {
        Self {
            current_usage: 0,
            peak_usage: 0,
        }
    }

    pub fn get_usage(&self) -> usize {
        self.current_usage
    }

    fn add(&mut self, amount: usize) {
        let old = self.current_usage;
        self.current_usage += amount;
        self.peak_usage = cmp::max(self.current_usage, self.peak_usage);
        self.log_change(old);
    }

    fn sub(&mut self, amount: usize) {
        let old = self.current_usage;
        self.current_usage -= amount;
        self.log_change(old);
    }

    fn log_change(&self, old: usize) {
        let new = self.current_usage;
        log::trace!("Updated memory tracker {self:p}: {old} bytes => {new} bytes");
    }

    /// Start tracking an object for memory consumption
    pub fn track<T: MemoryUsage, D: DropPolicy + Default>(&mut self, obj: T) -> Tracked<T, D> {
        self.add(obj.indirect_memory_usage());
        let drop_policy = D::default();
        Tracked { obj, drop_policy }
    }

    /// Stop tracking memory consumption of an object
    pub fn release<T: MemoryUsage, D: DropPolicy>(&mut self, tracked: Tracked<T, D>) -> T {
        self.sub(tracked.indirect_memory_usage());
        Self::forget(tracked)
    }

    /// Forget about the object being tracked without updating the tracker.
    ///
    /// Useful during tear down when the tracker is no longer in use. If the memory usage
    /// information is supposed to be updated, use [Self::release].
    pub fn forget<T, D: DropPolicy>(mut tracked: Tracked<T, D>) -> T {
        tracked.drop_policy.on_release();
        tracked.obj
    }

    /// Modify given object tracked for memory usage
    ///
    /// This is the only way to legally modify an object under memory tracking. This method is
    /// given the object to modify and a closure which performs the modifications. The memory taken
    /// up by the object is sampled before and after the modifications and the change is recorded
    /// in the tracker. Closure is also given access to the tracker in case more tracked objects
    /// need to be created/modified/dropped in the closure body.
    pub fn modify<T: MemoryUsage, D, R>(
        &mut self,
        tracked: &mut Tracked<T, D>,
        modify_fn: impl for<'a> FnOnce(&'a mut T, &'a mut MemUsageTracker) -> R,
    ) -> R {
        let obj = &mut tracked.obj;

        let usage_before = obj.indirect_memory_usage();
        let result = modify_fn(obj, self);
        let usage_after = obj.indirect_memory_usage();

        match usage_before.cmp(&usage_after) {
            cmp::Ordering::Equal => (),
            cmp::Ordering::Less => self.add(usage_after - usage_before),
            cmp::Ordering::Greater => self.sub(usage_before - usage_after),
        }

        result
    }
}

/// A data structure which has its memory consumption tracked
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug)]
#[must_use = "Memory-tracked object dropped without using Tracked::release"]
pub struct Tracked<T, D = NoOpDropPolicy> {
    obj: T,
    drop_policy: D,
}

/// We can freely create tracked objects without a tracker provided it does not contribute anything
/// to the memory consumption accumulator.
impl<T: ZeroUsageDefault, D: Default> Default for Tracked<T, D> {
    fn default() -> Self {
        let obj = T::default();
        assert_eq!(
            obj.indirect_memory_usage(),
            0,
            "Default not zero-size despite being marked as such"
        );

        let drop_policy = D::default();
        Self { obj, drop_policy }
    }
}

/// The tracked object can be accessed in an immutable way any time.
///
/// This means memory tracking can be circumvented using interior mutability but we ignore the issue
/// here as the data structures used in mempool do not use interior mutability.
impl<T, D> std::ops::Deref for Tracked<T, D> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.obj
    }
}

/// What to do with a [Tracked] object if it's dropped without being released. The actual handling
/// of the drop logic is done in the policy type's Drop implementation.
pub trait DropPolicy {
    fn on_release(&mut self) {}
}

/// Trivial drop policy that does nothing
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Default)]
pub struct NoOpDropPolicy;

impl DropPolicy for NoOpDropPolicy {}

/// Drop policy that asserts if the object has not been properly released
#[cfg(test)]
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Default)]
pub struct AssertDropPolicy {
    released: bool,
}

#[cfg(test)]
impl DropPolicy for AssertDropPolicy {
    fn on_release(&mut self) {
        self.released = true;
    }
}

#[cfg(test)]
impl Drop for AssertDropPolicy {
    fn drop(&mut self) {
        if !self.released {
            log::error!("A memory-tracked value dropped without being released");

            #[allow(clippy::manual_assert)]
            if !std::thread::panicking() {
                panic!("A memory-tracked value dropped without being released");
            }
        }
    }
}

// Code to estimate size taken up by [std::collections::BTreeSet] or [std::collections::BTreeMap].
mod btree {
    // The following structs are laid out in the same way as the real standard library equivalents
    // to give a reasonably precise estimation of their sizes. It is possible that the library
    // implementations change in the future. In that case, the estimation becomes less precise
    // although hopefully will remain good enough for our purposes until the structs below are
    // updated to reflect the change. It's still just an estimate after all.

    const B: usize = 6; // the B parameter for the B-tree
    const BF: usize = 2 * B; // branching factor
    const CAP: usize = BF - 1; // data capacity per node

    struct _LeafNode<K, V> {
        _parent: *mut (),
        _parent_idx: u16,
        _len: u16,
        _keys: [K; CAP],
        _vals: [V; CAP],
    }

    struct _InternalNode<K, V> {
        _data: _LeafNode<K, V>,
        _children: [*mut (); BF],
    }

    /// Estimate the memory usage of the B-tree structure.
    ///
    /// This includes the space taken up by the keys and values stored in the tree. It does NOT
    /// include data pointed to by keys and values indirectly (e.g. via `Box` or `Vec`).
    pub fn usage<K, V>(num_elems: usize) -> usize {
        // Use u64 internally to avoid possible overflow issues on 32-bit platforms
        let num_elems = num_elems as u64;

        // Size of B-tree nodes:
        let leaf_size = std::mem::size_of::<_LeafNode<K, V>>() as u64;
        let internal_size = std::mem::size_of::<_InternalNode<K, V>>() as u64;

        // Size of all leaf nodes.
        let leaves = (leaf_size * num_elems) / CAP as u64;

        // Size of internal nodes. We add extra 10% overhead for all the levels of the tree
        let elems_per_internal_node = (CAP * BF) as u64;
        let internals = (internal_size * num_elems * 11) / (elems_per_internal_node * 10);

        // Total size of the B-tree structure. Assuming nodes are on average 75% full,
        // an additional overhead is added for the unused occupied space.
        let total = 4 * (leaves + internals) / 3;

        total as usize
    }
}

/// Trait for data types capable of reporting their current memory usage
///
/// TODO: Make this a derivable trait so the `impl`s react automatically to changes.
pub trait MemoryUsage {
    /// Get amount of memory taken by the data owned by `self` (e.g. if it contains `Box` or `Vec`)
    fn indirect_memory_usage(&self) -> usize;
}

/// Total memory usage (indirectly by pointers + for the object itself)
fn total_memory_usage<T: MemoryUsage>(val: &T) -> usize {
    val.indirect_memory_usage() + mem::size_of::<T>()
}

macro_rules! impl_no_indirect_memory_usage {
    ($($ty:ty),* $(,)?) => {
        $(
            impl MemoryUsage for $ty {
                fn indirect_memory_usage(&self) -> usize { 0 }
            }
        )*
    };
}

impl_no_indirect_memory_usage!((), bool, usize, u8, u16, u32, u64, u128);

impl<K, V> MemoryUsage for std::collections::BTreeMap<K, V> {
    /// The mem usage for [BTreeMap].
    ///
    /// Includes the nodes and the key and value data stored in the nodes. It does not, however,
    /// include the memory taken up by data keys and values point to indirectly. Any indirect data
    /// has to be tracked separately. This is so that the memory usage of the B-tree map/set can be
    /// calculated from the number of elements alone without any expensive traversals.
    fn indirect_memory_usage(&self) -> usize {
        btree::usage::<K, V>(self.len())
    }
}

impl<K> MemoryUsage for std::collections::BTreeSet<K> {
    /// Same limitation as for `BTreeMap` also applies here
    fn indirect_memory_usage(&self) -> usize {
        btree::usage::<K, ()>(self.len())
    }
}

impl<T: MemoryUsage> MemoryUsage for Option<T> {
    fn indirect_memory_usage(&self) -> usize {
        self.as_ref().map_or(0, |x| x.indirect_memory_usage())
    }
}

impl<T: MemoryUsage> MemoryUsage for &[T] {
    fn indirect_memory_usage(&self) -> usize {
        self.iter().map(T::indirect_memory_usage).sum::<usize>() + mem::size_of_val::<[T]>(*self)
    }
}

impl<T: MemoryUsage> MemoryUsage for Vec<T> {
    fn indirect_memory_usage(&self) -> usize {
        self.as_slice().indirect_memory_usage()
    }
}

impl<T: MemoryUsage> MemoryUsage for Box<T> {
    fn indirect_memory_usage(&self) -> usize {
        total_memory_usage::<T>(self.as_ref())
    }
}

impl<T> MemoryUsage for common::primitives::Id<T> {
    fn indirect_memory_usage(&self) -> usize {
        0
    }
}

impl MemoryUsage for TxMempoolEntry {
    fn indirect_memory_usage(&self) -> usize {
        let transaction = self.transaction().indirect_memory_usage();
        let parents = self.parents.indirect_memory_usage();
        let children = self.children.indirect_memory_usage();
        transaction + parents + children
    }
}

impl MemoryUsage for SignedTransaction {
    /// Only data included indirectly (via pointers). The actual object usage is already contained
    /// in the B-tree map usage.
    fn indirect_memory_usage(&self) -> usize {
        let ins = self.inputs().indirect_memory_usage();
        let outs = self.outputs().indirect_memory_usage();
        let sigs = self.signatures().indirect_memory_usage();
        ins + outs + sigs
    }
}

impl MemoryUsage for TxOutput {
    fn indirect_memory_usage(&self) -> usize {
        match self {
            TxOutput::Transfer(_, _) => 0,
            TxOutput::LockThenTransfer(_, _, _) => 0,
            TxOutput::Burn(_) => 0,
            TxOutput::CreateStakePool(_, pd) => pd.indirect_memory_usage(),
            TxOutput::ProduceBlockFromStake(_, _) => 0,
            TxOutput::CreateDelegationId(_, _) => 0,
            TxOutput::DelegateStaking(_, _) => 0,
            TxOutput::IssueFungibleToken(issuance) => issuance.indirect_memory_usage(),
            TxOutput::IssueNft(_, issuance, _) => issuance.indirect_memory_usage(),
            TxOutput::DataDeposit(v) => v.indirect_memory_usage(),
            TxOutput::Htlc(_, htlc) => htlc.indirect_memory_usage(),
            TxOutput::CreateOrder(_) => 0,
        }
    }
}

impl MemoryUsage for InputWitness {
    fn indirect_memory_usage(&self) -> usize {
        match self {
            InputWitness::NoSignature(data) => data.indirect_memory_usage(),
            InputWitness::Standard(sig) => sig.raw_signature().indirect_memory_usage(),
        }
    }
}

impl_no_indirect_memory_usage!(
    StakePoolData,
    TxDependency,
    TxInput,
    TokenIssuance,
    NftIssuance,
    HashedTimelockContract
);

/// Types where the object created by T::default() takes no indirect memory.
pub trait ZeroUsageDefault: MemoryUsage + Default {}

impl<K, V> ZeroUsageDefault for std::collections::BTreeMap<K, V> {}
impl<K> ZeroUsageDefault for std::collections::BTreeSet<K> {}
impl<T: MemoryUsage> ZeroUsageDefault for Vec<T> {}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;
    use test_utils::random::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn box_size(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let data: Vec<u8> = (0u32..rng.gen_range(0..=1000)).map(|_| rng.gen()).collect();
        let box_data = Box::new(data.clone());
        assert_eq!(total_memory_usage(&data), box_data.indirect_memory_usage());
    }

    #[allow(unused_allocation)]
    fn check_indirect_primitive<T: MemoryUsage + Clone>(data: T) {
        assert_eq!(data.indirect_memory_usage(), 0);
        assert_eq!(Box::new(data).indirect_memory_usage(), mem::size_of::<T>());
    }

    #[test]
    fn primitives() {
        check_indirect_primitive(());
        check_indirect_primitive(false);
        check_indirect_primitive(15u8);
        check_indirect_primitive(15u16);
        check_indirect_primitive(15u32);
        check_indirect_primitive(15u8);
        check_indirect_primitive(15u16);
        check_indirect_primitive(15u32);
        check_indirect_primitive(15u64);
        check_indirect_primitive(15u128);
        check_indirect_primitive(15usize);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn track_vecs(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let mut tracker = MemUsageTracker::new();
        let mut data: Tracked<Vec<u8>, NoOpDropPolicy> = Tracked::default();

        let len1 = rng.gen_range(0..=100);
        tracker.modify(&mut data, |data, _| {
            data.extend((0..len1).map(|_| rng.gen::<u8>()))
        });
        assert_eq!(tracker.get_usage(), len1);

        let len2 = rng.gen_range(0..=300);
        tracker.modify(&mut data, |data, _| {
            data.extend((0..len2).map(|_| rng.gen::<u8>()))
        });
        assert_eq!(tracker.get_usage(), len1 + len2);
    }

    #[test]
    #[should_panic = "dropped without being released"]
    fn check_assert_drop_policy_works() {
        let mut tracker = MemUsageTracker::new();
        let data: Tracked<Box<u32>, AssertDropPolicy> = tracker.track(Box::new(123456u32));
        assert_eq!(tracker.get_usage(), 4);
        mem::drop(data);
    }

    #[test]
    fn check_assert_drop_policy_works_happy_case() {
        let mut tracker = MemUsageTracker::new();
        let data: Tracked<Box<u32>, AssertDropPolicy> = tracker.track(Box::new(123456u32));
        assert_eq!(tracker.get_usage(), 4);
        mem::drop(tracker.release(data));
        assert_eq!(tracker.get_usage(), 0);
    }
}
