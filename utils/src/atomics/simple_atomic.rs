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

//! This module implements "simplified" atomic types, which use predefined memory orderings.
//!
//! They come in three variants: one is the "relaxed" atomics, whose operations always use
//! the "Relaxed" memory ordering, and the other two are the "synchronizing" ones, which use
//! "acquire-release" and "sequentially-consistent" orderings respectively.
//!
//! The reason for having them is that, first of all, there are basically two use cases
//! for an atomic type:
//! 1) a low-level thread synchronization primitive;
//! 2) a way to get interior mutability and/or circumvent borrow checker's restrictions.
//!
//! In the first case, the atomic operations should normally use the "synchronizing"
//! memory orderings and in the second case the (generally cheaper) "Relaxed" ordering is enough.
//!
//! Secondly, sometimes atomic types can appear at the API boundary of a module or a package,
//! which may lead to a situation where a load is performed in one module and a store in another.
//! In this case, using the standard atomics effectively breaks encapsulation because,
//! on the one hand, the memory orderings used by modules are their implementation details
//! but, on the other hand, they must still agree with each other. Using a simplified atomic
//! in this case basically encodes the purpose of the atomic in its type's name and makes
//! the orderings a part of the module's interface.

use crate::atomics::{atomic_traits::HasStdAtomic, AtomicNumTrait, AtomicTrait};
use std::marker::PhantomData;

use crate::concurrency_impl::sync::atomic::Ordering;

mod private {
    #[doc(hidden)]
    pub trait Sealed {}
}

/// A predefined set of orderings to use by the [Atomic] type.
pub trait Orderings: private::Sealed {
    const ORD_LOAD: Ordering;
    const ORD_STORE: Ordering;
    const ORD_LOAD_STORE: Ordering;
}

/// A generic implementation of a simplified atomic type that uses a predefined set
/// of memory orderings.
pub struct Atomic<T, Ord>(<T as HasStdAtomic>::AtomicType, PhantomData<Ord>)
where
    T: HasStdAtomic;

/// Methods that are not specific to atomic types.
impl<T, Ord> Atomic<T, Ord>
where
    T: HasStdAtomic,
    <T as HasStdAtomic>::AtomicType: From<T>,
    Ord: Orderings,
{
    pub fn new(val: T) -> Self {
        let inner: <T as HasStdAtomic>::AtomicType = val.into();
        Self(inner, PhantomData)
    }

    pub fn inner(&self) -> &<T as HasStdAtomic>::AtomicType {
        &self.0
    }

    pub fn into_inner(self) -> <T as HasStdAtomic>::AtomicType {
        self.0
    }
}

/// Methods common to all atomic types.
impl<T, Ord> Atomic<T, Ord>
where
    T: HasStdAtomic,
    <T as HasStdAtomic>::AtomicType: AtomicTrait<Type = T>,
    Ord: Orderings,
{
    pub fn load(&self) -> T {
        self.0.load(Ord::ORD_LOAD)
    }

    pub fn store(&self, val: T) {
        self.0.store(val, Ord::ORD_STORE)
    }

    pub fn swap(&self, val: T) -> T {
        self.0.swap(val, Ord::ORD_LOAD_STORE)
    }

    // Note: no compare_and_swap because it's deprecated

    pub fn compare_exchange(&self, current: T, new: T) -> Result<T, T> {
        self.0.compare_exchange(current, new, Ord::ORD_LOAD_STORE, Ord::ORD_LOAD)
    }

    pub fn compare_exchange_weak(&self, current: T, new: T) -> Result<T, T> {
        self.0.compare_exchange_weak(current, new, Ord::ORD_LOAD_STORE, Ord::ORD_LOAD)
    }

    pub fn fetch_update<F>(&self, f: F) -> Result<T, T>
    where
        F: FnMut(T) -> Option<T>,
    {
        self.0.fetch_update(Ord::ORD_LOAD_STORE, Ord::ORD_LOAD, f)
    }

    pub fn fetch_and(&self, val: T) -> T {
        self.0.fetch_and(val, Ord::ORD_LOAD_STORE)
    }

    pub fn fetch_nand(&self, val: T) -> T {
        self.0.fetch_nand(val, Ord::ORD_LOAD_STORE)
    }

    pub fn fetch_or(&self, val: T) -> T {
        self.0.fetch_or(val, Ord::ORD_LOAD_STORE)
    }

    pub fn fetch_xor(&self, val: T) -> T {
        self.0.fetch_xor(val, Ord::ORD_LOAD_STORE)
    }
}

/// Methods that are specific to atomic numbers.
impl<T, Ord> Atomic<T, Ord>
where
    T: HasStdAtomic,
    <T as HasStdAtomic>::AtomicType: AtomicNumTrait<Type = T>,
    Ord: Orderings,
{
    pub fn fetch_add(&self, val: T) -> T {
        self.0.fetch_add(val, Ord::ORD_LOAD_STORE)
    }

    pub fn fetch_sub(&self, val: T) -> T {
        self.0.fetch_sub(val, Ord::ORD_LOAD_STORE)
    }

    pub fn fetch_max(&self, val: T) -> T {
        self.0.fetch_max(val, Ord::ORD_LOAD_STORE)
    }

    pub fn fetch_min(&self, val: T) -> T {
        self.0.fetch_min(val, Ord::ORD_LOAD_STORE)
    }
}

impl<T, Ord> Default for Atomic<T, Ord>
where
    T: HasStdAtomic + Default,
    <T as HasStdAtomic>::AtomicType: From<T>,
    Ord: Orderings,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T, Ord> From<T> for Atomic<T, Ord>
where
    T: HasStdAtomic,
    <T as HasStdAtomic>::AtomicType: From<T>,
    Ord: Orderings,
{
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T, Ord> std::fmt::Debug for Atomic<T, Ord>
where
    T: HasStdAtomic + std::fmt::Debug,
    <T as HasStdAtomic>::AtomicType: AtomicTrait<Type = T>,
    Ord: Orderings,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note: here we deliberately don't delegate to the wrapped type's Debug implementation,
        // so that the output doesn't depend on whether we're running with loom ot not.
        // Also note that we always use the Relaxed ordering for printing, just like
        // the standard atomic types do.
        std::fmt::Debug::fmt(&self.0.load(Ordering::Relaxed), f)
    }
}

#[doc(hidden)]
pub struct RelaxedOrderings;

impl Orderings for RelaxedOrderings {
    const ORD_LOAD: Ordering = Ordering::Relaxed;
    const ORD_STORE: Ordering = Ordering::Relaxed;
    const ORD_LOAD_STORE: Ordering = Ordering::Relaxed;
}

impl private::Sealed for RelaxedOrderings {}

/// The "relaxed" variant of the atomic.
pub type RelaxedAtomic<T> = Atomic<T, RelaxedOrderings>;

pub type RelaxedAtomicBool = RelaxedAtomic<bool>;
pub type RelaxedAtomicI8 = RelaxedAtomic<i8>;
pub type RelaxedAtomicU8 = RelaxedAtomic<u8>;
pub type RelaxedAtomicI16 = RelaxedAtomic<i16>;
pub type RelaxedAtomicU16 = RelaxedAtomic<u16>;
pub type RelaxedAtomicI32 = RelaxedAtomic<i32>;
pub type RelaxedAtomicU32 = RelaxedAtomic<u32>;
pub type RelaxedAtomicI64 = RelaxedAtomic<i64>;
pub type RelaxedAtomicU64 = RelaxedAtomic<u64>;
pub type RelaxedAtomicIsize = RelaxedAtomic<isize>;
pub type RelaxedAtomicUsize = RelaxedAtomic<usize>;

#[doc(hidden)]
pub struct AcqRelOrderings;

impl Orderings for AcqRelOrderings {
    const ORD_LOAD: Ordering = Ordering::Acquire;
    const ORD_STORE: Ordering = Ordering::Release;
    const ORD_LOAD_STORE: Ordering = Ordering::AcqRel;
}

impl private::Sealed for AcqRelOrderings {}

/// The "acquire-release" variant of the atomic.
///
pub type AcqRelAtomic<T> = Atomic<T, AcqRelOrderings>;

pub type AcqRelAtomicBool = AcqRelAtomic<bool>;
pub type AcqRelAtomicI8 = AcqRelAtomic<i8>;
pub type AcqRelAtomicU8 = AcqRelAtomic<u8>;
pub type AcqRelAtomicI16 = AcqRelAtomic<i16>;
pub type AcqRelAtomicU16 = AcqRelAtomic<u16>;
pub type AcqRelAtomicI32 = AcqRelAtomic<i32>;
pub type AcqRelAtomicU32 = AcqRelAtomic<u32>;
pub type AcqRelAtomicI64 = AcqRelAtomic<i64>;
pub type AcqRelAtomicU64 = AcqRelAtomic<u64>;
pub type AcqRelAtomicIsize = AcqRelAtomic<isize>;
pub type AcqRelAtomicUsize = AcqRelAtomic<usize>;

#[doc(hidden)]
pub struct SeqCstOrderings;

impl Orderings for SeqCstOrderings {
    const ORD_LOAD: Ordering = Ordering::SeqCst;
    const ORD_STORE: Ordering = Ordering::SeqCst;
    const ORD_LOAD_STORE: Ordering = Ordering::SeqCst;
}

impl private::Sealed for SeqCstOrderings {}

/// The "sequentially-consistent" variant of the atomic.
///
/// This is more expensive than [AcqRelAtomic] and gives an additional guarantee:
/// there exists a single total order of all SeqCst operations that is observed by all threads.
pub type SeqCstAtomic<T> = Atomic<T, SeqCstOrderings>;

pub type SeqCstAtomicBool = SeqCstAtomic<bool>;
pub type SeqCstAtomicI8 = SeqCstAtomic<i8>;
pub type SeqCstAtomicU8 = SeqCstAtomic<u8>;
pub type SeqCstAtomicI16 = SeqCstAtomic<i16>;
pub type SeqCstAtomicU16 = SeqCstAtomic<u16>;
pub type SeqCstAtomicI32 = SeqCstAtomic<i32>;
pub type SeqCstAtomicU32 = SeqCstAtomic<u32>;
pub type SeqCstAtomicI64 = SeqCstAtomic<i64>;
pub type SeqCstAtomicU64 = SeqCstAtomic<u64>;
pub type SeqCstAtomicIsize = SeqCstAtomic<isize>;
pub type SeqCstAtomicUsize = SeqCstAtomic<usize>;
