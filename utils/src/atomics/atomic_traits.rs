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

//! Atomic traits. Unlike traits from the `atomic_traits` crate, these are implemented
//! for `loom` types too.
//!
//! Note: functions that are not implemented by `loom` atomics (such as `get_mut`) are missing
//! here too.
//! We also omit deprecated functions, such as `compare_and_swap`, and don't support `AtomicPtr`.

use crate::sync::atomic::{
    AtomicBool, AtomicI16, AtomicI32, AtomicI64, AtomicI8, AtomicIsize, AtomicU16, AtomicU32,
    AtomicU64, AtomicU8, AtomicUsize, Ordering,
};

/// A trait that contains basic atomic operations common for all atomic types.
pub trait Atomic {
    type Type;

    fn load(&self, order: Ordering) -> Self::Type;
    fn store(&self, val: Self::Type, order: Ordering);
    fn swap(&self, val: Self::Type, order: Ordering) -> Self::Type;

    fn compare_exchange(
        &self,
        current: Self::Type,
        new: Self::Type,
        success: Ordering,
        failure: Ordering,
    ) -> Result<Self::Type, Self::Type>;

    fn compare_exchange_weak(
        &self,
        current: Self::Type,
        new: Self::Type,
        success: Ordering,
        failure: Ordering,
    ) -> Result<Self::Type, Self::Type>;

    fn fetch_update<F>(
        &self,
        fetch_order: Ordering,
        set_order: Ordering,
        f: F,
    ) -> Result<Self::Type, Self::Type>
    where
        F: FnMut(Self::Type) -> Option<Self::Type>;

    fn fetch_and(&self, val: Self::Type, order: Ordering) -> Self::Type;
    fn fetch_nand(&self, val: Self::Type, order: Ordering) -> Self::Type;
    fn fetch_or(&self, val: Self::Type, order: Ordering) -> Self::Type;
    fn fetch_xor(&self, val: Self::Type, order: Ordering) -> Self::Type;
}

/// A trait that contains atomic operations specific to atomic integers.
pub trait AtomicNum: Atomic {
    fn fetch_add(&self, val: Self::Type, order: Ordering) -> Self::Type;
    fn fetch_sub(&self, val: Self::Type, order: Ordering) -> Self::Type;
    fn fetch_max(&self, val: Self::Type, order: Ordering) -> Self::Type;
    fn fetch_min(&self, val: Self::Type, order: Ordering) -> Self::Type;
}

/// This trait is implemented for primitive types which have an atomic counterpart.
pub trait HasStdAtomic {
    type AtomicType;
}

macro_rules! impl_atomic {
    ($atomic_type:ident, $primitive_type:ident) => {
        impl Atomic for $atomic_type {
            type Type = $primitive_type;

            fn load(&self, order: Ordering) -> Self::Type {
                self.load(order)
            }

            fn store(&self, val: Self::Type, order: Ordering) {
                self.store(val, order)
            }

            fn swap(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.swap(val, order)
            }

            fn compare_exchange(
                &self,
                current: Self::Type,
                new: Self::Type,
                success: Ordering,
                failure: Ordering,
            ) -> Result<Self::Type, Self::Type> {
                self.compare_exchange(current, new, success, failure)
            }

            fn compare_exchange_weak(
                &self,
                current: Self::Type,
                new: Self::Type,
                success: Ordering,
                failure: Ordering,
            ) -> Result<Self::Type, Self::Type> {
                self.compare_exchange_weak(current, new, success, failure)
            }

            fn fetch_update<F>(
                &self,
                fetch_order: Ordering,
                set_order: Ordering,
                f: F,
            ) -> Result<Self::Type, Self::Type>
            where
                F: FnMut(Self::Type) -> Option<Self::Type>,
            {
                self.fetch_update(fetch_order, set_order, f)
            }

            fn fetch_and(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_and(val, order)
            }

            fn fetch_nand(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_nand(val, order)
            }

            fn fetch_or(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_or(val, order)
            }

            fn fetch_xor(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_xor(val, order)
            }
        }

        impl HasStdAtomic for $primitive_type {
            type AtomicType = $atomic_type;
        }
    };
}

macro_rules! impl_atomic_num {
    ($atomic_type:ident, $primitive_type:ident) => {
        impl_atomic! {$atomic_type, $primitive_type}

        impl AtomicNum for $atomic_type {
            fn fetch_add(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_add(val, order)
            }

            fn fetch_sub(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_sub(val, order)
            }

            fn fetch_max(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_max(val, order)
            }

            fn fetch_min(&self, val: Self::Type, order: Ordering) -> Self::Type {
                self.fetch_min(val, order)
            }
        }
    };
}

impl_atomic!(AtomicBool, bool);
impl_atomic_num!(AtomicI8, i8);
impl_atomic_num!(AtomicU8, u8);
impl_atomic_num!(AtomicI16, i16);
impl_atomic_num!(AtomicU16, u16);
impl_atomic_num!(AtomicI32, i32);
impl_atomic_num!(AtomicU32, u32);
impl_atomic_num!(AtomicI64, i64);
impl_atomic_num!(AtomicU64, u64);
impl_atomic_num!(AtomicIsize, isize);
impl_atomic_num!(AtomicUsize, usize);
