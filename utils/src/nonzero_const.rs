// Copyright (c) 2021-2024 RBB S.r.l
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

//! A bunch of macros that create NonZeroXXX types from literals or constants, producing
//! a compilation error if the value is zero.
//! E.g. this will compile:
//! ```
//! let num = utils::const_nz_u8!(123);
//! ```
//! and this will not:
//! ```compile_fail
//! let num = utils::const_nz_u8!(0);
//! ```
//! This will compile too:
//! ```
//! const NUM: u8 = 123;
//! let num = utils::const_nz_u8!(NUM * 2);
//! ```
//! and this will not:
//! ```compile_fail
//! const NUM: u8 = 0;
//! let num = utils::const_nz_u8!(NUM * 2);
//! ```

#[macro_export]
macro_rules! const_nz_u8 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroU8, $value)
    };
}

#[macro_export]
macro_rules! const_nz_i8 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroI8, $value)
    };
}

#[macro_export]
macro_rules! const_nz_u16 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroU16, $value)
    };
}

#[macro_export]
macro_rules! const_nz_i16 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroI16, $value)
    };
}

#[macro_export]
macro_rules! const_nz_u32 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroU32, $value)
    };
}

#[macro_export]
macro_rules! const_nz_i32 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroI32, $value)
    };
}

#[macro_export]
macro_rules! const_nz_u64 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroU64, $value)
    };
}

#[macro_export]
macro_rules! const_nz_i64 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroI64, $value)
    };
}

#[macro_export]
macro_rules! const_nz_u128 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroU128, $value)
    };
}

#[macro_export]
macro_rules! const_nz_i128 {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroI128, $value)
    };
}

#[macro_export]
macro_rules! const_nz_usize {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroUsize, $value)
    };
}

#[macro_export]
macro_rules! const_nz_isize {
    ($value:expr) => {
        $crate::const_nz_impl!(NonZeroIsize, $value)
    };
}

#[macro_export]
macro_rules! const_nz_impl {
    ($non_zero_type:ty, $value:expr) => {
        paste::paste! {
            {
                const RET: std::num::$non_zero_type = {
                    match std::num::$non_zero_type::new($value) {
                        Some(val) => val,
                        None => {
                            panic!("Value must not be zero")
                        }
                    }
                };
                RET
            }
        }
    };
}
