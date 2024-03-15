// Copyright (c) 2024 RBB S.r.l
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

use std::num::{
    NonZeroI128, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI8, NonZeroIsize, NonZeroU128,
    NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU8, NonZeroUsize,
};

pub use rpc_description_macro::HasValueHint;

/// Value hint associated with given type
pub trait HasValueHint {
    const HINT_SER: ValueHint;
    const HINT_DE: ValueHint = Self::HINT_SER;
}

/// A compositional way of describing values of RPC arguments and return values
#[derive(PartialEq, Eq, Debug)]
pub enum ValueHint {
    /// Primitive
    Prim(&'static str),

    /// Fixed string literal
    StrLit(&'static str),

    /// A choice between a number of hints
    Choice(&'static [&'static ValueHint]),

    /// A map with static members
    Object(&'static [(&'static str, &'static ValueHint)]),

    /// A dynamic key-value map
    Map(&'static ValueHint, &'static ValueHint),

    /// Array of elements of uniform type
    Array(&'static ValueHint),

    /// Heterogeneous array of elements
    Tuple(&'static [&'static ValueHint]),
}

type VH = ValueHint;

impl ValueHint {
    pub const IRRELEVANT: VH = VH::Prim("IRRELEVANT");
    pub const NOTHING: VH = VH::Prim("nothing");
    pub const NULL: VH = VH::Prim("null");
    pub const BOOL: VH = VH::Prim("bool");
    pub const NUMBER: VH = VH::Prim("number");
    pub const NONZERO_NUMBER: VH = VH::Prim("non-zero number");
    pub const STRING: VH = VH::Prim("string");
    pub const NUMBER_STRING: VH = VH::Prim("number string");
    pub const DECIMAL_STRING: VH = VH::Prim("decimal string");
    pub const BECH32_STRING: VH = VH::Prim("bech32 string");
    pub const HEX_STRING: VH = VH::Prim("hex string");
    pub const GENERIC_OBJECT: VH = VH::Prim("object");
    pub const JSON: VH = VH::Prim("json");
}

impl HasValueHint for () {
    const HINT_SER: VH = VH::NOTHING;
    const HINT_DE: VH = VH::NULL;
}

impl HasValueHint for std::time::Duration {
    const HINT_SER: VH = VH::Tuple(&[&VH::Prim("secs number"), &VH::Prim("nanos number")]);
}

impl<T: HasValueHint + ?Sized> HasValueHint for &T {
    const HINT_SER: VH = T::HINT_SER;
    const HINT_DE: VH = T::HINT_DE;
}

impl<T: HasValueHint + ?Sized> HasValueHint for Box<T> {
    const HINT_SER: VH = T::HINT_SER;
    const HINT_DE: VH = T::HINT_DE;
}

impl<T: HasValueHint> HasValueHint for Option<T> {
    const HINT_SER: VH = VH::Choice(&[&T::HINT_SER, &VH::NULL]);
    const HINT_DE: VH = VH::Choice(&[&T::HINT_DE, &VH::NULL]);
}

impl<T: HasValueHint, E> HasValueHint for Result<T, E> {
    // We report just the "happy path" value hint here. It works as long as the result type is only
    // used in RPC return values (not arguments) and it is the outer-most type wrapper.
    const HINT_SER: VH = T::HINT_SER;
    const HINT_DE: VH = T::HINT_DE;
}

impl<T: HasValueHint> HasValueHint for Vec<T> {
    const HINT_SER: VH = VH::Array(&T::HINT_SER);
    const HINT_DE: VH = VH::Array(&T::HINT_DE);
}

impl<K: HasValueHint, V: HasValueHint> HasValueHint for std::collections::BTreeMap<K, V> {
    const HINT_SER: VH = VH::Map(&K::HINT_SER, &V::HINT_SER);
    const HINT_DE: VH = VH::Map(&K::HINT_DE, &V::HINT_DE);
}

impl<T0: HasValueHint> HasValueHint for (T0,) {
    const HINT_SER: VH = VH::Tuple(&[&T0::HINT_SER]);
    const HINT_DE: VH = VH::Tuple(&[&T0::HINT_DE]);
}

impl<T0: HasValueHint, T1: HasValueHint> HasValueHint for (T0, T1) {
    const HINT_SER: VH = VH::Tuple(&[&T0::HINT_SER, &T1::HINT_SER]);
    const HINT_DE: VH = VH::Tuple(&[&T0::HINT_DE, &T1::HINT_DE]);
}

impl<T0: HasValueHint, T1: HasValueHint, T2: HasValueHint> HasValueHint for (T0, T1, T2) {
    const HINT_SER: VH = VH::Tuple(&[&T0::HINT_SER, &T1::HINT_SER, &T2::HINT_SER]);
    const HINT_DE: VH = VH::Tuple(&[&T0::HINT_DE, &T1::HINT_DE, &T2::HINT_DE]);
}

impl<T0: HasValueHint, T1: HasValueHint, T2: HasValueHint, T3: HasValueHint> HasValueHint
    for (T0, T1, T2, T3)
{
    const HINT_SER: VH = VH::Tuple(&[&T0::HINT_SER, &T1::HINT_SER, &T2::HINT_SER, &T3::HINT_SER]);
    const HINT_DE: VH = VH::Tuple(&[&T0::HINT_DE, &T1::HINT_DE, &T2::HINT_DE, &T3::HINT_DE]);
}

#[macro_export]
macro_rules! impl_value_hint {
    ({$($ty:ty => $hint:expr;)*}) => {
        $($crate::impl_value_hint!($ty => $hint);)*
    };
    ($ty:ty => $hint:expr) => {
        impl $crate::HasValueHint for $ty {
            const HINT_SER: $crate::ValueHint = $hint;
            const HINT_DE: $crate::ValueHint = $hint;
        }
    };
}

impl_value_hint!({
    bool => VH::BOOL;
    i8 => VH::NUMBER;
    u8 => VH::NUMBER;
    i16 => VH::NUMBER;
    u16 => VH::NUMBER;
    i32 => VH::NUMBER;
    u32 => VH::NUMBER;
    i64 => VH::NUMBER;
    u64 => VH::NUMBER;
    i128 => VH::NUMBER;
    u128 => VH::NUMBER;
    isize => VH::NUMBER;
    usize => VH::NUMBER;
    NonZeroI8 => VH::NONZERO_NUMBER;
    NonZeroU8 => VH::NONZERO_NUMBER;
    NonZeroI16 => VH::NONZERO_NUMBER;
    NonZeroU16 => VH::NONZERO_NUMBER;
    NonZeroI32 => VH::NONZERO_NUMBER;
    NonZeroU32 => VH::NONZERO_NUMBER;
    NonZeroI64 => VH::NONZERO_NUMBER;
    NonZeroU64 => VH::NONZERO_NUMBER;
    NonZeroI128 => VH::NONZERO_NUMBER;
    NonZeroU128 => VH::NONZERO_NUMBER;
    NonZeroIsize => VH::NONZERO_NUMBER;
    NonZeroUsize => VH::NONZERO_NUMBER;
    String => VH::STRING;
    std::path::Path => VH::STRING;
    std::net::SocketAddr => VH::STRING;
    std::net::IpAddr => VH::STRING;
    std::net::Ipv4Addr => VH::STRING;
    std::net::Ipv6Addr => VH::STRING;
    serde_json::Value => VH::JSON;
});
