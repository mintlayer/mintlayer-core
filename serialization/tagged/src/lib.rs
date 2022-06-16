// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): L. Kuklinek

//! Tools for encoding/decoding types that carry their own variant tag
//!
//! # Tagged types
//!
//! The [Tagged] trait is used for types whose encoding starts with a specific byte. The byte can
//! then be used to distinguis between enum variants without explicitly sotring the variant index.
//! Use `<T as Tagged>::TAG` to get the initial byte value as a `u8` constant.
//!
//! * There is a canonical [Tag] which is a unit type that encodes to the specified byte value.
//! * Tuples implement [Tagged] if the first element implements Tagged.
//! * Custom types can use the [Tagged derive macro](derive.Tagged.html).
//!   The macro docs provide more detail on various rules and restrictions.
//!
//! The above should be sufficient to make the need for implementing [Tagged] manually very rare.
//!
//! # Direct encoding for enums
//!
//! There are [DirectEncode] and [DirectDecode] derive macros that generate [Encode] and [Decode],
//! respectively. These macros work with encoding where the initial discriminant byte is not
//! explicitly stored. Instead the `<_ as Tagged>::TAG` value of the contained data is used to
//! detect which variant are we dealing with.
//!
//! Here are the rules:
//!
//! * Only applicable to `enum`s
//! * All variants must have data payload (at least a [Tag]), and the payload has to be [Tagged].
//! * All `<_ as Tagged>::TAG` values must be different
//!
//! # Example
//!
//! Example demonstrates block header versioning:
//!
//! ```
//! # use serialization::{*, tagged::*};
//! // An initial header version with PoW
//! #[derive(Tagged, Encode, Decode, Clone)]
//! struct HeaderV1 {
//!     version: Tag<1>,
//!     prev_hash: [u8; 32],
//!     tx_root: [u8; 32],
//!     nonce: u128,
//! }
//!
//! // A new version, switching to PoS and added timestamp
//! #[derive(Tagged, Encode, Decode, Clone)]
//! struct HeaderV2 {
//!     version: Tag<2>,
//!     prev_hash: [u8; 32],
//!     tx_root: [u8; 32],
//!     time: u32,
//!     signature: Vec<u8>,
//! }
//!
//! // A top-level header type
//! #[derive(DirectEncode, DirectDecode)]
//! enum Header {
//!     V1(HeaderV1),
//!     v2(HeaderV2),
//! }
//!
//! // Create a PoW header
//! let header_v1 = HeaderV1 {
//!     version: Tag,
//!     prev_hash: [42; 32],
//!     tx_root: [43; 32],
//!     nonce: 177_984_342_498_312,
//! };
//! let header = Header::V1(header_v1.clone());
//!
//! // Serializing `Header` and `HeaderV1` gives the same encoding.
//! assert_eq!(header.encode(), header_v1.encode());
//! ```
//!
//! ## Illegal usage
//!
//! It is mandatory to specify the initial byte value, the following is not legal:
//!
//! ```compile_fail
//! # use serialization::tagged::*;
//! #[derive(Tagged)]
//! enum Example { X }
//! ```
//!
//! While this is:
//!
//! ```
//! # use serialization::tagged::*;
//! #[derive(Tagged)]
//! enum Example { X = 5 }
//! ```
//!
//! Tagged enums cannot have multiple variants:
//! ```compile_fail
//! # use serialization::tagged::*;
//! #[derive(Tagged)]
//! enum Example { X = 1, Y = 2 }
//! ```
//!
//! Directly encoded enums have to have distinct tag values:
//! ```compile_fail
//! # use serialization::tagged::*;
//! #[derive(DirectDecode)]
//! enum Example { X(Tag<5>), Y(Tag<5>) }
//! ```

pub mod derive_support;

/// Derive the [Tagged] trait
///
/// * An `enum` with just one variant always starts with the variant index and can be made [Tagged].
///   The `#[codec(index = X)]` or enum discriminant has to be provided explicitly.
/// * A struct where the first element implements [Tagged] can be made Tagged.
pub use serialization_tagged_derive::Tagged;

/// Derive [Encode] that does not add the discriminant byte
pub use serialization_tagged_derive::DirectEncode;

/// Derive [Decode] for decoding without the initial discriminant byte
pub use serialization_tagged_derive::DirectDecode;

use serialization_core::{Decode, Encode, Error, Input};

/// Types whose encoding starts with a fixed byte (tag)
pub trait Tagged {
    /// Initial byte in encoding of `Self`
    const TAG: u8;
}

// Impls for some common wrapper types
impl<T: Tagged> Tagged for &T {
    const TAG: u8 = T::TAG;
}
impl<T: Tagged> Tagged for &mut T {
    const TAG: u8 = T::TAG;
}
impl<T: Tagged> Tagged for Box<T> {
    const TAG: u8 = T::TAG;
}

// Tuples are tagged if the first element is tagged
macro_rules! impl_tagged_for_tuple {
    ($T:ident, $($TS:ident),*) => {
        impl<$T: Tagged, $($TS),*> Tagged for ($T, $($TS),*) {
            const TAG: u8 = <$T as Tagged>::TAG;
        }
    };
}
// Up to 8 elements for now, can be expanded if needed
impl_tagged_for_tuple!(T0,);
impl_tagged_for_tuple!(T0, T1);
impl_tagged_for_tuple!(T0, T1, T2);
impl_tagged_for_tuple!(T0, T1, T2, T3);
impl_tagged_for_tuple!(T0, T1, T2, T3, T4);
impl_tagged_for_tuple!(T0, T1, T2, T3, T4, T5);
impl_tagged_for_tuple!(T0, T1, T2, T3, T4, T5, T6);
impl_tagged_for_tuple!(T0, T1, T2, T3, T4, T5, T6, T7);

/// Generic tag type where the encoding is always single byte specified in the generic parameter.
#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug, Default)]
pub struct Tag<const N: u8>;

impl<const N: u8> Tagged for Tag<N> {
    const TAG: u8 = N;
}

impl<const N: u8> Encode for Tag<N> {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&[N])
    }

    fn size_hint(&self) -> usize {
        self.encoded_size()
    }

    fn encoded_size(&self) -> usize {
        1
    }
}

impl<const N: u8> Decode for Tag<N> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, crate::Error> {
        u8::decode(input).and_then(|b| {
            Some(Tag).filter(|_| b == N).ok_or_else(|| "Unexpected tag number".into())
        })
    }

    fn skip<I: Input>(input: &mut I) -> Result<(), crate::Error> {
        input.read_byte().map(|_| ())
    }

    fn encoded_fixed_size() -> Option<usize> {
        Some(1)
    }
}

/// Query the tag of given value
pub const fn tag_of<T: Tagged>(_: &T) -> u8 {
    <T as Tagged>::TAG
}
