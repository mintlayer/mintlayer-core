//! Size-dependent data encoding and decoding.
//!
//! # Example
//!
//! ```
//! # use serialization_core::*;
//! # use serialization_size_dependent::*;
//! # use hex_literal::hex;
//! #
//! // Destination type with size-dependent encoding. If it is encoded in 20 bytes, it is treated
//! // as PubkeyHash, if it is encoded in 32 bytes, it is treated as ScriptHash.
//! #[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
//! enum Destination {
//!     PubkeyHash([u8; 20]),
//!     ScriptHash([u8; 32]),
//! }
//!
//! // Implement the encoding
//! impl SizedEncode for Destination {
//!     fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
//!         match self {
//!             Destination::ScriptHash(data) => data.encode_to(dest),
//!             Destination::PubkeyHash(data) => data.encode_to(dest),
//!         }
//!     }
//! }
//!
//! // Implement the decoding
//! impl SizedDecode for Destination {
//!     fn sized_decode(input: &[u8]) -> Result<Self, Error> {
//!         // Decide which variant based on input length
//!         match input.len() {
//!             20 => Ok(Destination::PubkeyHash(input.try_into().unwrap())),
//!             32 => Ok(Destination::ScriptHash(input.try_into().unwrap())),
//!             _ => Err("Bad spend type length".into()),
//!         }
//!     }
//! }
//!
//! // Transaction output uses the `SizeDependent` wrapper to augment destination with size.
//! #[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Decode, Encode)]
//! struct TxOutput {
//!     amount: u32,
//!     #[codec(encoded_as = "SizeDependent<Destination>")]
//!     dest: Destination,
//! }
//!
//! // We need From<SizeDependent<Destiantion>> for Destination for it to work, do it here.
//! impl_FromSizeDependent!(Destination);
//!
//! // Example with Pubkey hash output
//! let txout = TxOutput {
//!     amount: 10,
//!     dest: Destination::PubkeyHash([0x15; 20]),
//! };
//! let encoded = hex!(
//!     "0a000000" // amount: 10 = 0x0a; in little endian 0x0a000000
//!     "50"       // data size: 20 bytes; shift by 2 bits for compact encoding: 80 = 0x50
//!     "1515151515151515151515151515151515151515"  // data
//! );
//! // Check encoding is as expected
//! assert_eq!(txout.encode(), encoded);
//! // Check decoding it back gives the same txout
//! assert_eq!(DecodeAll::decode_all(&mut &encoded[..]), Ok(txout));
//!
//! // Example with ScriptHash output
//! let txout = TxOutput {
//!     amount: 258,
//!     dest: Destination::ScriptHash([0xda; 32]),
//! };
//! let encoded = hex!(
//!     "02010000" // amount: 257 = 0x0201 in LE
//!     "80"       // data size: 32 bytes = 0x20; shift by 2 bits for compact encoding: 0x80
//!     "dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada"  // data
//! );
//! // Check encoding is as expected
//! assert_eq!(txout.encode(), encoded);
//! // Check decoding it back gives the same txout
//! assert_eq!(DecodeAll::decode_all(&mut &encoded[..]), Ok(txout));
//! ```

use serialization_core::{Compact, Decode, DecodeAll, Encode, EncodeAsRef, Error, Input, Output};
use either::Either;

/// Trait for types where encoding size is significant for decoding.
///
/// The interface is identical to [Encode] but having a distinct trait here allows us to
/// distinguish it from self-contained encodings that don't need the size annotation and avoid
/// subtle issues with encoding ambiguity.
pub trait SizedEncode {
    /// Size hint, used for optimization. See [Encode::size_hint]
    fn sized_size_hint(&self) -> usize { 0 }

    /// Encode to given output. See [Encode::encode_to]
    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.sized_using_encoded(|buf| dest.write(buf))
    }

    /// Encode into a fresh Vec. See [Encode::encode]
    fn sized_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.sized_size_hint());
        self.sized_encode_to(&mut out);
        out
    }

    /// Feed encoding into given callback. See [Encode::using_encoded]
    fn sized_using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.sized_encode())
    }

    /// Get size of encoded object. Does not include encoding of the size itself.
    fn sized_encoded_size(&self) -> usize {
        struct ByteCounter(usize);
        impl Output for ByteCounter {
            fn write(&mut self, data: &[u8]) {
                self.0 += data.len();
            }
        }
        let mut counter = ByteCounter(0);
        self.sized_encode_to(&mut counter);
        counter.0
    }
}

/// Trait for types that are decoded in size-dependent way.
///
/// The interface is very similar to [crate::DecodeAll] but it has a default implementation.
/// By having a separate trait, we make size-dependent encoding opt-in.
pub trait SizedDecode: Sized {
    /// Decode given slice with size information.
    ///
    /// The decoder is allowed to read the slice length to make decoding decisions. It is expected
    /// that an error is raised if the size is not correct for this type. The implementation can
    /// delegate to [crate::DecodeAll::decode_all] if appropriate.
    fn sized_decode(input: &[u8]) -> Result<Self, Error>;
}

/// Marker trait for types where T::encode is guaranteed to return a non-empty byte sequence.
pub trait NonEmptyEncoding {}

// TODO these macros would be much nicer as derive macros

#[macro_export]
macro_rules! impl_FromSizeDependent {
    // TODO support generic types
    ($T:ident) => {
        impl ::core::convert::From<$crate::SizeDependent<$T>> for $T {
            fn from(wrapped: $crate::SizeDependent<$T>) -> $T {
                wrapped.0
            }
        }
    };
}

#[macro_export]
macro_rules! impl_SizedDecode_via_DecodeAll {
    // TODO support generic types
    ($T:ident) => {
        impl $crate::SizedDecode for $T where $T: $crate::Encode {
            fn sized_decode(mut input: &[u8]) -> ::core::result::Result<Self, $crate::Error> {
                $crate::DecodeAll::decode_all(&mut input)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_SizedEncode_via_Encode {
    // TODO support generic types
    ($T:ident) => {
        impl $crate::SizedEncode for $T where $T: $crate::Decode {
            fn sized_using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
                $crate::Encode::using_encoded(self, f)
            }
        }
    };
}

// Support encoding by references

impl<T: SizedEncode> SizedEncode for &T {
    fn sized_size_hint(&self) -> usize {
        (*self).sized_size_hint()
    }
    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        (*self).sized_using_encoded(|buf| dest.write(buf))
    }
    fn sized_using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        (*self).sized_using_encoded(f)
    }
    fn sized_encoded_size(&self) -> usize {
        (*self).sized_encoded_size()
    }
}

// Box wrapper

impl<T: SizedEncode> SizedEncode for Box<T> {
    fn sized_size_hint(&self) -> usize {
        self.as_ref().sized_size_hint()
    }
    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.as_ref().sized_encode_to(dest)
    }
    fn sized_using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.as_ref().sized_using_encoded(f)
    }
    fn sized_encoded_size(&self) -> usize {
        self.as_ref().sized_encoded_size()
    }
}

impl<T: SizedDecode> SizedDecode for Box<T> {
    fn sized_decode(data: &[u8]) -> Result<Self, crate::Error> {
        SizedDecode::sized_decode(data).map(Box::new)
    }
}

// If a `Vec<T>` is coded in a size-dependent way, it does not need to store the element count.

impl<T: Encode + NonEmptyEncoding> SizedEncode for Vec<T> {
    fn sized_size_hint(&self) -> usize {
        self.size_hint()
    }
    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.iter().for_each(|x| x.encode_to(dest))
    }
    fn sized_encoded_size(&self) -> usize {
        self.iter().map(Encode::encoded_size).sum()
    }
}

impl<T: Decode + NonEmptyEncoding> SizedDecode for Vec<T> {
    fn sized_decode(mut data: &[u8]) -> Result<Self, crate::Error> {
        let mut ret = Vec::new();
        while !data.is_empty() {
            ret.push(T::decode(&mut data)?);
        }
        Ok(ret)
    }
}

// If Option is coded in a size-independent way, we can treat empty byte sequence to be None as
// long as the contents encode to a non-empty byte sequence.

impl<T: Encode + NonEmptyEncoding> SizedEncode for Option<T> {
    fn sized_size_hint(&self) -> usize {
        self.as_ref().map_or(0, |x| x.size_hint())
    }
    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.iter().for_each(|x| x.encode_to(dest))
    }
    fn sized_encoded_size(&self) -> usize {
        self.as_ref().map_or(0, |x| x.encoded_size())
    }
}

impl<T: Decode + NonEmptyEncoding> SizedDecode for Option<T> {
    fn sized_decode(mut data: &[u8]) -> Result<Self, crate::Error> {
        let ret = if data.is_empty() {
            None
        } else {
            Some(T::decode(&mut data)?)
        };
        Ok(ret)
    }
}

// This captures how structs and tuples are encoded/decoded in a size-dependent way. A struct can
// be size-encoded if all but last elements are `Encode` and the last element is `SizedEncode`.
// Same goes for decoding.

impl<T: Encode, U: SizedEncode> SizedEncode for (T, U) {
    fn sized_size_hint(&self) -> usize {
        self.0.size_hint() + self.1.sized_size_hint()
    }

    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.0.encode_to(dest);
        self.1.sized_encode_to(dest);
    }

    fn sized_encoded_size(&self) -> usize {
        self.0.encoded_size() + self.1.sized_encoded_size()
    }
}

impl<T: Decode, U: SizedDecode> SizedDecode for (T, U) {
    fn sized_decode(mut data: &[u8]) -> Result<Self, crate::Error> {
        let x = Decode::decode(&mut data)?;
        let y = SizedDecode::sized_decode(data)?;
        Ok((x, y))
    }
}

// This captures enums are encoded/decoded in a size-dependent way. An enum can be size-dependently
// coded if all variants can be individually size-dependently coded.

impl<T: SizedEncode, U: SizedEncode> SizedEncode for Either<T, U> {
    fn sized_size_hint(&self) -> usize {
        self.as_ref().either(|l| l.sized_size_hint(), |r| r.sized_size_hint()) + 1
    }
    fn sized_encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.as_ref().either_with(
            dest,
            |dest, l| (0u8, l).sized_encode_to(dest),
            |dest, r| (1u8, r).sized_encode_to(dest),
        );
    }
    fn sized_encoded_size(&self) -> usize {
        self.as_ref().either(|l| l.sized_encoded_size(), |r| r.sized_encoded_size()) + 1
    }
}

impl<T: SizedDecode, U: SizedDecode> SizedDecode for Either<T, U> {
    fn sized_decode(data: &[u8]) -> Result<Self, crate::Error> {
        let (tag, data) = data.split_first().ok_or("Enum tag not present")?;
        match tag {
            0 => T::sized_decode(data).map(Either::Left),
            1 => U::sized_decode(data).map(Either::Right),
            _ => Err(Error::from("Enum tag not recognized")),
        }
    }
}

// Some built-in types

impl_SizedDecode_via_DecodeAll!(bool);
impl_SizedDecode_via_DecodeAll!(u8);
impl_SizedDecode_via_DecodeAll!(u16);
impl_SizedDecode_via_DecodeAll!(u32);
impl_SizedDecode_via_DecodeAll!(u64);

impl_SizedEncode_via_Encode!(bool);
impl_SizedEncode_via_Encode!(u8);
impl_SizedEncode_via_Encode!(u16);
impl_SizedEncode_via_Encode!(u32);
impl_SizedEncode_via_Encode!(u64);

/// Bridge from size-dependent encoding to self-contained encoding.
///
/// The representation consists of the object size placed first, followed by that number of bytes
/// of data that encode the inner object `T`. Since the size is stored externally, the inner object
///  of type `T` is required to implement [SizedDecode]/[SizedEncode].
pub struct SizeDependent<T>(pub T);

impl<T> From<T> for SizeDependent<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: SizedEncode> Encode for SizeDependent<T> {
    fn size_hint(&self) -> usize {
        self.0.sized_size_hint() + 4
    }

    fn encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        // TODO what to do about this expect?
        let size: u32 = self.0.sized_encoded_size().try_into().expect("Size too big");
        Compact(size).encode_to(dest);
        self.0.sized_encode_to(dest);
    }

    fn encoded_size(&self) -> usize {
        let inner_size = self.0.sized_encoded_size();
        let len_size = Compact(inner_size as u32).encoded_size();
        len_size + inner_size
    }
}

impl<'a, T: SizedEncode + 'a> EncodeAsRef<'a, T> for SizeDependent<T> {
    type RefType = SizeDependent<&'a T>;
}

impl<T: SizedDecode> Decode for SizeDependent<T> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let data = Vec::<u8>::decode(input)?;
        T::sized_decode(&data[..]).map(SizeDependent::from)
    }

    fn skip<I: Input>(input: &mut I) -> Result<(), Error> {
        Vec::<u8>::skip(input)
    }
}
