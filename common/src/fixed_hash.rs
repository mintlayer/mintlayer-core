// Copyright 2020 Parity Technologies
//
// Modified in 2022 by
//   Carla Yap <carla.yap@mintlayer.org>
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Construct a fixed-size hash type.
///
/// # Examples
///
/// Create a public unformatted hash type with 32 bytes size.
///
/// ```
/// use common::construct_fixed_hash;
///
/// construct_fixed_hash!{ pub struct H256(32); }
/// assert_eq!(std::mem::size_of::<H256>(), 32);
/// ```
///
/// With additional attributes and doc comments.
///
/// ```
/// use common::construct_fixed_hash;
/// construct_fixed_hash!{
///     /// My unformatted 160 bytes sized hash type.
///     #[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
///     pub struct H160(20);
/// }
/// assert_eq!(std::mem::size_of::<H160>(), 20);
/// ```
///
/// The visibility modifier is optional and you can create a private hash type.
///
/// ```
/// use common::construct_fixed_hash;
/// construct_fixed_hash!{ struct H512(64); }
/// assert_eq!(std::mem::size_of::<H512>(), 64);
/// ```
#[macro_export(local_inner_macros)]
#[doc(hidden)]
macro_rules! construct_fixed_hash {
	( $(#[$attr:meta])* $visibility:vis struct $name:ident ( $n_bytes:expr ); ) => {
		#[repr(C)]
		$(#[$attr])*
		$visibility struct $name (pub [u8; $n_bytes]);

		impl From<[u8; $n_bytes]> for $name {
			/// Constructs a hash type from the given bytes array of fixed length.
            ///
            /// # Note
            ///
            /// The given bytes are interpreted in little endian order.
			#[inline]
			fn from(bytes: [u8; $n_bytes]) -> Self {
				$name(bytes)
			}
		}

		impl<'a> From<&'a [u8; $n_bytes]> for $name {
			/// Constructs a hash type from the given reference
            /// to the bytes array of fixed length.
            ///
            /// # Note
            ///
            /// The given bytes are interpreted in little endian order.
			#[inline]
			fn from(bytes: &'a [u8; $n_bytes]) -> Self {
				$name(*bytes)
			}
		}

		impl<'a> From<&'a mut [u8; $n_bytes]> for $name {
			/// Constructs a hash type from the given reference
            /// to the mutable bytes array of fixed length.
            ///
            /// # Note
            ///
            /// The given bytes are interpreted in little endian order.
			#[inline]
			fn from(bytes: &'a mut [u8; $n_bytes]) -> Self {
				$name(*bytes)
			}
		}

		impl From<$name> for [u8; $n_bytes] {
			#[inline]
			fn from(s: $name) -> Self {
				s.0
			}
		}

		impl AsRef<[u8]> for $name {
			#[inline]
			fn as_ref(&self) -> &[u8] {
				self.as_bytes()
			}
		}

		impl AsMut<[u8]> for $name {
			#[inline]
			fn as_mut(&mut self) -> &mut [u8] {
				self.as_bytes_mut()
			}
		}

		impl $name {
			/// Returns a new fixed hash where all bits are set to the given byte.
			#[inline]
			pub const fn repeat_byte(byte: u8) -> $name {
				$name([byte; $n_bytes])
			}

			/// Returns a new zero-initialized fixed hash.
			#[inline]
			pub const fn zero() -> $name {
				$name::repeat_byte(0u8)
			}

			/// Returns the size of this hash in bytes.
			#[inline]
			pub const fn len_bytes() -> usize {
				$n_bytes
			}

			/// Extracts a byte slice containing the entire fixed hash.
			#[inline]
			pub fn as_bytes(&self) -> &[u8] {
				&self.0
			}

			/// Extracts a mutable byte slice containing the entire fixed hash.
			#[inline]
			pub fn as_bytes_mut(&mut self) -> &mut [u8] {
				&mut self.0
			}

			/// Extracts a reference to the byte array containing the entire fixed hash.
			#[inline]
			pub const fn as_fixed_bytes(&self) -> &[u8; $n_bytes] {
				&self.0
			}

			/// Extracts a reference to the byte array containing the entire fixed hash.
			#[inline]
			pub fn as_fixed_bytes_mut(&mut self) -> &mut [u8; $n_bytes] {
				&mut self.0
			}

			/// Returns the inner bytes array.
			#[inline]
			pub const fn to_fixed_bytes(self) -> [u8; $n_bytes] {
				self.0
			}

			/// Returns a constant raw pointer to the value.
			#[inline]
			pub fn as_ptr(&self) -> *const u8 {
				self.as_bytes().as_ptr()
			}

			/// Returns a mutable raw pointer to the value.
			#[inline]
			pub fn as_mut_ptr(&mut self) -> *mut u8 {
				self.as_bytes_mut().as_mut_ptr()
			}

			/// Assign the bytes from the byte slice `src` to `self`.
            ///
            /// # Note
            ///
            /// The given bytes are interpreted in little endian order.
            ///
            /// # Panics
            ///
            /// If the length of `src` and the number of bytes in `self` do not match.
			pub fn assign_from_slice(&mut self, src: &[u8]) {
				core::assert_eq!(src.len(), $n_bytes);
				self.as_bytes_mut().copy_from_slice(src);
			}

			/// Create a new fixed-hash from the given slice `src`.
            ///
            /// # Note
            ///
            /// The given bytes are interpreted in little endian order.
            ///
            /// # Panics
            ///
            /// If the length of `src` and the number of bytes in `Self` do not match.
			pub fn from_slice(src: &[u8]) -> Self {
				core::assert_eq!(src.len(), $n_bytes);
				let mut ret = Self::zero();
				ret.assign_from_slice(src);
				ret
			}

			/// Returns `true` if all bits set in `b` are also set in `self`.
			#[inline]
			pub fn covers(&self, b: &Self) -> bool {
				&(b & self) == b
			}

			/// Returns `true` if no bits are set.
			#[inline]
			pub fn is_zero(&self) -> bool {
				self.as_bytes().iter().all(|&byte| byte == 0u8)
			}
		}

		/// Returns the big endian format
		impl core::fmt::Debug for $name {
			fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
				core::write!(f, "{:#x}", $name(self.0))
			}
		}

		/// Returns the little endian format
		impl core::fmt::Display for $name {
			fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
				core::write!(f, "0x")?;

				let ctr = &self.0[$n_bytes - 2..$n_bytes];
				for i in ctr.iter().rev() {
					core::write!(f, "{:02x}", i)?;
				}
				core::write!(f, "…")?;

				let ctr = &self.0[0..2];
				for i in ctr.iter().rev() {
					core::write!(f, "{:02x}", i)?;
				}
				Ok(())
			}
		}

		impl core::fmt::LowerHex for $name {
			fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
				if f.alternate() {
					core::write!(f, "0x")?;
				}

				let ctr = &self.0[0..];
				for i in ctr.iter().rev() {
					core::write!(f, "{:02x}", i)?;
				}
				Ok(())
			}
		}

		impl core::fmt::UpperHex for $name {
			fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
				if f.alternate() {
					core::write!(f, "0X")?;
				}

				let ctr = &self.0[0..];
				for i in ctr.iter().rev() {
					core::write!(f, "{:02X}", i)?;
				}
				Ok(())
			}
		}

		impl core::marker::Copy for $name {}

		#[cfg_attr(feature = "dev", allow(expl_impl_clone_on_copy))]
		impl core::clone::Clone for $name {
			fn clone(&self) -> $name {
				let mut ret = $name::zero();
				ret.0.copy_from_slice(&self.0);
				ret
			}
		}

		impl core::cmp::Eq for $name {}

		impl core::cmp::PartialOrd for $name {
			fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
				Some(self.cmp(other))
			}
		}

		impl core::hash::Hash for $name {
			fn hash<H>(&self, state: &mut H) where H: core::hash::Hasher {
				state.write(&self.0);
				state.finish();
			}
		}

		impl<I> core::ops::Index<I> for $name
		where
			I: core::slice::SliceIndex<[u8]>
		{
			type Output = I::Output;

			#[inline]
			fn index(&self, index: I) -> &I::Output {
				&self.as_bytes()[index]
			}
		}

		impl<I> core::ops::IndexMut<I> for $name
		where
			I: core::slice::SliceIndex<[u8], Output = [u8]>
		{
			#[inline]
			fn index_mut(&mut self, index: I) -> &mut I::Output {
				&mut self.as_bytes_mut()[index]
			}
		}

		impl core::default::Default for $name {
			#[inline]
			fn default() -> Self {
				Self::zero()
			}
		}

		impl_ops_for_hash!($name, BitOr, bitor, BitOrAssign, bitor_assign, |, |=);
		impl_ops_for_hash!($name, BitAnd, bitand, BitAndAssign, bitand_assign, &, &=);
		impl_ops_for_hash!($name, BitXor, bitxor, BitXorAssign, bitxor_assign, ^, ^=);

		impl_byteorder_for_fixed_hash!($name);
		impl_rand_for_fixed_hash!($name);
		impl_cmp_for_fixed_hash!($name);
		impl_rustc_hex_for_fixed_hash!($name);
		// impl_quickcheck_for_fixed_hash!($name);
		impl_arbitrary_for_fixed_hash!($name);
	}
}

// Implementation for byteorder crate support.
#[macro_export]
#[doc(hidden)]
macro_rules! impl_byteorder_for_fixed_hash {
    ( $name:ident ) => {
        /// Utilities using the `byteorder` crate.
        impl $name {
            /// Returns the least significant `n` bytes as slice.
            ///
            /// # Panics
            ///
            /// If `n` is greater than the number of bytes in `self`.
            #[inline]
            fn least_significant_bytes(&self, n: usize) -> &[u8] {
                core::assert_eq!(true, n <= Self::len_bytes());
                &self[(Self::len_bytes() - n)..]
            }

            fn to_low_u64_with_byteorder<B>(self) -> u64
            where
                B: byteorder::ByteOrder,
            {
                let mut buf = [0x0; 8];
                let capped = core::cmp::min(Self::len_bytes(), 8);
                buf[(8 - capped)..].copy_from_slice(self.least_significant_bytes(capped));
                B::read_u64(&buf)
            }

            /// Returns the lowest 8 bytes interpreted as little endian.
            ///
            /// # Note
            ///
            /// For hash type with less than 8 bytes the missing bytes
            /// are interpreted as being zero.
            #[inline]
            pub fn to_low_u64_be(&self) -> u64 {
                self.to_low_u64_with_byteorder::<byteorder::BigEndian>()
            }

            /// Returns the lowest 8 bytes interpreted as little endian.
            ///
            /// # Note
            ///
            /// For hash type with less than 8 bytes the missing bytes
            /// are interpreted as being zero.
            #[inline]
            pub fn to_low_u64_le(&self) -> u64 {
                self.to_low_u64_with_byteorder::<byteorder::LittleEndian>()
            }

            /// Returns the lowest 8 bytes interpreted as native-endian.
            ///
            /// # Note
            ///
            /// For hash type with less than 8 bytes the missing bytes
            /// are interpreted as being zero.
            #[inline]
            pub fn to_low_u64_ne(&self) -> u64 {
                self.to_low_u64_with_byteorder::<byteorder::NativeEndian>()
            }

            fn from_low_u64_with_byteorder<B>(val: u64) -> Self
            where
                B: byteorder::ByteOrder,
            {
                let mut buf = [0x0; 8];
                B::write_u64(&mut buf, val);

                let capped = core::cmp::min(Self::len_bytes(), 8);
                let mut bytes = [0x0; core::mem::size_of::<Self>()];
                bytes[(Self::len_bytes() - capped)..].copy_from_slice(&buf[..capped]);
                bytes.reverse();
                Self::from_slice(&bytes)
            }

            /// Creates a new hash type from the given `u64` value.
            ///
            /// # Note
            ///
            /// - The given `u64` value is interpreted as big endian.
            /// - Ignores the most significant bits of the given value
            ///   if the hash type has less than 8 bytes.
            #[inline]
            pub fn from_low_u64_be(val: u64) -> Self {
                Self::from_low_u64_with_byteorder::<byteorder::BigEndian>(val)
            }

            /// Creates a new hash type from the given `u64` value.
            ///
            /// # Note
            ///
            /// - The given `u64` value is interpreted as little endian.
            /// - Ignores the most significant bits of the given value
            ///   if the hash type has less than 8 bytes.
            #[inline]
            pub fn from_low_u64_le(val: u64) -> Self {
                Self::from_low_u64_with_byteorder::<byteorder::LittleEndian>(val)
            }

            /// Creates a new hash type from the given `u64` value.
            ///
            /// # Note
            ///
            /// - The given `u64` value is interpreted as native endian.
            /// - Ignores the most significant bits of the given value
            ///   if the hash type has less than 8 bytes.
            #[inline]
            pub fn from_low_u64_ne(val: u64) -> Self {
                Self::from_low_u64_with_byteorder::<byteorder::NativeEndian>(val)
            }
        }
    };
}

// Implementation for rand crate support.
#[macro_export]
#[doc(hidden)]
macro_rules! impl_rand_for_fixed_hash {
    ( $name:ident ) => {
        impl crypto::random::distributions::Distribution<$name>
            for crypto::random::distributions::Standard
        {
            fn sample<R: crypto::random::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                let mut ret = $name::zero();
                for byte in ret.as_bytes_mut().iter_mut() {
                    *byte = rng.gen();
                }
                ret
            }
        }

        /// Utilities using the `rand` crate.
        impl $name {
            /// Assign `self` to a cryptographically random value using the
            /// given random number generator.
            pub fn randomize_using<R>(&mut self, rng: &mut R)
            where
                R: crypto::random::Rng + ?Sized,
            {
                use crypto::random::distributions::Distribution;
                *self = crypto::random::distributions::Standard.sample(rng);
            }

            /// Assign `self` to a cryptographically random value.
            pub fn randomize(&mut self) {
                let mut rng = crypto::random::rngs::OsRng;
                self.randomize_using(&mut rng);
            }

            /// Create a new hash with cryptographically random content using the
            /// given random number generator.
            pub fn random_using<R>(rng: &mut R) -> Self
            where
                R: crypto::random::Rng + ?Sized,
            {
                let mut ret = Self::zero();
                ret.randomize_using(rng);
                ret
            }

            /// Create a new hash with cryptographically random content.
            pub fn random() -> Self {
                let mut hash = Self::zero();
                hash.randomize();
                hash
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_cmp_for_fixed_hash {
    ( $name:ident ) => {
        impl core::cmp::PartialEq for $name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.as_bytes() == other.as_bytes()
            }
        }

        impl core::cmp::Ord for $name {
            #[inline]
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.as_bytes().cmp(other.as_bytes())
            }
        }
    };
}

// Implementation for rustc-hex crate support.
#[macro_export]
#[doc(hidden)]
macro_rules! impl_rustc_hex_for_fixed_hash {
    ( $name:ident ) => {
        impl core::str::FromStr for $name {
            type Err = rustc_hex::FromHexError;

            /// Creates a hash type instance from the given string.
            ///
            /// # Note
            ///
            /// The given input string is interpreted in little endian.
            ///
            /// # Errors
            ///
            /// - When encountering invalid non hex-digits
            /// - Upon empty string input or invalid input length in general
            fn from_str(input: &str) -> core::result::Result<$name, rustc_hex::FromHexError> {
                let input = input.strip_prefix("0x").unwrap_or(input);
                let mut iter = rustc_hex::FromHexIter::new(input);

                let mut result = Self::zero();

                for byte in result.as_mut().iter_mut().rev() {
                    *byte = iter.next().ok_or(Self::Err::InvalidHexLength)??;
                }

                if iter.next().is_some() {
                    return Err(Self::Err::InvalidHexLength);
                }
                Ok(result)
            }
        }
    };
}

//
// TODO: works on version 0.9.0. But has version conflicts with env_logger.
// Upgrading the quickcheck version also removes the `fill_bytes` method.
// See issue: [missing fill_bytes](https://github.com/BurntSushi/quickcheck/issues/291)
//
//Implementation for quickcheck crate support.
// #[macro_export]
// #[doc(hidden)]
// macro_rules! impl_quickcheck_for_fixed_hash {
//     ( $name:ident ) => {
//         impl quickcheck::Arbitrary for $name {
//             fn arbitrary(g: &mut quickcheck::Gen) -> Self {
//                 let mut res = [0u8; core::mem::size_of::<Self>()];
//                 g.fill_bytes(&mut res[..Self::len_bytes()]);
//                 Self::from(res)
//             }
//         }
//     };
// }

// Implementation for arbitrary crate support
#[macro_export]
#[doc(hidden)]
macro_rules! impl_arbitrary_for_fixed_hash {
    ( $name:ident ) => {
        impl<'a> arbitrary::Arbitrary<'a> for $name {
            fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
                let mut res = Self::zero();
                u.fill_buffer(&mut res.0)?;
                Ok(Self::from(res))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_ops_for_hash {
	(
		$impl_for:ident,
		$ops_trait_name:ident,
		$ops_fn_name:ident,
		$ops_assign_trait_name:ident,
		$ops_assign_fn_name:ident,
		$ops_tok:tt,
		$ops_assign_tok:tt
	) => {
		impl<'r> core::ops::$ops_assign_trait_name<&'r $impl_for> for $impl_for {
			fn $ops_assign_fn_name(&mut self, rhs: &'r $impl_for) {
				for (lhs, rhs) in self.as_bytes_mut().iter_mut().zip(rhs.as_bytes()) {
					*lhs $ops_assign_tok rhs;
				}
			}
		}

		impl core::ops::$ops_assign_trait_name<$impl_for> for $impl_for {
			#[inline]
			fn $ops_assign_fn_name(&mut self, rhs: $impl_for) {
				*self $ops_assign_tok &rhs;
			}
		}

		impl<'l, 'r> core::ops::$ops_trait_name<&'r $impl_for> for &'l $impl_for {
			type Output = $impl_for;

			fn $ops_fn_name(self, rhs: &'r $impl_for) -> Self::Output {
				let mut ret = self.clone();
				ret $ops_assign_tok rhs;
				ret
			}
		}

		impl core::ops::$ops_trait_name<$impl_for> for $impl_for {
			type Output = $impl_for;

			#[inline]
			fn $ops_fn_name(self, rhs: Self) -> Self::Output {
				&self $ops_tok &rhs
			}
		}
	};
}

/// Implements lossy conversions between the given types.
///
/// # Note
///
/// - Both types must be of different sizes.
/// - Type `large_ty` must have a larger memory footprint compared to `small_ty`.
///
/// # Panics
///
/// Both `From` implementations will panic if sizes of the given types
/// do not meet the requirements stated above.
///
/// # Example
///
/// ```
/// use common::{construct_fixed_hash, impl_fixed_hash_conversions};
///
/// construct_fixed_hash!{ struct H160(20); }
/// construct_fixed_hash!{ struct H256(32); }
/// impl_fixed_hash_conversions!(H256, H160);
/// // now use it!
/// assert_eq!(H256::from(H160::zero()), H256::zero());
/// assert_eq!(H160::from(H256::zero()), H160::zero());
/// ```
#[macro_export]
macro_rules! impl_fixed_hash_conversions {
    ($large_ty:ident, $small_ty:ident) => {
        static_assertions::const_assert!(
            core::mem::size_of::<$small_ty>() < core::mem::size_of::<$large_ty>()
        );

        impl From<$small_ty> for $large_ty {
            fn from(value: $small_ty) -> $large_ty {
                let large_ty_size = $large_ty::len_bytes();
                let small_ty_size = $small_ty::len_bytes();

                core::debug_assert!(
                    large_ty_size > small_ty_size
                        && large_ty_size % 2 == 0
                        && small_ty_size % 2 == 0
                );

                let mut ret = $large_ty::zero();
                ret.as_bytes_mut()[(large_ty_size - small_ty_size)..large_ty_size]
                    .copy_from_slice(value.as_bytes());
                ret
            }
        }

        impl From<$large_ty> for $small_ty {
            fn from(value: $large_ty) -> $small_ty {
                let large_ty_size = $large_ty::len_bytes();
                let small_ty_size = $small_ty::len_bytes();

                core::debug_assert!(
                    large_ty_size > small_ty_size
                        && large_ty_size % 2 == 0
                        && small_ty_size % 2 == 0
                );

                let mut ret = $small_ty::zero();
                ret.as_bytes_mut()
                    .copy_from_slice(&value[(large_ty_size - small_ty_size)..large_ty_size]);
                ret
            }
        }
    };
}

#[cfg(test)]
mod test {
    use crate::primitives::H256;
    use std::str::FromStr;

    #[test]
    fn display_test() {
        fn check(hash: &str) {
            let h256 = H256::from_str(hash).expect("should not fail");

            let debug = format!("{:?}", h256);
            assert_eq!(debug, format!("0x{}", hash));

            let display = format!("{}", h256);
            let (_, last_value) = hash.split_at(hash.len() - 4);
            assert_eq!(display, format!("0x{}…{}", &hash[0..4], last_value));

            let no_0x = format!("{:x}", h256);
            assert_eq!(no_0x, hash.to_string());

            let sharp = format!("{:#x}", h256);
            assert_eq!(sharp, debug);

            let upper_hex = format!("{:#010X}", h256);
            assert_eq!(upper_hex, format!("0X{}", hash.to_uppercase()));
        }

        check("000000000000000000059fa50103b9683e51e5aba83b8a34c9b98ce67d66136c");
        check("000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f");
        check("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd");
    }
}
