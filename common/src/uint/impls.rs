// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// Modified in 2022 by
//     Carla Yap <carla.yap@mintlayer.org>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Big unsigned integer types.
//!
//! Implementation of various large-but-fixed sized unsigned integer types.
//! The functions here are designed to be fast.

use crate::primitives::Amount;
use thiserror::Error;

macro_rules! construct_uint {
    ($name:ident, $n_words:expr) => {
        /// little endian large integer type
        #[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub [u64; $n_words]);
        impl_array_newtype!($name, u64, $n_words);

        impl $name {
            pub const ZERO: Self = Self::from_u64(0u64);
            pub const ONE: Self = Self::from_u64(1u64);
            pub const MAX: Self = Self([u64::MAX; $n_words]);
            pub const BITS: u32 = u64::BITS * $n_words;

            /// Conversion to u32
            #[inline]
            pub fn low_u32(&self) -> u32 {
                self.0[0] as u32
            }

            /// Conversion to u64
            #[inline]
            pub fn low_u64(&self) -> u64 {
                self.0[0]
            }

            /// Return the least number of bits needed to represent the number
            #[inline]
            pub fn bits(&self) -> usize {
                let &$name(ref arr) = self;
                for i in 1..$n_words {
                    if arr[$n_words - i] > 0 {
                        return (0x40 * ($n_words - i + 1))
                            - arr[$n_words - i].leading_zeros() as usize;
                    }
                }
                0x40 - arr[0].leading_zeros() as usize
            }

            /// Multiplication by u32
            pub fn mul_u32(self, other: u32) -> Self {
                self.widening_mul_u64(other as u64).0
            }

            fn widening_mul_u64(self, rhs: u64) -> (Self, u64) {
                const U64_MAX: u128 = u64::MAX as u128;
                let lhs = &self.0;
                let mut res = [0u64; $n_words];
                let mut carry = 0u64;
                for i in 0..$n_words {
                    assert!(carry < u64::MAX);
                    let prod = lhs[i] as u128 * rhs as u128;
                    assert!(prod <= U64_MAX * U64_MAX);
                    let prod = prod + carry as u128;
                    assert!(prod < U64_MAX * U64_MAX + U64_MAX);
                    res[i] = prod as u64;
                    carry = (prod >> 64) as u64
                }
                (Self(res), carry)
            }

            /// Create an object from a given unsigned 64-bit integer
            #[inline]
            pub const fn from_u64(init: u64) -> $name {
                let mut ret = [0; $n_words];
                ret[0] = init;
                $name(ret)
            }

            /// Create an object from a given unsigned 128-bit integer
            #[inline]
            pub fn from_u128(init: u128) -> $name {
                let mut ret = [0; $n_words];
                ret[0] = init as u64;
                ret[1] = (init >> 64) as u64;
                Self(ret)
            }

            /// Create an object from a given unsigned Amount
            #[inline]
            pub fn from_amount(init: Amount) -> $name {
                Self::from_u128(init.into_atoms())
            }

            /// Creates big integer value from a byte array using
            /// big endian encoding
            pub fn from_be_bytes(bytes: [u8; $n_words * 8]) -> $name {
                Self::_from_be_slice(&bytes)
            }

            /// Creates big integer value from a byte slice using
            /// big endian encoding
            pub fn from_be_slice(bytes: &[u8]) -> Result<$name, ParseLengthError> {
                if bytes.len() != $n_words * 8 {
                    Err(ParseLengthError {
                        actual: bytes.len(),
                        expected: $n_words * 8,
                    })
                } else {
                    Ok(Self::_from_be_slice(bytes))
                }
            }

            fn _from_be_slice(bytes: &[u8]) -> $name {
                use crate::uint::endian::slice_to_u64_be;
                let mut slice = [0u64; $n_words];
                slice
                    .iter_mut()
                    .rev()
                    .zip(bytes.chunks(8))
                    .for_each(|(word, bytes)| *word = slice_to_u64_be(bytes));
                $name(slice)
            }

            /// Convert a big integer into a byte array using big endian encoding
            pub fn to_be_bytes(&self) -> [u8; $n_words * 8] {
                use crate::uint::endian::u64_to_array_be;
                let mut res = [0; $n_words * 8];
                for i in 0..$n_words {
                    let start = i * 8;
                    res[start..start + 8]
                        .copy_from_slice(&u64_to_array_be(self.0[$n_words - (i + 1)]));
                }
                res
            }

            /// Creates big integer value from a byte array using
            /// little endian encoding
            pub fn from_bytes(bytes: [u8; $n_words * 8]) -> $name {
                Self::inner_from_slice(&bytes)
            }

            /// Creates big integer value from a byte slice using
            /// little endian encoding
            pub fn from_slice(bytes: &[u8]) -> Result<$name, ParseLengthError> {
                if bytes.len() != $n_words * 8 {
                    Err(ParseLengthError {
                        actual: bytes.len(),
                        expected: $n_words * 8,
                    })
                } else {
                    Ok(Self::inner_from_slice(bytes))
                }
            }

            fn inner_from_slice(bytes: &[u8]) -> $name {
                use crate::uint::endian::slice_to_u64_le;
                let mut slice = [0u64; $n_words];
                slice
                    .iter_mut()
                    .zip(bytes.chunks(8))
                    .for_each(|(word, bytes)| *word = slice_to_u64_le(bytes));
                $name(slice)
            }

            /// Convert a big integer into a byte array using little endian encoding
            pub fn to_bytes(&self) -> [u8; $n_words * 8] {
                use crate::uint::endian::u64_to_array_le;
                let mut res = [0; $n_words * 8];
                for i in 0..$n_words {
                    let start = i * 8;
                    res[start..start + 8].copy_from_slice(&u64_to_array_le(self.0[i]));
                }
                res
            }

            // divmod like operation, returns (quotient, remainder)
            #[inline]
            fn div_rem(self, other: Self) -> (Self, Self) {
                let mut sub_copy = self;
                let mut shift_copy = other;
                let mut ret = [0u64; $n_words];

                let my_bits = self.bits();
                let your_bits = other.bits();

                // Check for division by 0
                assert!(your_bits != 0);

                // Early return in case we are dividing by a larger number than us
                if my_bits < your_bits {
                    return ($name(ret), sub_copy);
                }

                // Bitwise long division
                let mut shift = my_bits - your_bits;
                shift_copy = shift_copy << shift;
                loop {
                    if sub_copy >= shift_copy {
                        ret[shift / 64] |= 1 << (shift % 64);
                        sub_copy = sub_copy.unchecked_sub(&shift_copy);
                    }
                    shift_copy = shift_copy >> 1;
                    if shift == 0 {
                        break;
                    }
                    shift -= 1;
                }

                ($name(ret), sub_copy)
            }

            fn overflowing_add_with_carry(&self, other: &Self, mut carry: bool) -> (Self, bool) {
                let lhs = &self.0;
                let rhs = &other.0;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    let (ab, ab_c) = lhs[i].overflowing_add(rhs[i]);
                    let (abc, abc_c) = ab.overflowing_add(carry as u64);
                    ret[i] = abc;
                    carry = ab_c | abc_c;
                }
                (Self(ret), carry)
            }

            fn overflowing_add(&self, other: &Self) -> (Self, bool) {
                self.overflowing_add_with_carry(other, false)
            }

            fn unchecked_sub(&self, other: &Self) -> Self {
                let a = self.overflowing_add(&!*other).0;
                let one: $name = $crate::uint::BitArray::one();
                a.overflowing_add(&one).0
            }

            fn unchecked_div(&self, other: &Self) -> Self {
                self.div_rem(*other).0
            }

            fn unchecked_rem(&self, other: &Self) -> Self {
                self.div_rem(*other).1
            }

            pub fn checked_add(&self, other: &Self) -> Option<Self> {
                let (result, carry) = self.overflowing_add(other);
                (!carry).then_some(result)
            }

            pub fn checked_sub(&self, other: &Self) -> Option<Self> {
                (*self >= *other).then(|| self.unchecked_sub(other))
            }

            pub fn widening_mul(&self, other: &Self) -> (Self, Self) {
                let mut res_lo = Self([0u64; $n_words]);
                let mut res_hi = Self([0u64; $n_words]);
                for (i, rhs_i) in other.0.iter().enumerate() {
                    let (res_i, carry_mul) = self.widening_mul_u64(*rhs_i);
                    let lo = res_i.shl_words(i);
                    let hi = {
                        let mut hi = res_i.shr_words($n_words - i);
                        hi.0[i] = carry_mul;
                        hi
                    };
                    let (res_lo_new, carry0) = res_lo.overflowing_add(&lo);
                    let (res_hi_new, carry1) = res_hi.overflowing_add_with_carry(&hi, carry0);
                    assert!(!carry1);
                    res_hi = res_hi_new;
                    res_lo = res_lo_new;
                }
                (res_lo, res_hi)
            }

            fn shr_words(&self, n: usize) -> Self {
                let mut res = [0u64; $n_words];
                (&mut res[0..($n_words - n)]).copy_from_slice(&self.0[n..$n_words]);
                Self(res)
            }

            fn shl_words(&self, n: usize) -> Self {
                let mut res = [0u64; $n_words];
                (&mut res[n..$n_words]).copy_from_slice(&self.0[0..($n_words - n)]);
                Self(res)
            }

            pub fn checked_mul(&self, other: &Self) -> Option<Self> {
                let (res, res_hi) = self.widening_mul(other);
                (res_hi == Self::ZERO).then_some(res)
            }

            pub fn checked_div(&self, other: &Self) -> Option<Self> {
                (*other != Self::ZERO).then(|| self.unchecked_div(other))
            }

            pub fn checked_rem(&self, other: &Self) -> Option<Self> {
                (*other != Self::ZERO).then(|| self.unchecked_rem(other))
            }
        }

        impl From<[u8; $n_words * 8]> for $name {
            /// Creates a Uint256 from the given bytes array of fixed length.
            ///
            /// # Note
            ///
            /// The given bytes are assumed to be in little endian order.
            #[inline]
            fn from(data: [u8; $n_words * 8]) -> Self {
                Self::from_bytes(data)
            }
        }

        impl<'a> From<&'a [u8; $n_words * 8]> for $name {
            /// Creates a Uint256 from the given reference
            /// to the bytes array of fixed length.
            ///
            /// # Note
            ///
            /// The given bytes are assumed to be in little endian order.
            #[inline]
            fn from(data: &'a [u8; $n_words * 8]) -> Self {
                Self::inner_from_slice(data)
            }
        }

        impl From<u64> for $name {
            #[inline]
            fn from(n: u64) -> Self {
                Self::from_u64(n)
            }
        }

        impl From<u128> for $name {
            #[inline]
            fn from(n: u128) -> Self {
                Self::from_u128(n)
            }
        }

        impl From<Amount> for $name {
            #[inline]
            fn from(n: Amount) -> Self {
                Self::from_amount(n)
            }
        }

        impl PartialOrd for $name {
            #[inline]
            fn partial_cmp(&self, other: &$name) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }

        impl Ord for $name {
            #[inline]
            fn cmp(&self, other: &$name) -> ::core::cmp::Ordering {
                // We need to manually implement ordering because we use little endian
                // and the auto derive is a lexicographic ordering(i.e. memcmp)
                // which with numbers is equivalent to big endian
                for i in 0..$n_words {
                    if self[$n_words - 1 - i] < other[$n_words - 1 - i] {
                        return ::core::cmp::Ordering::Less;
                    }
                    if self[$n_words - 1 - i] > other[$n_words - 1 - i] {
                        return ::core::cmp::Ordering::Greater;
                    }
                }
                ::core::cmp::Ordering::Equal
            }
        }

        impl ::core::ops::Add<$name> for $name {
            type Output = Option<$name>;

            fn add(self, other: $name) -> Option<$name> {
                self.checked_add(&other)
            }
        }

        impl ::core::ops::Sub<$name> for $name {
            type Output = Option<$name>;

            #[inline]
            fn sub(self, other: $name) -> Option<$name> {
                self.checked_sub(&other)
            }
        }

        impl ::core::ops::Mul<$name> for $name {
            type Output = Option<$name>;

            fn mul(self, other: $name) -> Option<$name> {
                self.checked_mul(&other)
            }
        }

        impl ::core::ops::Div<$name> for $name {
            type Output = Option<$name>;

            fn div(self, other: $name) -> Option<$name> {
                self.checked_div(&other)
            }
        }

        impl ::core::ops::Rem<$name> for $name {
            type Output = Option<$name>;

            fn rem(self, other: $name) -> Option<$name> {
                self.checked_rem(&other)
            }
        }

        impl $crate::uint::BitArray for $name {
            #[inline]
            fn bit(&self, index: usize) -> bool {
                let &$name(ref arr) = self;
                arr[index / 64] & (1 << (index % 64)) != 0
            }

            #[inline]
            fn bit_slice(&self, start: usize, end: usize) -> $name {
                (*self >> start).mask(end - start)
            }

            #[inline]
            fn mask(&self, n: usize) -> $name {
                let &$name(ref arr) = self;
                let mut ret = [0; $n_words];
                for i in 0..$n_words {
                    if n >= 0x40 * (i + 1) {
                        ret[i] = arr[i];
                    } else {
                        ret[i] = arr[i] & ((1 << (n - 0x40 * i)) - 1);
                        break;
                    }
                }
                $name(ret)
            }

            #[inline]
            fn trailing_zeros(&self) -> usize {
                let &$name(ref arr) = self;
                for i in 0..($n_words - 1) {
                    if arr[i] > 0 {
                        return (0x40 * i) + arr[i].trailing_zeros() as usize;
                    }
                }
                (0x40 * ($n_words - 1)) + arr[$n_words - 1].trailing_zeros() as usize
            }

            fn zero() -> $name {
                Default::default()
            }
            fn one() -> $name {
                $name({
                    let mut ret = [0; $n_words];
                    ret[0] = 1;
                    ret
                })
            }
        }

        impl ::core::ops::BitAnd<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitand(self, other: $name) -> $name {
                let $name(ref arr1) = self;
                let $name(ref arr2) = other;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = arr1[i] & arr2[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::BitXor<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitxor(self, other: $name) -> $name {
                let $name(ref arr1) = self;
                let $name(ref arr2) = other;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = arr1[i] ^ arr2[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::BitOr<$name> for $name {
            type Output = $name;

            #[inline]
            fn bitor(self, other: $name) -> $name {
                let $name(ref arr1) = self;
                let $name(ref arr2) = other;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = arr1[i] | arr2[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::Not for $name {
            type Output = $name;

            #[inline]
            fn not(self) -> $name {
                let $name(ref arr) = self;
                let mut ret = [0u64; $n_words];
                for i in 0..$n_words {
                    ret[i] = !arr[i];
                }
                $name(ret)
            }
        }

        impl ::core::ops::Shl<usize> for $name {
            type Output = $name;

            fn shl(self, shift: usize) -> $name {
                let $name(ref original) = self;
                let mut ret = [0u64; $n_words];
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for i in 0..$n_words {
                    // Shift
                    if bit_shift < 64 && i + word_shift < $n_words {
                        ret[i + word_shift] += original[i] << bit_shift;
                    }
                    // Carry
                    if bit_shift > 0 && i + word_shift + 1 < $n_words {
                        ret[i + word_shift + 1] += original[i] >> (64 - bit_shift);
                    }
                }
                $name(ret)
            }
        }

        impl ::core::ops::Shr<usize> for $name {
            type Output = $name;

            fn shr(self, shift: usize) -> $name {
                let $name(ref original) = self;
                let mut ret = [0u64; $n_words];
                let word_shift = shift / 64;
                let bit_shift = shift % 64;
                for i in word_shift..$n_words {
                    // Shift
                    ret[i - word_shift] += original[i] >> bit_shift;
                    // Carry
                    if bit_shift > 0 && i < $n_words - 1 {
                        ret[i - word_shift] += original[i + 1] << (64 - bit_shift);
                    }
                }
                $name(ret)
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                let &$name(ref data) = self;
                write!(f, "0x")?;
                for ch in data.iter().rev() {
                    write!(f, "{:016x}", ch)?;
                }
                Ok(())
            }
        }

        impl std::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                if f.alternate() {
                    write!(f, "0x")?;
                }
                let &$name(ref data) = self;
                for ch in data.iter().rev() {
                    write!(f, "{:016x}", ch)?;
                }
                Ok(())
            }
        }

        impl std::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                if f.alternate() {
                    write!(f, "0X")?;
                }
                let &$name(ref data) = self;
                for ch in data.iter().rev() {
                    write!(f, "{:016X}", ch)?;
                }
                Ok(())
            }
        }
    };
}

construct_uint!(Uint512, 8);
construct_uint!(Uint256, 4);
construct_uint!(Uint128, 2);

/// Invalid slice length
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
/// Invalid slice length
pub struct ParseLengthError {
    /// The length of the slice de-facto
    pub actual: usize,
    /// The required length of the slice
    pub expected: usize,
}

impl core::fmt::Display for ParseLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Invalid length: got {}, expected {}",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for ParseLengthError {}

impl Uint256 {
    /// Decay to a uint128
    #[inline]
    pub fn low_128(&self) -> Uint128 {
        let &Uint256(data) = self;
        Uint128([data[0], data[1]])
    }
}

impl From<Uint128> for u128 {
    #[inline]
    fn from(n: Uint128) -> Self {
        u128::from_le_bytes(n.to_bytes())
    }
}

impl From<Uint256> for Uint512 {
    #[inline]
    fn from(n: Uint256) -> Self {
        Uint512([n[0], n[1], n[2], n[3], 0x0, 0x0, 0x0, 0x0])
    }
}

impl From<Uint128> for Uint256 {
    #[inline]
    fn from(n: Uint128) -> Self {
        Self([n[0], n[1], 0x0, 0x0])
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum UintConversionError {
    #[error("Conversion would overflow result type")]
    ConversionOverflow,
}

impl TryFrom<Uint256> for u128 {
    type Error = UintConversionError;

    fn try_from(n: Uint256) -> Result<Self, UintConversionError> {
        if n > Uint256::from_u128(u128::MAX) {
            Err(UintConversionError::ConversionOverflow)
        } else {
            Ok(n.low_128().into())
        }
    }
}

impl TryFrom<Uint512> for Uint256 {
    type Error = UintConversionError;

    fn try_from(n: Uint512) -> Result<Self, UintConversionError> {
        if n > Uint256::MAX.into() {
            Err(UintConversionError::ConversionOverflow)
        } else {
            Ok(Uint256([n[0], n[1], n[2], n[3]]))
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::uint::BitArray;
    use randomness::Rng;
    use test_utils::random::{make_seedable_rng, Seed};

    #[test]
    pub fn uint256_bits_test() {
        assert_eq!(Uint256::from_u64(255).bits(), 8);
        assert_eq!(Uint256::from_u64(256).bits(), 9);
        assert_eq!(Uint256::from_u64(300).bits(), 9);
        assert_eq!(Uint256::from_u64(60000).bits(), 16);
        assert_eq!(Uint256::from_u64(70000).bits(), 17);

        // Try to read the following lines out loud quickly
        let mut shl = Uint256::from_u64(70000);
        shl = shl << 100;
        assert_eq!(shl.bits(), 117);
        shl = shl << 100;
        assert_eq!(shl.bits(), 217);
        shl = shl << 100;
        assert_eq!(shl.bits(), 0);

        // Bit set check
        assert!(!Uint256::from_u64(10).bit(0));
        assert!(Uint256::from_u64(10).bit(1));
        assert!(!Uint256::from_u64(10).bit(2));
        assert!(Uint256::from_u64(10).bit(3));
        assert!(!Uint256::from_u64(10).bit(4));
    }

    #[test]
    pub fn uint256_display_test() {
        assert_eq!(
            format!("{:?}", Uint256::from_u64(0xDEADBEEF)),
            "0x00000000000000000000000000000000000000000000000000000000deadbeef"
        );
        assert_eq!(
            format!("{:x}", Uint256::from_u64(0xDEADBEEF)),
            "00000000000000000000000000000000000000000000000000000000deadbeef"
        );
        assert_eq!(
            format!("{:#x}", Uint256::from_u64(0xDEADBEEF)),
            "0x00000000000000000000000000000000000000000000000000000000deadbeef"
        );
        assert_eq!(
            format!("{:X}", Uint256::from_u64(0xDEADBEEF)),
            "00000000000000000000000000000000000000000000000000000000DEADBEEF"
        );
        assert_eq!(
            format!("{:#X}", Uint256::from_u64(0xDEADBEEF)),
            "0X00000000000000000000000000000000000000000000000000000000DEADBEEF"
        );
        assert_eq!(
            format!("{:?}", Uint256::from_u64(u64::MAX)),
            "0x000000000000000000000000000000000000000000000000ffffffffffffffff"
        );
        assert_eq!(
            format!("{:x}", Uint256::from_u64(u64::MAX)),
            "000000000000000000000000000000000000000000000000ffffffffffffffff"
        );
        assert_eq!(
            format!("{:#x}", Uint256::from_u64(u64::MAX)),
            "0x000000000000000000000000000000000000000000000000ffffffffffffffff"
        );
        assert_eq!(
            format!("{:X}", Uint256::from_u64(u64::MAX)),
            "000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF"
        );
        assert_eq!(
            format!("{:#X}", Uint256::from_u64(u64::MAX)),
            "0X000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFF"
        );

        let max_val = Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]);
        assert_eq!(
            format!("{max_val:?}"),
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    pub fn uint256_comp_test() {
        let small = Uint256([10u64, 0, 0, 0]);
        let big = Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let bigger = Uint256([0x9C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0]);
        let biggest = Uint256([0x5C8C3EE70C644118u64, 0x0209E7378231E632, 0, 1]);

        assert!(small < big);
        assert!(big < bigger);
        assert!(bigger < biggest);
        assert!(bigger <= biggest);
        assert!(bigger >= big);
        assert!(bigger >= small);
    }

    #[test]
    pub fn uint_from_be_bytes() {
        assert_eq!(
            Uint128::from_be_bytes([
                0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed,
                0xfe, 0xed
            ]),
            Uint128([0xdeafbabe2bedfeed, 0x1badcafedeadbeef])
        );

        assert_eq!(
            Uint256::from_be_bytes([
                0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed,
                0xfe, 0xed, 0xba, 0xad, 0xf0, 0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba,
                0xd1, 0xc0, 0xff, 0xe0
            ]),
            Uint256([
                0x11fed2bad1c0ffe0,
                0xbaadf00ddefaceda,
                0xdeafbabe2bedfeed,
                0x1badcafedeadbeef
            ])
        );
    }

    #[test]
    pub fn uint_to_be_bytes() {
        assert_eq!(
            Uint128([0xdeafbabe2bedfeed, 0x1badcafedeadbeef]).to_be_bytes(),
            [
                0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed,
                0xfe, 0xed
            ]
        );

        assert_eq!(
            Uint256([
                0x11fed2bad1c0ffe0,
                0xbaadf00ddefaceda,
                0xdeafbabe2bedfeed,
                0x1badcafedeadbeef
            ])
            .to_be_bytes(),
            [
                0x1b, 0xad, 0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe, 0x2b, 0xed,
                0xfe, 0xed, 0xba, 0xad, 0xf0, 0x0d, 0xde, 0xfa, 0xce, 0xda, 0x11, 0xfe, 0xd2, 0xba,
                0xd1, 0xc0, 0xff, 0xe0
            ]
        );
    }

    #[test]
    pub fn uint_from_le_bytes() {
        assert_eq!(
            Uint128::from([
                0xed, 0xfe, 0xed, 0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca,
                0xad, 0x1b
            ]),
            Uint128([0xdeafbabe2bedfeed, 0x1badcafedeadbeef])
        );

        assert_eq!(
            Uint256::from([
                0xe0, 0xff, 0xc0, 0xd1, 0xba, 0xd2, 0xfe, 0x11, 0xda, 0xce, 0xfa, 0xde, 0x0d, 0xf0,
                0xad, 0xba, 0xed, 0xfe, 0xed, 0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde,
                0xfe, 0xca, 0xad, 0x1b,
            ]),
            Uint256([
                0x11fed2bad1c0ffe0,
                0xbaadf00ddefaceda,
                0xdeafbabe2bedfeed,
                0x1badcafedeadbeef
            ])
        );
    }

    #[test]
    pub fn uint_to_le_bytes() {
        assert_eq!(
            Uint128([0xdeafbabe2bedfeed, 0x1badcafedeadbeef]).to_bytes(),
            [
                0xed, 0xfe, 0xed, 0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca,
                0xad, 0x1b
            ]
        );

        assert_eq!(
            Uint256([
                0x11fed2bad1c0ffe0,
                0xbaadf00ddefaceda,
                0xdeafbabe2bedfeed,
                0x1badcafedeadbeef,
            ])
            .to_bytes(),
            [
                0xe0, 0xff, 0xc0, 0xd1, 0xba, 0xd2, 0xfe, 0x11, 0xda, 0xce, 0xfa, 0xde, 0x0d, 0xf0,
                0xad, 0xba, 0xed, 0xfe, 0xed, 0x2b, 0xbe, 0xba, 0xaf, 0xde, 0xef, 0xbe, 0xad, 0xde,
                0xfe, 0xca, 0xad, 0x1b,
            ]
        );
    }

    #[test]
    pub fn uint256_arithmetic_test() {
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF);
        let copy = init;

        let add = (init + copy).unwrap();
        assert_eq!(add, Uint256([0xBD5B7DDFBD5B7DDEu64, 1, 0, 0]));
        // Bitshifts
        let shl = add << 88;
        assert_eq!(shl, Uint256([0u64, 0xDFBD5B7DDE000000, 0x1BD5B7D, 0]));
        let shr = shl >> 40;
        assert_eq!(
            shr,
            Uint256([0x7DDE000000000000u64, 0x0001BD5B7DDFBD5B, 0, 0])
        );
        // Increment
        let mut incr = shr;
        incr = (incr + 1u64.into()).unwrap();
        assert_eq!(
            incr,
            Uint256([0x7DDE000000000001u64, 0x0001BD5B7DDFBD5B, 0, 0])
        );
        // Subtraction
        let sub = (incr - init).unwrap();
        assert_eq!(
            sub,
            Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0])
        );
        // Multiplication
        let mult = sub.mul_u32(300);
        assert_eq!(
            mult,
            Uint256([0x8C8C3EE70C644118u64, 0x0209E7378231E632, 0, 0])
        );
        // Division
        assert_eq!(
            (Uint256::from_u64(105) / Uint256::from_u64(5)).unwrap(),
            Uint256::from_u64(21)
        );
        let div = (mult / Uint256::from_u64(300)).unwrap();
        assert_eq!(
            div,
            Uint256([0x9F30411021524112u64, 0x0001BD5B7DDFBD5A, 0, 0])
        );

        assert_eq!(
            (Uint256::from_u64(105) % Uint256::from_u64(5)).unwrap(),
            Uint256::from_u64(0)
        );
        assert_eq!(
            (Uint256::from_u64(35498456) % Uint256::from_u64(3435)).unwrap(),
            Uint256::from_u64(1166)
        );
        let m = (mult * Uint256::from_u64(39842)).unwrap();
        let rem_src = (m + Uint256::from_u64(9054)).unwrap();
        assert_eq!(
            (rem_src % Uint256::from_u64(39842)).unwrap(),
            Uint256::from_u64(9054)
        );
        // TODO: bit inversion
    }

    #[test]
    pub fn mul_u32_test() {
        let u64_val = Uint256::from_u64(0xDEADBEEFDEADBEEF);

        let u96_res = u64_val.mul_u32(0xFFFFFFFF);
        let u128_res = u96_res.mul_u32(0xFFFFFFFF);
        let u160_res = u128_res.mul_u32(0xFFFFFFFF);
        let u192_res = u160_res.mul_u32(0xFFFFFFFF);
        let u224_res = u192_res.mul_u32(0xFFFFFFFF);
        let u256_res = u224_res.mul_u32(0xFFFFFFFF);

        assert_eq!(u96_res, Uint256([0xffffffff21524111u64, 0xDEADBEEE, 0, 0]));
        assert_eq!(
            u128_res,
            Uint256([0x21524111DEADBEEFu64, 0xDEADBEEE21524110, 0, 0])
        );
        assert_eq!(
            u160_res,
            Uint256([0xBD5B7DDD21524111u64, 0x42A4822200000001, 0xDEADBEED, 0])
        );
        assert_eq!(
            u192_res,
            Uint256([0x63F6C333DEADBEEFu64, 0xBD5B7DDFBD5B7DDB, 0xDEADBEEC63F6C334, 0])
        );
        assert_eq!(
            u224_res,
            Uint256([0x7AB6FBBB21524111u64, 0xFFFFFFFBA69B4558, 0x854904485964BAAA, 0xDEADBEEB])
        );
        assert_eq!(
            u256_res,
            Uint256([
                0xA69B4555DEADBEEFu64,
                0xA69B455CD41BB662,
                0xD41BB662A69B4550,
                0xDEADBEEAA69B455C
            ])
        );
    }

    #[test]
    pub fn multiplication_test() {
        let u64_val = Uint256::from_u64(0xDEADBEEFDEADBEEF);

        let u128_res = (u64_val * u64_val).unwrap();

        assert_eq!(
            u128_res,
            Uint256([0x048D1354216DA321u64, 0xC1B1CD13A4D13D46, 0, 0])
        );

        let u256_res = (u128_res * u128_res).unwrap();

        assert_eq!(
            u256_res,
            Uint256([
                0xF4E166AAD40D0A41u64,
                0xF5CF7F3618C2C886u64,
                0x4AFCFF6F0375C608u64,
                0x928D92B4D7F5DF33u64
            ])
        );

        let u256_val: Uint512 = Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ])
        .into();
        let u512_res = (u256_val * u256_val).unwrap();
        assert_eq!(
            u512_res,
            Uint512([
                0x0000000000000001,
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x3FFFFFFFFFFFFFFF,
            ])
        );
    }

    #[test]
    pub fn increment_test() {
        let mut val = Uint256([
            0xFFFFFFFFFFFFFFFEu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xEFFFFFFFFFFFFFFFu64,
        ]);
        val = (val + 1u64.into()).unwrap();
        assert_eq!(
            val,
            Uint256([
                0xFFFFFFFFFFFFFFFFu64,
                0xFFFFFFFFFFFFFFFFu64,
                0xFFFFFFFFFFFFFFFFu64,
                0xEFFFFFFFFFFFFFFFu64,
            ])
        );
        val = (val + 1u64.into()).unwrap();
        assert_eq!(
            val,
            Uint256([
                0x0000000000000000u64,
                0x0000000000000000u64,
                0x0000000000000000u64,
                0xF000000000000000u64,
            ])
        );

        let val = Uint256([
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
            0xFFFFFFFFFFFFFFFFu64,
        ]);
        assert!((val + 1u64.into()).is_none());

        let max_val_u256 = Uint256::MAX;
        let mut a = Uint512::from(max_val_u256);
        a = (a + 1u64.into()).unwrap();
        assert_eq!(a, Uint512([0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]));

        let max_val = Uint512::MAX;
        assert!((max_val + 1u64.into()).is_none());
    }

    #[test]
    pub fn uint256_bitslice_test() {
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF);
        let add = (init + (init << 64)).unwrap();
        assert_eq!(add.bit_slice(64, 128), init);
        assert_eq!(add.mask(64), init);
    }

    #[test]
    pub fn uint256_extreme_bitshift_test() {
        // Shifting a u64 by 64 bits gives an undefined value, so make sure that
        // we're doing the Right Thing here
        let init = Uint256::from_u64(0xDEADBEEFDEADBEEF);

        assert_eq!(init << 64, Uint256([0, 0xDEADBEEFDEADBEEF, 0, 0]));
        let add = ((init << 64) + init).unwrap();
        assert_eq!(add, Uint256([0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0, 0]));
        assert_eq!(add >> 64, Uint256([0xDEADBEEFDEADBEEF, 0, 0, 0]));
        assert_eq!(
            add << 64,
            Uint256([0, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0])
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uint256_from_uint128(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        for _ in 0..1000 {
            let v = rng.gen::<u128>();
            let b1 = v << 64;
            let a1 = Uint256::from_u64(v as u64);
            let b2 = a1 << 64;
            let b3 = Uint256::from_u128(b1);
            assert_eq!(b2, b3);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn uint512_from_uint256(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        for _ in 0..1000 {
            let v = rng.gen::<u128>();
            let a1 = v << 64;
            let b1 = Uint256::from_u128(a1) << (64 * 2);
            let a2 = Uint512::from_u64(v as u64);
            let b2 = a2 << (64 * 3);
            let b3 = Uint512::from(b1);
            assert_eq!(b2, b3);
        }
    }

    #[test]
    pub fn uint512_from_uint256_simple() {
        assert_eq!(Uint512::ONE, Uint512::from(Uint256::ONE));

        let a = Uint256([0xFA, 0xFB, 0xFC, 0xFD]);
        let b = Uint512([0xFA, 0xFB, 0xFC, 0xFD, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(Uint512::from(a), b);

        let a = Uint256::MAX;
        let b = Uint512([u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(Uint512::from(a), b);
    }

    #[test]
    pub fn uint256_from_uint512_simple() {
        assert_eq!(Uint256::ONE, Uint256::try_from(Uint512::ONE).unwrap());

        let a = Uint256([0xFA, 0xFB, 0xFC, 0xFD]);
        let b = Uint512([0xFA, 0xFB, 0xFC, 0xFD, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(Uint256::try_from(b).unwrap(), a);

        let a = Uint256::MAX;
        let b = Uint512([u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(Uint256::try_from(b).unwrap(), a);

        let a = (Uint512::from(Uint256::MAX) + Uint512::ONE).unwrap();
        assert_eq!(
            Uint256::try_from(a).unwrap_err(),
            UintConversionError::ConversionOverflow
        );

        let a = Uint512::MAX;
        assert_eq!(
            Uint256::try_from(a).unwrap_err(),
            UintConversionError::ConversionOverflow
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn u128_from_uint128(#[case] seed: Seed) {
        assert_eq!(1u128, Uint128::ONE.into());
        assert_eq!(u128::MAX, Uint128::MAX.into());

        let mut rng = make_seedable_rng(seed);
        for _ in 0..1000 {
            let a = rng.gen::<u128>();
            let b = Uint128::from_u128(a);
            assert_eq!(a, b.into());
        }
    }

    #[test]
    pub fn uint128_from_uint256_simple() {
        assert_eq!(1u128, u128::try_from(Uint256::ONE).unwrap());

        let a = u128::from_str_radix("FB00000000000000FA", 16).unwrap();
        let b = Uint256([0xFA, 0xFB, 0x00, 0x00]);
        assert_eq!(u128::try_from(b).unwrap(), a);

        let a = u128::MAX;
        let b = Uint256([u64::MAX, u64::MAX, 0x00, 0x00]);
        assert_eq!(u128::try_from(b).unwrap(), a);

        let a = (Uint256::from(u128::MAX) + Uint256::ONE).unwrap();
        assert_eq!(
            u128::try_from(a).unwrap_err(),
            UintConversionError::ConversionOverflow
        );

        let a = Uint256::MAX;
        assert_eq!(
            u128::try_from(a).unwrap_err(),
            UintConversionError::ConversionOverflow
        );
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn checked_add(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        {
            let a = Uint128::MAX;
            let b = rng.gen_range(1..u128::MAX).into();
            assert!(a.checked_add(&b).is_none());
            assert!(b.checked_add(&a).is_none());
        }
        {
            let a: Uint128 = rng.gen::<u128>().into();
            let b = (Uint128::MAX - a).unwrap();
            assert_eq!(a.checked_add(&b), Some(a.overflowing_add(&b).0));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn checked_sub(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        {
            let a = Uint128::ZERO;
            let b = rng.gen_range(1..u128::MAX).into();
            assert!(a.checked_sub(&b).is_none());
        }
        {
            let a = rng.gen::<u128>();
            let b: Uint128 = rng.gen_range(0..a).into();
            let a: Uint128 = a.into();
            assert_eq!(a.checked_sub(&b), Some(a.unchecked_sub(&b)));
            assert_eq!(b.checked_sub(&a), None);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn checked_mul(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        {
            let a = Uint128::MAX;
            let b = rng.gen_range(2..u128::MAX).into();
            assert!(a.checked_mul(&b).is_none());
            assert!(b.checked_mul(&a).is_none());
        }
        {
            let a: Uint128 = rng.gen::<u128>().into();
            let b = Uint128::ZERO;
            assert_eq!(a.checked_mul(&b), Some(Uint128::ZERO));
            assert_eq!(b.checked_mul(&a), Some(Uint128::ZERO));
            assert_eq!(b.checked_mul(&b), Some(Uint128::ZERO));
        }
        {
            let a = Uint128::from_u64(rng.gen::<u64>());
            let b = Uint128::from_u64(rng.gen::<u64>());
            assert_eq!(a.checked_mul(&b), Some(a.widening_mul(&b).0));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn checked_div(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        {
            let a: Uint128 = rng.gen::<u128>().into();
            let b = Uint128::ZERO;
            assert!(a.checked_div(&b).is_none());
        }
        {
            let a = Uint128::ZERO;
            let b: Uint128 = rng.gen::<u128>().into();
            assert_eq!(a.checked_div(&b), Some(Uint128::ZERO));
        }
        {
            let a: Uint128 = rng.gen::<u128>().into();
            let b: Uint128 = rng.gen::<u128>().into();
            assert_eq!(a.checked_div(&b), Some(a.unchecked_div(&b)));
        }
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn uint128_u128_equivalent() {
        // *_m - model, *_v - to be verified against the model
        let a_m = kani::any();
        let b_m = kani::any();
        let a_v = Uint128::from_u128(a_m);
        let b_v = Uint128::from_u128(b_m);

        {
            let (ab_m, c_m) = a_m.overflowing_add(b_m);
            let (ab_v, c_v) = a_v.overflowing_add(&b_v);
            assert_eq!(Uint128::from_u128(ab_m), ab_v, "Result mismatch");
            assert_eq!(c_m, c_v, "Carry flag mismatch");
        }
    }

    #[cfg(feature = "expensive-verification")]
    #[kani::proof]
    fn uint128_mul_u64() {
        let a_m = kani::any();
        let a_v = Uint128::from_u128(a_m);
        let b: u64 = kani::any();

        let (ab_m, is_verflow_m) = a_m.overflowing_mul(b as u128);
        let (ab_v, c_v) = a_v.widening_mul_u64(b);
        assert_eq!(Uint128::from_u128(ab_m), ab_v, "Result mismatch");
        assert_eq!(is_verflow_m, c_v != 0, "Carry flag mismatch");
    }

    #[cfg(feature = "expensive-verification")]
    #[kani::proof]
    fn uint128_mul_u64max() {
        let x = Uint128(kani::any());
        let u64_max = Uint128::from_u64(u64::MAX);
        let r = (Uint256::from(x) << 64) - Uint256::from(x);
        let r_hi = Uint128([r.0[2], r.0[3]]);
        let r_lo = Uint128([r.0[0], r.0[1]]);
        assert_eq!(x.widening_mul(&u64_max), (r_lo, r_hi));
        assert_eq!(u64_max.widening_mul(&x), (r_lo, r_hi));
    }

    #[kani::proof]
    fn uint128_mul_u64big() {
        let x = Uint128(kani::any());
        kani::assume(x != Uint128::ZERO);
        let big = Uint128::from_u64(3u64 << 62);
        let r = (Uint256::from(x) << 62) + (Uint256::from(x) << 63);
        let r_hi = Uint128([r.0[2], r.0[3]]);
        let r_lo = Uint128([r.0[0], r.0[1]]);
        assert_eq!(x.widening_mul(&big), (r_lo, r_hi));
        assert_eq!(big.widening_mul(&x), (r_lo, r_hi));
    }

    #[kani::proof]
    fn uint256_additive_identity() {
        let x = Uint256(kani::any());
        assert_eq!(x + Uint256::ZERO, x);
        assert_eq!(Uint256::ZERO + x, x);
    }

    #[kani::proof]
    fn uint256_add_commut() {
        let x = Uint256(kani::any());
        let y = Uint256(kani::any());
        assert_eq!(x.overflowing_add(&y), y.overflowing_add(&x));
    }

    #[kani::proof]
    fn uint256_add_assoc() {
        let x = Uint256(kani::any());
        let y = Uint256(kani::any());
        let z = Uint256(kani::any());
        assert_eq!(
            x.checked_add(&y).and_then(|xy| xy.checked_add(&z)),
            y.checked_add(&z).and_then(|yz| x.checked_add(&yz)),
        );
    }

    #[kani::proof]
    fn uint256_mul_up_to_5_commut() {
        let x = Uint256(kani::any());
        let y2 = Uint256::from_u64(2);
        let y3 = Uint256::from_u64(3);
        let y4 = Uint256::from_u64(4);
        let y5 = Uint256::from_u64(5);
        assert_eq!(x.widening_mul(&y2), y2.widening_mul(&x));
        assert_eq!(x.widening_mul(&y3), y3.widening_mul(&x));
        assert_eq!(x.widening_mul(&y4), y4.widening_mul(&x));
        assert_eq!(x.widening_mul(&y5), y5.widening_mul(&x));
    }

    #[kani::proof]
    fn uint256_mul_01() {
        let x = Uint256(kani::any());
        assert_eq!(
            x.widening_mul(&Uint256::ZERO),
            (Uint256::ZERO, Uint256::ZERO)
        );
        assert_eq!(x.widening_mul(&Uint256::ONE), (x, Uint256::ZERO));
        assert_eq!(
            Uint256::ZERO.widening_mul(&x),
            (Uint256::ZERO, Uint256::ZERO)
        );
        assert_eq!(Uint256::ONE.widening_mul(&x), (x, Uint256::ZERO));
    }

    #[kani::proof]
    fn shl_and_shl_words_agree() {
        let x = Uint256(kani::any());
        for i in 0..=4 {
            assert_eq!(x << (i * 64), x.shl_words(i));
            assert_eq!(x >> (i * 64), x.shr_words(i));
        }
    }
}
