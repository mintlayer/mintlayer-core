// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

use crypto_bigint::{Encoding, U256, U512};
use serialization::{Decode, Encode};

#[macro_use]
pub(crate) mod internal_macros;

pub(crate) mod endian;

/// A trait which allows numbers to act as fixed-size bit arrays
pub trait BitArray {
    /// Is bit set?
    fn bit(&self, idx: usize) -> bool;

    /// Returns an array which is just the bits from start to end
    fn bit_slice(&self, start: usize, end: usize) -> Self;

    /// Bitwise and with `n` ones
    fn mask(&self, n: usize) -> Self;

    /// Trailing zeros
    fn trailing_zeros(&self) -> usize;

    /// Create all-zeros value
    fn zero() -> Self;

    /// Create value representing one
    fn one() -> Self;
}

#[derive(Debug, Clone)]
pub struct U256Encodable(pub U256);

impl Encode for U256Encodable {
    fn size_hint(&self) -> usize {
        32
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.0.to_le_bytes());
    }

    fn encoded_size(&self) -> usize {
        32
    }
}

impl Decode for U256Encodable {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let v = <[u8; 32]>::decode(input)?;
        Ok(U256Encodable(U256::from_le_bytes(v)))
    }
}

pub fn into_u512(u: U256) -> U512 {
    (U256::ZERO, u).into()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::primitives::H256;
    use rstest::rstest;
    use test_utils::random::Seed;

    #[test]
    fn convert() {
        assert_eq!(into_u512(U256::ONE), U512::ONE)
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    pub fn uint256_serialization(#[case] seed: Seed) {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let h256val = H256::random_using(&mut rng);
        let uint256val = U256Encodable(h256val.into());
        let encoded_h256 = h256val.encode();
        let encoded_uint256val = uint256val.encode();
        assert_eq!(encoded_uint256val.len(), 32);
        assert_eq!(encoded_h256, encoded_uint256val);
    }

    #[test]
    pub fn u256_display_test() {
        assert_eq!(
            format!("{:x}", U256::from_u64(0xDEADBEEF)),
            "00000000000000000000000000000000000000000000000000000000deadbeef"
        );
        assert_eq!(
            format!("{:x}", U256::from_u64(u64::max_value())),
            "000000000000000000000000000000000000000000000000ffffffffffffffff"
        );

        let max_val = U256::MAX;
        assert_eq!(
            format!("{max_val:x}"),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    pub fn uint256_bits_test() {
        assert_eq!(U256::from_u64(255).bits_vartime(), 8);
        assert_eq!(U256::from_u64(256).bits_vartime(), 9);
        assert_eq!(U256::from_u64(300).bits_vartime(), 9);
        assert_eq!(U256::from_u64(60000).bits_vartime(), 16);
        assert_eq!(U256::from_u64(70000).bits_vartime(), 17);

        // Try to read the following lines out loud quickly
        let mut shl = U256::from_u64(70000);
        shl = shl << 100;
        assert_eq!(shl.bits_vartime(), 117);
        shl = shl << 100;
        assert_eq!(shl.bits_vartime(), 217);
        shl = shl << 100;
        assert_eq!(shl.bits_vartime(), 0);

        // Bit set check
        assert_eq!(0, U256::from_u64(10).bit_vartime(0));
        assert_eq!(1, U256::from_u64(10).bit_vartime(1));
        assert_eq!(0, U256::from_u64(10).bit_vartime(2));
        assert_eq!(1, U256::from_u64(10).bit_vartime(3));
        assert_eq!(0, U256::from_u64(10).bit_vartime(4));
    }
}
