use common::primitives::Uint256;
use std::ops::Shl;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub struct Compact(pub(crate) u32);

impl Compact {
    // https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L223
    pub fn from_uint256(value: Uint256) -> Option<Self> {
        let mut size = (value.bits() + 7) / 8;

        let mut compact = if size <= 3 {
            (value.low_u64() << (8 * (3 - size)))
        } else {
            let bn = value >> (8 * (size - 3));
            bn.low_u64()
        };

        if (compact & 0x00800000) != 0 {
            compact >>= 8;
            size += 1;
        }

        let x = compact as u32 | (size << 24) as u32;

        Some(Compact(x))
    }

    // https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L203
    pub fn into_uint256(self) -> Option<Uint256> {
        let compact = self.0;
        let size = compact >> 24;
        let mut word = compact & 0x007FFFFF;

        let value = if size <= 3 {
            word >>= 8 * (3 - size);

            Uint256::from_u64(word as u64)
        } else {
            Uint256::from_u64(word as u64).map(|x| {
                let shift = 8 * (size - 3);
                x.shl(shift as usize)
            })
        };

        if (word != 0 && (compact & 0x00800000) != 0)
            || (word != 0
                && ((size > 34) || (word > 0xFF && size > 33) || (word > 0xFFFF && size > 32)))
        {
            return None;
        }

        value
    }
}

#[cfg(test)]
mod tests {
    // taken from https://github.com/bitcoin/bitcoin/blob/master/src/test/arith_uint256_tests.cpp#L406
    use super::*;

    fn check_conversion(for_uint256: u32, expected_value: u32) {
        let uint256 = {
            let compact = Compact(for_uint256);
            compact
                .into_uint256()
                .expect("conversion should not fail from compact to uint256")
        };

        let updated_compact = Compact::from_uint256(uint256)
            .expect("conversion should not fail from uint256 to compact");
        assert_eq!(updated_compact, Compact(expected_value));
    }

    #[test]
    fn test_compact_uint256_conversion() {
        let u256 = Uint256::from_u64(0x80).expect("it should convert with not problems");
        let compact = Compact::from_uint256(u256).expect("it should convert with no problems");
        assert_eq!(compact, Compact(0x02008000));

        // zero values
        [
            0x00123456, 0x01003456, 0x02000056, 0x03000000, 0x04000000, 0x00923456, 0x01803456,
            0x02800056, 0x03800000, 0x04800000,
        ]
        .into_iter()
        .for_each(|x| {
            check_conversion(x, 0);
        });

        [
            (0x1d00ffff, 0x1d00ffff),
            (0x01123456, 0x01120000),
            (0x02123456, 0x02123400),
            (0x03123456, 0x03123456),
            (0x04123456, 0x04123456),
            (0x05009234, 0x05009234),
            (0x20123456, 0x20123456),
        ]
        .into_iter()
        .for_each(|(x, y)| {
            check_conversion(x, y);
        });
    }

    #[test]
    fn test_none_conversion() {
        assert!(Compact(0x04923456).into_uint256().is_none());
        assert!(Compact(0x01fedcba).into_uint256().is_none());
    }
}
