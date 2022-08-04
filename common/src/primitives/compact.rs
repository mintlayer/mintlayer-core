// Copyright (c) 2022 RBB S.r.l
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

use crate::uint::Uint256;
use serialization::{Decode, Encode};
use std::ops::Shl;

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Debug, Encode, Decode)]
pub struct Compact(pub u32);

impl TryFrom<Compact> for Uint256 {
    type Error = Option<Uint256>;

    // https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L203
    fn try_from(value: Compact) -> Result<Self, Self::Error> {
        let compact = value.0;
        let size = compact >> 24;
        let mut word = compact & 0x007FFFFF;

        let value = if size <= 3 {
            word >>= 8 * (3 - size);

            Uint256::from_u64(word as u64)
        } else {
            let value = Uint256::from_u64(word as u64);
            let shift = 8 * (size - 3);
            value.shl(shift as usize)
        };

        if (word != 0 && (compact & 0x00800000) != 0)
            || (word != 0
                && ((size > 34) || (word > 0xFF && size > 33) || (word > 0xFFFF && size > 32)))
        {
            return Err(Some(value));
        }

        Ok(value)
    }
}

// https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.cpp#L223
impl From<Uint256> for Compact {
    fn from(value: Uint256) -> Self {
        let mut size = (value.bits() + 7) / 8;

        let mut compact = if size <= 3 {
            value.low_u64() << (8 * (3 - size))
        } else {
            let bn = value >> (8 * (size - 3));
            bn.low_u64()
        };

        if (compact & 0x00800000) != 0 {
            compact >>= 8;
            size += 1;
        }

        let x = compact as u32 | (size << 24) as u32;

        Compact(x)
    }
}

#[cfg(test)]
mod tests {
    // taken from https://github.com/bitcoin/bitcoin/blob/master/src/test/arith_uint256_tests.cpp#L406
    use super::*;

    fn check_conversion(for_uint256: u32, expected_value: u32) {
        let uint256 = {
            let compact = Compact(for_uint256);
            Uint256::try_from(compact).expect("conversion should not fail from compact to uint256")
        };

        let updated_compact = Compact::from(uint256);
        assert_eq!(updated_compact, Compact(expected_value));
    }

    #[test]
    fn test_compact_uint256_conversion() {
        let u256 = Uint256::from_u64(0x80);
        let compact = Compact::from(u256);
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
    fn test_err_conversion() {
        fn err_conversion(c: u32) {
            match Uint256::try_from(Compact(c)) {
                Ok(v) => {
                    panic!("conversion of {} should fail, not {:?}", c, v);
                }
                Err(e) => {
                    assert!(e.is_some())
                }
            }
        }

        err_conversion(0x04923456);
        err_conversion(0x01fedcba);
        err_conversion(!0x00800000); // overflow
    }
    /*

    #[test]
    fn test_min_difficulty() {
        let min_difficulty = Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ]);
        let compact: Compact = min_difficulty.into();
        let min_difficulty_again = Uint256::try_from(compact).expect("conversion");
        assert_eq!(min_difficulty, min_difficulty_again)
    }
    */
}
