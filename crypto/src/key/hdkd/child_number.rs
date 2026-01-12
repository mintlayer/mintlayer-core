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

use std::{
    fmt::{self, Formatter, Write},
    str::FromStr,
};

use super::{derivable::DerivationError, u31::U31};

const HARDENED_APOS: char = '\'';
const HARDENED_H: char = 'h';

/// BIP32-like child numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChildNumber(u32);

impl ChildNumber {
    pub const ZERO: Self = ChildNumber(0);
    pub const ONE: Self = ChildNumber(1);

    /// Return a hardened child number
    pub const fn from_hardened(index: U31) -> Self {
        ChildNumber(index.into_encoded_with_msb(true))
    }

    /// Return a normal child number
    pub const fn from_normal(index: U31) -> Self {
        ChildNumber(index.into_encoded_with_msb(false))
    }

    /// Return a child based on the hardened bit (MSB bit)
    pub fn from_index_with_hardened_bit(index: u32) -> Self {
        Self(index)
    }

    /// Get the index without the hardened bit set
    pub const fn get_index(&self) -> U31 {
        U31::from_u32_with_msb(self.0).0
    }

    /// Return a BIP32-like child number index that has the hardened bit set if needed
    pub fn into_encoded_index(self) -> u32 {
        self.0
    }

    pub fn is_hardened(&self) -> bool {
        U31::from_u32_with_msb(self.0).1
    }

    pub fn is_normal(&self) -> bool {
        !self.is_hardened()
    }

    pub fn into_encoded_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn from_encoded_be_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }

    pub fn increment(&self) -> Result<Self, DerivationError> {
        let (index_u31, msb) = U31::from_u32_with_msb(self.0);
        let new_index_u31 = index_u31.plus_one()?;
        Ok(Self(U31::into_encoded_with_msb(new_index_u31, msb)))
    }
}

impl FromStr for ChildNumber {
    type Err = DerivationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check if this child number is hardened and get the index number string
        let (index_str, is_hardened) = match s.strip_suffix([HARDENED_APOS, HARDENED_H]) {
            Some(prefix) => (prefix, true),
            None => (s, false),
        };

        // Check that the number string contains only digits
        if index_str.bytes().any(|c| !c.is_ascii_digit()) {
            return Err(DerivationError::InvalidChildNumberFormat);
        }

        // Check if the number has leading 0s
        if index_str.len() > 1 && index_str.starts_with('0') {
            return Err(DerivationError::InvalidChildNumberFormat);
        }

        let index = U31::from_str(index_str)?;

        if is_hardened {
            Ok(ChildNumber::from_hardened(index))
        } else {
            Ok(ChildNumber::from_normal(index))
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (index_u31, msb) = U31::from_u32_with_msb(self.0);
        if msb {
            fmt::Display::fmt(&index_u31, f)?;
            let alt = f.alternate();
            f.write_char(if alt { HARDENED_H } else { HARDENED_APOS })
        } else {
            fmt::Display::fmt(&index_u31, f)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::key::hdkd::child_number::ChildNumber;
    use crate::key::hdkd::u31;
    use crate::key::hdkd::u31::U31;
    use randomness::RngCore;
    use rstest::rstest;
    use std::str::FromStr;
    use test_utils::random::make_seedable_rng;
    use test_utils::random::Seed;

    fn examine_child_number(num: ChildNumber, encoded_num: u32, is_hardened: bool) {
        assert_eq!(num.is_normal(), !is_hardened);
        assert_eq!(num.is_hardened(), is_hardened);
        assert_eq!(num.into_encoded_index(), encoded_num);
        assert_eq!(num.into_encoded_be_bytes(), encoded_num.to_be_bytes());
    }

    #[rstest]
    #[trace]
    #[case(0, false)]
    #[case(1, false)]
    #[case(1234567, false)]
    #[case(!0x80000000 - 1, false)]
    #[case(!0x80000000, false)]
    #[case(!0x80000000 + 1, true)]
    #[case(u32::MAX - 1, true)]
    #[case(u32::MAX, true)]
    fn create_child_number(#[case] encoded_num: u32, #[case] is_hardened: bool) {
        test_create_child_number(encoded_num, is_hardened)
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn create_child_number_random(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let encoded_num: u32 = rng.next_u32() | u31::MSB_BIT;
        let is_hardened: bool = true;
        test_create_child_number(encoded_num, is_hardened);

        let encoded_num: u32 = encoded_num & !u31::MSB_BIT;
        let is_hardened: bool = false;
        test_create_child_number(encoded_num, is_hardened);
    }

    fn test_create_child_number(encoded_num: u32, is_hardened: bool) {
        let num = ChildNumber::from_index_with_hardened_bit(encoded_num);
        examine_child_number(num, encoded_num, is_hardened);

        // Check to string and from string parsing
        // <child_number>' form
        let num_str_expected = format!("{}{}", num.get_index(), if is_hardened { "'" } else { "" });
        let num_str = format!("{num}");
        assert_eq!(num_str, num_str_expected);
        let parsed_num = ChildNumber::from_str(&num_str).unwrap();
        assert_eq!(parsed_num, num);
        examine_child_number(parsed_num, encoded_num, is_hardened);

        // <child_number>h form
        let num_str_expected = format!("{}{}", num.get_index(), if is_hardened { "h" } else { "" });
        let num_str = format!("{num:#}");
        assert_eq!(num_str, num_str_expected);
        let parsed_num = ChildNumber::from_str(&num_str).unwrap();
        assert_eq!(parsed_num, num);
        examine_child_number(parsed_num, encoded_num, is_hardened);

        // Check explicit normal child
        let normal = ChildNumber::from_normal(U31::from_u32_with_msb(encoded_num).0);
        examine_child_number(normal, encoded_num & !u31::MSB_BIT, false);

        // Check explicit hardened child
        let hardened = ChildNumber::from_hardened(U31::from_u32_with_msb(encoded_num).0);
        examine_child_number(hardened, encoded_num | u31::MSB_BIT, true);
    }
}
