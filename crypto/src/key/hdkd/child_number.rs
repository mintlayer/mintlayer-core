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

use serialization::{Decode, Encode, Error, Input, Output};
use std::{
    fmt::{self, Formatter, Write},
    str::FromStr,
};

use super::{derivable::DerivationError, u31::U31};

const HARDENED_APOS: char = '\'';
const HARDENED_H: char = 'h';

/// BIP32-like child numbers. Currently we only support hardened derivations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChildNumber(DerivationType);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
enum DerivationType {
    Normal(U31),
    Hardened(U31),
}

impl ChildNumber {
    pub const ZERO: Self = ChildNumber(DerivationType::Normal(U31::from_u32_with_msb(0).0));

    /// Return a hardened child number
    pub const fn from_hardened(index: U31) -> Self {
        ChildNumber(DerivationType::Hardened(index))
    }

    /// Return a normal child number
    pub const fn from_normal(index: U31) -> Self {
        ChildNumber(DerivationType::Normal(index))
    }

    /// Return a child based on the hardened bit (MSB bit)
    pub fn from_index_with_hardened_bit(index: u32) -> Self {
        let (index_u31, msb) = U31::from_u32_with_msb(index);
        if msb {
            Self::from_hardened(index_u31)
        } else {
            Self::from_normal(index_u31)
        }
    }

    /// Get the index without the hardened bit set
    pub fn get_index(&self) -> u32 {
        match self.0 {
            DerivationType::Normal(i) | DerivationType::Hardened(i) => i.into(),
        }
    }

    /// Return a BIP32-like child number index that has the hardened bit set if needed
    pub fn into_encoded_index(self) -> u32 {
        match self.0 {
            DerivationType::Normal(i) => i.into_encoded_with_msb(false),
            DerivationType::Hardened(i) => i.into_encoded_with_msb(true),
        }
    }

    pub fn into_encoded_be_bytes(self) -> [u8; 4] {
        self.into_encoded_index().to_be_bytes()
    }

    pub fn is_hardened(&self) -> bool {
        match self.0 {
            DerivationType::Normal(_) => false,
            DerivationType::Hardened(_) => true,
        }
    }

    pub fn is_normal(&self) -> bool {
        !self.is_hardened()
    }

    pub fn plus_one(&self) -> Result<Self, DerivationError> {
        match self.0 {
            DerivationType::Normal(i) => Ok(ChildNumber(DerivationType::Normal(i.plus_one()?))),
            DerivationType::Hardened(i) => Ok(ChildNumber(DerivationType::Hardened(i.plus_one()?))),
        }
    }
}

impl Encode for ChildNumber {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.write(&self.into_encoded_be_bytes());
    }
}

impl Decode for ChildNumber {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut num_be_bytes = [0u8; 4];
        input.read(&mut num_be_bytes)?;
        Ok(Self::from_index_with_hardened_bit(u32::from_be_bytes(
            num_be_bytes,
        )))
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
        match self.0 {
            DerivationType::Hardened(index) => {
                fmt::Display::fmt(&index, f)?;
                let alt = f.alternate();
                f.write_char(if alt { HARDENED_H } else { HARDENED_APOS })
            }
            DerivationType::Normal(index) => fmt::Display::fmt(&index, f),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::key::hdkd::child_number::ChildNumber;
    use crate::key::hdkd::u31;
    use crate::key::hdkd::u31::U31;
    use rstest::rstest;
    use serialization::{DecodeAll, Encode};
    use std::str::FromStr;

    fn examine_child_number(num: ChildNumber, encoded_num: u32, is_hardened: bool) {
        assert_eq!(num.is_normal(), !is_hardened);
        assert_eq!(num.is_hardened(), is_hardened);
        assert_eq!(num.into_encoded_index(), encoded_num);
        assert_eq!(num.into_encoded_be_bytes(), encoded_num.to_be_bytes());
        assert_eq!(
            num,
            ChildNumber::decode_all(&mut num.encode().as_slice()).unwrap()
        );
    }

    #[rstest]
    #[trace]
    #[case(0, false)]
    #[case(1, false)]
    #[case(1234567, false)]
    #[case(u32::MAX & (!0x80000000 - 1), false)]
    #[case(u32::MAX & !0x80000000, false)]
    #[case(u32::MAX & (!0x80000000 + 1), true)]
    #[case(u32::MAX - 1, true)]
    #[case(u32::MAX, true)]
    fn create_child_number(#[case] encoded_num: u32, #[case] is_hardened: bool) {
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
