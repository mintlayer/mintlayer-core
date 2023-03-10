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
