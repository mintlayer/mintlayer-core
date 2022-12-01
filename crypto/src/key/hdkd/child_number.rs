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

/// BIP32-like child numbers. Currently we only support hardened derivations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct ChildNumber(DerivationType);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
enum DerivationType {
    Hardened(U31),
}

impl ChildNumber {
    /// Return a hardened child number
    pub fn from_hardened(index: U31) -> Result<Self, DerivationError> {
        Ok(ChildNumber(DerivationType::Hardened(index)))
    }

    /// Return a normal child number
    fn from_normal(_index: U31) -> Result<Self, DerivationError> {
        // For the time being we don't support non-hardened derivations
        Err(DerivationError::UnsupportedDerivationType)
    }

    /// Return a child based on the hardened bit (MSB bit)
    pub fn from_index_with_hardened_bit(index: u32) -> Result<Self, DerivationError> {
        let (index_u31, msb) = U31::from_u32_with_msb(index);
        if msb {
            Self::from_hardened(index_u31)
        } else {
            Self::from_normal(index_u31)
        }
    }

    /// Return a BIP32-like child number index that has the hardened bit set if needed
    pub fn to_encoded_index(self) -> u32 {
        match self.0 {
            DerivationType::Hardened(i) => i.into_encoded_with_msb(true),
        }
    }

    pub fn to_encoded_be_bytes(self) -> [u8; 4] {
        self.to_encoded_index().to_be_bytes()
    }

    /// Returns true if this child number is hardened
    pub fn is_hardened(&self) -> bool {
        match self.0 {
            DerivationType::Hardened(_) => true,
        }
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
            ChildNumber::from_hardened(index)
        } else {
            ChildNumber::from_normal(index)
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
        }
    }
}
