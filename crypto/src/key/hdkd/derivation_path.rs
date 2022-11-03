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

use super::derivable::DerivationError;
use super::u31::U31;
use core::fmt;
use std::fmt::{Formatter, Write};
use std::str::FromStr;

const PREFIX: &str = "m";
const SEPARATOR: &str = "/";
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

/// BIP-32 compatible derivation path
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct DerivationPath(Vec<ChildNumber>);

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(path: Vec<ChildNumber>) -> Self {
        DerivationPath(path)
    }
}

impl<'a> IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = std::slice::Iter<'a, ChildNumber>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl FromStr for DerivationPath {
    type Err = DerivationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(SEPARATOR);
        // Get the prefix part, if it exists
        let prefix_part = parts.next().ok_or(DerivationError::InvalidDerivationPathFormat)?;
        // Check if that prefix == "m"
        if prefix_part != PREFIX {
            return Err(DerivationError::InvalidDerivationPathFormat);
        }
        // Parse the rest of the parts to ChildNumber
        let path: Result<Vec<ChildNumber>, DerivationError> = parts.map(str::parse).collect();
        Ok(path?.into())
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(PREFIX, f)?;
        for child in self.0.iter() {
            fmt::Display::fmt(child, f)?;
            fmt::Display::fmt(SEPARATOR, f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_derivation_path() {
        assert_eq!(
            DerivationPath::from_str(""),
            Err(DerivationError::InvalidDerivationPathFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/42"),
            Err(DerivationError::UnsupportedDerivationType)
        );
        assert_eq!(
            DerivationPath::from_str("m/h"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("42"),
            Err(DerivationError::InvalidDerivationPathFormat)
        );
        assert_eq!(
            DerivationPath::from_str("n/0'/0"),
            Err(DerivationError::InvalidDerivationPathFormat)
        );
        assert_eq!(
            DerivationPath::from_str("4/m/5"),
            Err(DerivationError::InvalidDerivationPathFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m//3/0'"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/0x"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/2147483648"),
            Err(DerivationError::InvalidChildNumber(2147483648))
        );
        assert_eq!(
            DerivationPath::from_str("m/123'h"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/123h'"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/1e2h"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/+3h"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/-4"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/0008h"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/①②③h"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/❶❷❸'"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/⓵⓶⓷"),
            Err(DerivationError::InvalidChildNumberFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/⑴⑵⑶/456"),
            Err(DerivationError::InvalidChildNumberFormat)
        );

        assert_eq!(
            DerivationPath(vec![]),
            DerivationPath::from_str("m").unwrap()
        );
        // assert_eq!(DerivationPath::master(), DerivationPath::default());
        assert_eq!(DerivationPath::from_str("m"), Ok(vec![].into()));
        assert_eq!(
            DerivationPath::from_str("m/0'"),
            Ok(vec![ChildNumber::from_hardened(0.try_into().unwrap()).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/1'/2'"),
            Ok(vec![
                ChildNumber::from_hardened(0.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(1.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(2.try_into().unwrap()).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1'/2h/2h"),
            Ok(vec![
                ChildNumber::from_hardened(0.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(1.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(2.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(2.try_into().unwrap()).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1'/2'/2'/1000000000'"),
            Ok(vec![
                ChildNumber::from_hardened(0.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(1.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(2.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(2.try_into().unwrap()).unwrap(),
                ChildNumber::from_hardened(1000000000.try_into().unwrap()).unwrap(),
            ]
            .into())
        );
        assert_eq!(
            DerivationPath::from_str("m/2147483647'"),
            Ok(vec![ChildNumber::from_hardened(2147483647.try_into().unwrap()).unwrap()].into())
        );
        assert_eq!(
            DerivationPath::from_str("m/2147483648'"),
            Err(DerivationError::InvalidChildNumber(2147483648))
        );
    }
}
