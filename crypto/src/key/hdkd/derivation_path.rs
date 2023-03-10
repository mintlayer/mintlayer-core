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

use super::child_number::ChildNumber;
use super::derivable::DerivationError;
use core::fmt;
use serialization::{Decode, Encode, Error, Input, Output};
use std::fmt::Formatter;
use std::str::FromStr;

const PREFIX: &str = "m";
const SEPARATOR: &str = "/";
/// The typical path size in BIP44 is 5 and we add this path limit
/// in order to support SLIP32 key serialization
const MAX_PATH_SIZE: usize = u8::MAX as usize;

/// BIP-32 compatible derivation path
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct DerivationPath(Vec<ChildNumber>);

impl DerivationPath {
    pub fn empty() -> Self {
        DerivationPath(vec![])
    }

    pub fn into_vec(self) -> Vec<ChildNumber> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Encode for DerivationPath {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        let size = self.0.len();
        debug_assert!(size <= MAX_PATH_SIZE);
        let size = size as u8;
        dest.push_byte(size);
        for num in &self.0 {
            dest.write(&num.into_encoded_be_bytes());
        }
    }
}

impl Decode for DerivationPath {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let size = input.read_byte()?;
        let mut path = Vec::with_capacity(size as usize);

        for _ in 0..size {
            path.push(<ChildNumber>::decode(input)?);
        }
        Ok(DerivationPath(path))
    }
}

impl TryFrom<Vec<ChildNumber>> for DerivationPath {
    type Error = DerivationError;

    fn try_from(path: Vec<ChildNumber>) -> Result<Self, Self::Error> {
        if path.len() <= MAX_PATH_SIZE {
            Ok(DerivationPath(path))
        } else {
            Err(DerivationError::PathTooLong)
        }
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
        path?.try_into()
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(PREFIX, f)?;
        for child in self.0.iter() {
            fmt::Display::fmt(SEPARATOR, f)?;
            fmt::Display::fmt(child, f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::{assert_encoded_eq, decode_from_hex};

    #[test]
    fn parse_derivation_path() {
        assert_eq!(
            DerivationPath::from_str(""),
            Err(DerivationError::InvalidDerivationPathFormat)
        );
        assert_eq!(
            DerivationPath::from_str("m/"),
            Err(DerivationError::InvalidChildNumberFormat)
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
        assert_eq!(DerivationPath::from_str("m"), Ok(DerivationPath::empty()));
        assert_eq!(
            DerivationPath::from_str("m/0'"),
            Ok(vec![ChildNumber::from_hardened(0.try_into().unwrap())].try_into().unwrap())
        );
        assert_eq!(
            DerivationPath::from_str("m/0h/1'/2'"),
            Ok(vec![
                ChildNumber::from_hardened(0.try_into().unwrap()),
                ChildNumber::from_hardened(1.try_into().unwrap()),
                ChildNumber::from_hardened(2.try_into().unwrap()),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1'/2h/2h"),
            Ok(vec![
                ChildNumber::from_hardened(0.try_into().unwrap()),
                ChildNumber::from_hardened(1.try_into().unwrap()),
                ChildNumber::from_hardened(2.try_into().unwrap()),
                ChildNumber::from_hardened(2.try_into().unwrap()),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DerivationPath::from_str("m/0'/1'/2/2'/1000000000"),
            Ok(vec![
                ChildNumber::from_hardened(0.try_into().unwrap()),
                ChildNumber::from_hardened(1.try_into().unwrap()),
                ChildNumber::from_normal(2.try_into().unwrap()),
                ChildNumber::from_hardened(2.try_into().unwrap()),
                ChildNumber::from_normal(1000000000.try_into().unwrap()),
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DerivationPath::from_str("m/2147483647/2147483647'"),
            Ok(vec![
                ChildNumber::from_normal(2147483647.try_into().unwrap()),
                ChildNumber::from_hardened(2147483647.try_into().unwrap())
            ]
            .try_into()
            .unwrap())
        );
        assert_eq!(
            DerivationPath::from_str("m/2147483648'"),
            Err(DerivationError::InvalidChildNumber(2147483648))
        );
    }

    #[test]
    fn max_size() {
        let path = vec![ChildNumber::ZERO; MAX_PATH_SIZE].to_vec();
        assert!(DerivationPath::try_from(path).is_ok());
        let path = vec![ChildNumber::ZERO; MAX_PATH_SIZE + 1].to_vec();
        assert!(DerivationPath::try_from(path).is_err());
    }

    #[test]
    fn push_pop_path() {
        let path_1_2 = DerivationPath::from_str("m/1'/2'").unwrap();
        let mut path = path_1_2.clone().into_vec();
        let index_3 = ChildNumber::from_hardened(3.try_into().unwrap());
        path.push(index_3);
        assert_eq!(
            path,
            DerivationPath::from_str("m/1'/2'/3'").unwrap().into_vec()
        );
        assert_eq!(path.pop(), Some(index_3));
        assert_eq!(path, path_1_2.into_vec());
        path.pop();
        path.pop();
        assert_eq!(path.pop(), None);
    }

    #[test]
    fn serialization() {
        let path_string = "m/44'/2'/0'/1/255";
        let path_encoded_hex = "058000002c800000028000000000000001000000ff";
        let path = DerivationPath::from_str(path_string).unwrap();
        // Assert encoding
        assert_encoded_eq(&path, path_encoded_hex);
        // Assert decoding
        let decoded_path: DerivationPath = decode_from_hex(path_encoded_hex);
        assert_eq!(path_string, decoded_path.to_string());
        assert_eq!(path, decoded_path);
    }

    #[test]
    fn len_and_is_empty_() {
        let path_string = "m/1/2/3";
        let path = DerivationPath::from_str(path_string).unwrap();
        assert_eq!(path.len(), 3);
        assert!(DerivationPath::empty().is_empty());
    }
}
