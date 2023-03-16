// Copyright (c) 2023 RBB S.r.l
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

use serialization::{Decode, Encode};
use thiserror::Error;
use utils::ensure;

const MAX_LENGTH: usize = 24;

/// Wrapper type for the user agent string.
///
/// Used to validate the submitted string.
/// The string cannot be too long and can only contain ASCII alphanumeric characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode)]
pub struct UserAgent(Vec<u8>);

pub fn mintlayer_core_user_agent() -> UserAgent {
    "MintlayerCore".try_into().expect("default value must be valid")
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum UserAgentError {
    #[error("Empty string is not allowed")]
    Empty,
    #[error("The string is too long: {0}, max allowed: {1}")]
    TooLong(usize, usize),
    #[error("Only ASCII alphanumeric characters allowed")]
    InvalidChars,
}

impl From<UserAgentError> for serialization::Error {
    fn from(error: UserAgentError) -> Self {
        match error {
            UserAgentError::Empty => serialization::Error::from("Is empty"),
            UserAgentError::TooLong(_, _) => serialization::Error::from("The string is too long"),
            UserAgentError::InvalidChars => {
                serialization::Error::from("Only ASCII alphanumeric characters allowed")
            }
        }
    }
}

impl Decode for UserAgent {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        <Vec<u8>>::decode(input)?.try_into().map_err(Into::into)
    }
}

impl TryFrom<Vec<u8>> for UserAgent {
    type Error = UserAgentError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(UserAgentError::Empty);
        }
        ensure!(!value.is_empty(), UserAgentError::Empty);
        ensure!(
            value.len() <= MAX_LENGTH,
            UserAgentError::TooLong(value.len(), MAX_LENGTH)
        );
        ensure!(
            value.iter().all(|ch| (*ch as char).is_ascii_alphanumeric()),
            UserAgentError::InvalidChars
        );
        Ok(Self(value))
    }
}

impl TryFrom<&str> for UserAgent {
    type Error = UserAgentError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes().to_owned())
    }
}

impl std::fmt::Display for UserAgent {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.write_str(std::str::from_utf8(&self.0).expect("already checked"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(value: &str, valid: bool) {
        let convert_res = UserAgent::try_from(value.as_bytes().to_owned());
        assert_eq!(
            convert_res.is_ok(),
            valid,
            "convert check failed for {}",
            value
        );

        let encoded = value.encode();
        let decode_res =
            <UserAgent as serialization::DecodeAll>::decode_all(&mut encoded.as_slice());
        assert_eq!(
            decode_res.is_ok(),
            valid,
            "decode check failed for {}",
            value
        );

        if let Ok(decoded) = decode_res {
            assert_eq!(decoded.to_string(), value);
        }
    }

    #[test]
    fn user_agent() {
        // Valid values
        check("1", true);
        check("MintlayerCore", true);
        check("SomeLongString1234567890", true);

        // Invalid values
        check("", false);
        check("VeryLongStringVeryLongString", false);
        check("京", false);
    }
}
