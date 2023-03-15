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

use thiserror::Error;
use utils::ensure;

const MAX_LENGTH: usize = 24;

/// Wrapper type for the user agent string.
///
/// Used to validate the submitted string.
/// The string cannot be too long and can only contain ASCII alphanumeric characters.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UserAgent(String);

pub fn default_user_agent() -> UserAgent {
    "MintlayerCore".to_owned().try_into().expect("default value must be valid")
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

impl TryFrom<String> for UserAgent {
    type Error = UserAgentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ensure!(!value.is_empty(), UserAgentError::Empty);
        ensure!(
            value.len() <= MAX_LENGTH,
            UserAgentError::TooLong(value.len(), MAX_LENGTH)
        );
        ensure!(
            value.chars().all(|ch| ch.is_ascii_alphanumeric()),
            UserAgentError::InvalidChars
        );
        Ok(Self(value))
    }
}

impl AsRef<str> for UserAgent {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid(value: &str) -> bool {
        UserAgent::try_from(value.to_owned()).is_ok()
    }

    #[test]
    fn user_agent() {
        // Valid values
        assert!(valid("1"));
        assert!(valid("MintlayerCore"));
        assert!(valid("SomeLongString1234567890"));

        // Invalid values
        assert!(!valid(""));
        assert!(!valid("VeryLongStringVeryLongString"));
        assert!(!valid("京"));
    }
}
