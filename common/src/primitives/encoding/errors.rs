// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bech32::{self, Error};
use core::fmt;

#[derive(thiserror::Error, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Bech32Error {
    /// missing separator
    #[error("Missing separator`")]
    NoSeparator,
    #[error("Invalid checksum")]
    FailedChecksum,
    #[error("Length either too short or too long")]
    InvalidLength,
    #[error("Char value not supported")]
    InvalidChar(char),
    #[error("Provided u8 value in the data is invalid")]
    InvalidData(u8),
    #[error("Padding issue")]
    InvalidPadding,
    #[error("Mix of lowercase and uppercase is not allowed")]
    MixCase,
    #[error("Only variant Bech32m is supported")]
    UnsupportedVariant,
    #[error("List of indices containing invalid characters in a bech32 string `{0:?}`")]
    ErrorLocation(Vec<usize>),
    #[error("Standard rust error: `{0}`")]
    StdError(#[from] fmt::Error),
}

impl From<bech32::Error> for Bech32Error {
    fn from(e: Error) -> Self {
        match e {
            Error::MissingSeparator => Self::NoSeparator,
            Error::InvalidChecksum => Self::FailedChecksum,
            Error::InvalidLength => Self::InvalidLength,
            Error::InvalidChar(x) => Self::InvalidChar(x),
            Error::InvalidData(x) => Self::InvalidData(x),
            Error::InvalidPadding => Self::InvalidPadding,
            Error::MixedCase => Self::MixCase,
        }
    }
}
