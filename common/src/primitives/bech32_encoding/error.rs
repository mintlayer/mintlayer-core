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

use bech32::{
    self,
    primitives::{decode::CheckedHrpstringError, hrp},
    DecodeError, EncodeError,
};

#[derive(thiserror::Error, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum Bech32Error {
    /// missing separator
    #[error("Decode parsing error: `{0}`")]
    DecodeParsingError(String),
    #[error("Checksum error: `{0}`")]
    DecodeChecksumError(String),
    #[error("Unknown decode error: `{0}`")]
    UnknownDecodeError(String),
    #[error("Data too long for encoding: `{0}`")]
    EncodeTooLongError(String),
    #[error("Encode formatter error: `{0}`")]
    EncodeFormatterError(String),
    #[error("Unknown encode error: `{0}`")]
    UnknownEncodeError(String),
    #[error("Hrp too long: `{0}`")]
    HrpTooLong(usize),
    #[error("Hrp is empty")]
    HrpEmpty,
    #[error("Mixed case found in hrp")]
    MixedCase,
    #[error("Hrp contains non-ascii character: `{0}`")]
    HrpNonAscii(char),
    #[error("Hrp contains invalid byte: `{0}`")]
    HrpInvalidByte(u8),
    #[error("Unknown hrp error: `{0}`")]
    UnknownHrpError(String),
    #[error("Variant check parse error: `{0}`")]
    VariantCheckParseError(String),
    #[error("Variant check checksum error: `{0}`")]
    VariantCheckChecksumError(String),
    #[error("Unknown variant check error: `{0}`")]
    UnknownVariantCheckError(String),
}

impl From<DecodeError> for Bech32Error {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::Parse(e) => Bech32Error::DecodeParsingError(e.to_string()),
            DecodeError::Checksum(e) => Bech32Error::DecodeChecksumError(e.to_string()),
            _ => Bech32Error::UnknownDecodeError(e.to_string()),
        }
    }
}

impl From<EncodeError> for Bech32Error {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::TooLong(e) => Bech32Error::EncodeTooLongError(e.to_string()),
            EncodeError::Fmt(e) => Bech32Error::EncodeFormatterError(e.to_string()),
            _ => Bech32Error::UnknownEncodeError(e.to_string()),
        }
    }
}

impl From<hrp::Error> for Bech32Error {
    fn from(e: hrp::Error) -> Self {
        match e {
            hrp::Error::TooLong(size) => Bech32Error::HrpTooLong(size),
            hrp::Error::Empty => Bech32Error::HrpEmpty,
            hrp::Error::NonAsciiChar(ch) => Bech32Error::HrpNonAscii(ch),
            hrp::Error::InvalidAsciiByte(b) => Bech32Error::HrpInvalidByte(b),
            hrp::Error::MixedCase => Bech32Error::MixedCase,
            _ => Bech32Error::UnknownHrpError(e.to_string()),
        }
    }
}

impl From<CheckedHrpstringError> for Bech32Error {
    fn from(e: CheckedHrpstringError) -> Self {
        match e {
            CheckedHrpstringError::Parse(e) => Bech32Error::VariantCheckParseError(e.to_string()),
            CheckedHrpstringError::Checksum(e) => {
                Bech32Error::VariantCheckChecksumError(e.to_string())
            }
            _ => Bech32Error::UnknownVariantCheckError(e.to_string()),
        }
    }
}
