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

use std::{fmt::Display, str::FromStr};

use crate::hex::{HexDecode, HexEncode, HexError};

/// Wrapper that serializes objects as hex encoded string for `serde`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexEncoded<T>(T);

impl<T> HexEncoded<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn take(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for HexEncoded<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for HexEncoded<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: serialization_core::Encode> serde::Serialize for HexEncoded<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex = self.0.hex_encode();
        serializer.serialize_str(&hex)
    }
}

impl<'de, T: serialization_core::Decode> serde::Deserialize<'de> for HexEncoded<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        let value = T::hex_decode_all(hex).map_err(serde::de::Error::custom)?;
        Ok(HexEncoded(value))
    }
}

impl<T: serialization_core::Decode> FromStr for HexEncoded<T> {
    type Err = HexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <T as HexDecode>::hex_decode_all(s).map(Self)
    }
}

impl<T: serialization_core::Encode> Display for HexEncoded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0.hex_encode())
    }
}

impl<T> rpc_description::HasValueHint for HexEncoded<T> {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::HEX_STRING;
}
