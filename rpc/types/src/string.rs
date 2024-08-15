// Copyright (c) 2024 RBB S.r.l
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

use rpc_description::{HasValueHint, ValueHint as VH};

/// Binary data encoded as a hex string in Serde/RPC.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "HexStringSerde", into = "HexStringSerde")]
pub struct RpcHexString(Vec<u8>);

impl RpcHexString {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::str::FromStr for RpcHexString {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(Self)
    }
}

impl AsRef<[u8]> for RpcHexString {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for RpcHexString {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl From<RpcHexString> for Vec<u8> {
    fn from(value: RpcHexString) -> Self {
        value.into_bytes()
    }
}

impl std::fmt::Display for RpcHexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        hex::encode(self.as_bytes()).fmt(f)
    }
}

impl std::fmt::LowerHex for RpcHexString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as std::fmt::Display>::fmt(self, f)
    }
}

impl rpc_description::HasValueHint for RpcHexString {
    const HINT_SER: VH = VH::HEX_STRING;
}

#[derive(serde::Serialize, serde::Deserialize)]
struct HexStringSerde(String);

impl From<RpcHexString> for HexStringSerde {
    fn from(value: RpcHexString) -> Self {
        Self(hex::encode(value.0))
    }
}

impl TryFrom<HexStringSerde> for RpcHexString {
    type Error = hex::FromHexError;

    fn try_from(value: HexStringSerde) -> Result<Self, Self::Error> {
        value.0.parse()
    }
}

/// A binary string type suitable for use in RPC input parameters. Accepts a string or a hex
/// string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(into = "RpcStringSer", try_from = "RpcStringDe")]
pub struct RpcString(Vec<u8>);

impl RpcString {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_string(data: String) -> Self {
        Self(data.into_bytes())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn try_into_string(self) -> Result<String, (Self, std::str::Utf8Error)> {
        String::from_utf8(self.0).map_err(|e| {
            let err = e.utf8_error();
            let this = Self::from_bytes(e.into_bytes());
            (this, err)
        })
    }

    pub fn try_as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(self.as_ref())
    }
}

impl AsRef<[u8]> for RpcString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for RpcString {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl From<String> for RpcString {
    fn from(value: String) -> Self {
        Self::from_string(value)
    }
}

impl From<RpcHexString> for RpcString {
    fn from(value: RpcHexString) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl HasValueHint for RpcString {
    const HINT_SER: VH =
        VH::Object(&[("text", &<Option<String>>::HINT_SER), ("hex", &VH::HEX_STRING)]);
    const HINT_DE: VH = VH::Choice(&[&VH::STRING, &VH::Object(&[("hex", &VH::HEX_STRING)])]);
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RpcStringSer {
    #[serde(default)]
    text: Option<String>,
    hex: RpcHexString,
}

impl From<RpcString> for RpcStringSer {
    fn from(value: RpcString) -> Self {
        let hex = value.0.clone().into();
        let text = String::from_utf8(value.0).ok();
        Self { text, hex }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum RpcStringDe {
    Obj {
        #[serde(default)]
        text: Option<String>,
        #[serde(default)]
        hex: Option<RpcHexString>,
    },
    Bare(String),
}

#[derive(PartialEq, Debug, thiserror::Error)]
enum RpcStringDeError {
    #[error("Text and hex keys hold different data")]
    Mismatch,
    #[error("Neither text nor hex is present")]
    Missing,
}

impl TryFrom<RpcStringDe> for RpcString {
    type Error = RpcStringDeError;

    fn try_from(value: RpcStringDe) -> Result<Self, Self::Error> {
        match value {
            RpcStringDe::Bare(s) => Ok(s.into()),
            RpcStringDe::Obj { text, hex } => match (text, hex) {
                (None, None) => Err(RpcStringDeError::Missing),
                (None, Some(hex)) => Ok(hex.into()),
                (Some(text), None) => Ok(text.into()),
                (Some(text), Some(hex)) if text.as_bytes() == hex.as_ref() => Ok(hex.into()),
                (Some(_text), Some(_hex)) => Err(RpcStringDeError::Mismatch),
            },
        }
    }
}
