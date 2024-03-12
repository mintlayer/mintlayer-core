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
}

impl AsRef<[u8]> for RpcHexString {
    fn as_ref(&self) -> &[u8] {
        &self.0
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

impl rpc_description::HasValueHint for RpcHexString {
    const HINT: VH = VH::HEX_STRING;
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
        Ok(RpcHexString::from_bytes(hex::decode(value.0)?))
    }
}

/// A binary string type suitable for use in RPC input parameters. Accepts a string or a hex
/// string.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(into = "RpcStringInSerde", from = "RpcStringInSerde")]
pub struct RpcStringIn(Vec<u8>);

impl RpcStringIn {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_string(data: String) -> Self {
        Self(data.into_bytes())
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
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

impl AsRef<[u8]> for RpcStringIn {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for RpcStringIn {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl From<String> for RpcStringIn {
    fn from(value: String) -> Self {
        Self::from_string(value)
    }
}

impl From<RpcHexString> for RpcStringIn {
    fn from(value: RpcHexString) -> Self {
        Self::from_bytes(value.into_bytes())
    }
}

impl HasValueHint for RpcStringIn {
    const HINT: VH = VH::Choice(&[&VH::STRING, &VH::Object(&[("hex", &VH::HEX_STRING)])]);
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum RpcStringInSerde {
    Text(String),
    Hex(RpcHexString),
    #[serde(untagged)]
    Bare(String),
}

impl From<RpcStringIn> for RpcStringInSerde {
    fn from(value: RpcStringIn) -> Self {
        Self::Hex(RpcHexString::from_bytes(value.0))
    }
}

impl From<RpcStringInSerde> for RpcStringIn {
    fn from(value: RpcStringInSerde) -> Self {
        match value {
            RpcStringInSerde::Text(s) | RpcStringInSerde::Bare(s) => s.into(),
            RpcStringInSerde::Hex(hex) => hex.into(),
        }
    }
}

/// A binary string type suitable for use in RPC return values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(into = "RpcStringOutSerde", try_from = "RpcStringOutSerde")]
pub struct RpcStringOut(Vec<u8>);

impl RpcStringOut {
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn from_string(data: String) -> Self {
        Self(data.into_bytes())
    }
}

impl From<Vec<u8>> for RpcStringOut {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl From<String> for RpcStringOut {
    fn from(value: String) -> Self {
        Self::from_string(value)
    }
}

impl HasValueHint for RpcStringOut {
    const HINT: VH = RpcStringOutSerde::HINT;
}

#[derive(serde::Serialize, serde::Deserialize, HasValueHint)]
struct RpcStringOutSerde {
    text: Option<String>,
    hex: RpcHexString,
}

impl From<RpcStringOut> for RpcStringOutSerde {
    fn from(value: RpcStringOut) -> Self {
        let hex = value.0.clone().into();
        let text = String::from_utf8(value.0).ok();
        Self { text, hex }
    }
}

#[derive(PartialEq, Debug, thiserror::Error)]
enum RpcStringOutConversionError {
    #[error("Text and hex keys hold different data")]
    TextHexMismatch,
}

impl TryFrom<RpcStringOutSerde> for RpcStringOut {
    type Error = RpcStringOutConversionError;
    fn try_from(value: RpcStringOutSerde) -> Result<Self, Self::Error> {
        let bytes = value.hex.into_bytes();
        utils::ensure!(
            value.text.map_or(true, |text| text.as_bytes() == &bytes),
            RpcStringOutConversionError::TextHexMismatch,
        );
        Ok(Self(bytes))
    }
}
