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

mod error;
use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
pub use error::*;

pub fn bech32m_decode(s: impl AsRef<str>) -> Result<DecodedBech32, Bech32Error> {
    let (hrp, data) = bech32::decode(s.as_ref())?;

    // To ensure that the encoding is bech32m, this should be done separately, as bech32::decode() works for both bech32 and bech32m
    let _checked_type = CheckedHrpstring::new::<Bech32m>(s.as_ref())?;

    let result = DecodedBech32::new(hrp.as_str().to_string(), data);

    Ok(result)
}

pub fn bech32m_encode(
    hrp: impl AsRef<str>,
    data: impl AsRef<[u8]>,
) -> Result<String, error::Bech32Error> {
    let parsed_hrp = Hrp::parse(hrp.as_ref())?;

    let encoded = bech32::encode::<Bech32m>(parsed_hrp, data.as_ref())?;

    Ok(encoded)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBech32 {
    hrp: String,
    data: Vec<u8>,
}

impl DecodedBech32 {
    pub fn new(hrp: String, data: Vec<u8>) -> Self {
        Self { hrp, data }
    }

    pub fn hrp(&self) -> &str {
        &self.hrp
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
#[cfg(test)]
mod tests;
