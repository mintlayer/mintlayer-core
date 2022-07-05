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

use super::Bech32Error;
use super::DecodedArbitraryDataFromBech32;
use super::DecodedBase32FromBech32;
use bech32::u5;
use bech32::{self, Variant};

pub fn base32_to_bech32m<S: AsRef<str>, T: AsRef<[u5]>>(
    hrp: S,
    data: T,
) -> Result<String, Bech32Error> {
    bech32::encode(hrp.as_ref(), data, Variant::Bech32m).map_err(|e| e.into())
}

#[allow(dead_code)]
pub fn bech32m_to_base32(s: &str) -> Result<DecodedBase32FromBech32, Bech32Error> {
    match bech32::decode(s) {
        Ok((hrp, base32, variant)) => {
            if variant == Variant::Bech32 {
                return Err(Bech32Error::UnsupportedVariant);
            }

            // ------- this checking is only for BITCOIN: Witness Programs
            // if hrp == "bc" && ( s.len() < 2 || s.len() > 40 ) {
            //     return Err(Bech32Error::InvalidLength);
            // }
            // ------- EOL

            Ok(DecodedBase32FromBech32::new(hrp, base32))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn arbitrary_data_to_bech32m<S: AsRef<str>, T: AsRef<[u8]>>(
    hrp: S,
    data: T,
) -> Result<String, Bech32Error> {
    let data = super::base32::encode(data.as_ref())?;
    bech32::encode(hrp.as_ref(), data, Variant::Bech32m).map_err(|e| e.into())
}

pub fn bech32m_to_arbitrary_data<S: AsRef<str>>(
    s: S,
) -> Result<DecodedArbitraryDataFromBech32, Bech32Error> {
    match bech32::decode(s.as_ref()) {
        Ok((hrp, base32, variant)) => {
            if variant == Variant::Bech32 {
                return Err(Bech32Error::UnsupportedVariant);
            }

            let data = super::base32::decode(base32)?;
            Ok(DecodedArbitraryDataFromBech32::new(hrp, data))
        }
        Err(e) => Err(e.into()),
    }
}
