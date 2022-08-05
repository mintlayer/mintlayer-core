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

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decoded<T> {
    hrp: String,
    data: Vec<T>,
    // TODO: see if this can benefit for short string optimization
}

impl<T> Decoded<T> {
    pub fn hrp(&self) -> &str {
        &self.hrp
    }

    pub fn data(&self) -> &[T] {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBase32FromBech32(Decoded<bech32::u5>);

impl DecodedBase32FromBech32 {
    pub fn new(hrp: String, data: Vec<bech32::u5>) -> Self {
        Self(Decoded { hrp, data })
    }

    pub fn hrp(&self) -> &str {
        self.0.hrp()
    }

    pub fn data(&self) -> &[bech32::u5] {
        self.0.data()
    }

    pub fn encode(&self) -> Result<String, Bech32Error> {
        bech32m::base32_to_bech32m(self.hrp(), self.data())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedArbitraryDataFromBech32(Decoded<u8>);

impl DecodedArbitraryDataFromBech32 {
    pub fn new(hrp: String, data: Vec<u8>) -> Self {
        Self(Decoded { hrp, data })
    }

    pub fn hrp(&self) -> &str {
        self.0.hrp()
    }

    pub fn data(&self) -> &[u8] {
        self.0.data()
    }

    pub fn encode(&self) -> Result<String, Bech32Error> {
        bech32m::arbitrary_data_to_bech32m(self.hrp(), self.data())
    }
}
