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

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serialization::{Decode, Encode};

use super::derivable::DerivationError;

pub const MSB_BIT: u32 = 0x80000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Serialize, Deserialize)]
pub struct U31(u32);

impl U31 {
    pub const ZERO: U31 = U31(0);
    pub const ONE: U31 = U31(1);
    pub const TWO: U31 = U31(2);

    pub const fn from_u32_with_msb(val: u32) -> (Self, bool) {
        let msb = val & MSB_BIT != 0; // If the msb is set
        let val = val & !MSB_BIT; // Get the value without the msb
        let result = Self(val);
        (result, msb)
    }

    pub const fn into_u32(self) -> u32 {
        self.0
    }

    pub const fn from_u32(value: u32) -> Option<Self> {
        if value & MSB_BIT == 0 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn into_encoded_with_msb(self, msb: bool) -> u32 {
        self.0 | (MSB_BIT * msb as u32)
    }

    pub fn plus_one(&self) -> Result<Self, DerivationError> {
        (self.0 + 1).try_into()
    }
}

impl From<U31> for u32 {
    fn from(v: U31) -> Self {
        v.into_u32()
    }
}

impl TryFrom<u32> for U31 {
    type Error = DerivationError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        U31::from_u32(value).ok_or(DerivationError::InvalidChildNumber(value))
    }
}

impl Display for U31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for U31 {
    type Err = DerivationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.parse::<u32>().map_err(|_| DerivationError::InvalidChildNumberFormat)?;
        Self::try_from(value)
    }
}

impl Decode for U31 {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        u32::decode(input).and_then(|v| {
            U31::from_u32(v).ok_or_else(|| serialization::Error::from("Invalid U31 value"))
        })
    }
}
