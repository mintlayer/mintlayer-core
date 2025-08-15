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

use super::Destination;
use crate::primitives::Amount;
use serialization::{Decode, Encode};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
    strum::EnumDiscriminants,
)]
#[strum_discriminants(name(TokenTotalSupplyTag), derive(strum::EnumIter))]
pub enum TokenTotalSupply {
    #[codec(index = 0)]
    Fixed(Amount), // fixed to a certain amount
    #[codec(index = 1)]
    Lockable, // not known in advance but can be locked once at some point in time
    #[codec(index = 2)]
    Unlimited, // limited only by the Amount data type
}

/// Indicates whether a token can be frozen
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum IsTokenFreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

impl IsTokenFreezable {
    pub fn as_bool(&self) -> bool {
        match self {
            Self::No => false,
            Self::Yes => true,
        }
    }
}

/// Indicates whether a token can be unfrozen after being frozen
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum IsTokenUnfreezable {
    #[codec(index = 0)]
    No,
    #[codec(index = 1)]
    Yes,
}

impl IsTokenUnfreezable {
    pub fn as_bool(&self) -> bool {
        match self {
            Self::No => false,
            Self::Yes => true,
        }
    }
}

/// Indicates whether a token is frozen at the moment or not. If it is then no operations with this token can be performed.
/// Meaning transfers, burns, minting, unminting, supply locks etc. Frozen token can only be unfrozen
/// if such an option was provided while freezing.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum IsTokenFrozen {
    #[codec(index = 0)]
    No(IsTokenFreezable),
    #[codec(index = 1)]
    Yes(IsTokenUnfreezable),
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum TokenIssuance {
    #[codec(index = 1)]
    V1(TokenIssuanceV1),
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TokenIssuanceV1 {
    pub token_ticker: Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
    pub total_supply: TokenTotalSupply,
    pub authority: Destination,
    pub is_freezable: IsTokenFreezable,
}
