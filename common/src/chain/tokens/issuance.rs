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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct TokenIssuanceVersion(u32);

impl TokenIssuanceVersion {
    /// Initial issuance implementation
    pub const V0: Self = Self(0);
    /// Add reissuance support
    pub const V1: Self = Self(1);

    // FIXME: get rid of CURRENT
    pub const CURRENT: Self = Self::V1;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, serde::Serialize)]
pub enum TokenTotalSupply {
    Fixed(Amount), // fixed to a certain amount
    Lockable,      // not known in advance but can be locked at some point in time
    Unlimited,     // limited only by the Amount data type
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, serde::Serialize)]
pub enum TokenIssuanceVersioned {
    V1(TokenIssuanceV1),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, serde::Serialize)]
pub struct TokenIssuanceV1 {
    pub token_ticker: Vec<u8>,
    pub number_of_decimals: u8,
    pub metadata_uri: Vec<u8>,
    pub supply_limit: TokenTotalSupply,
    pub reissuance_controller: Destination,
}
