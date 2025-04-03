// Copyright (c) 2021-2022 RBB S.r.l
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

pub mod amount;
pub mod bech32_encoding;
pub mod compact;
pub mod error;
pub mod height;
pub mod id;
pub mod per_thousand;
pub mod rational;
pub mod semver;
pub mod time;
pub mod user_agent;
pub mod version_tag;

mod hash_encoded;

pub use amount::{Amount, DecimalAmount, DisplayAmount};
pub use bech32_encoding::Bech32Error;
pub use compact::Compact;
pub use height::{BlockCount, BlockDistance, BlockHeight};
pub use id::{Id, Idable, H256};
pub use version_tag::VersionTag;

use crate::chain::{output_value::OutputValue, tokens::TokenId};
use serialization::{Decode, Encode};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fee(pub Amount);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subsidy(pub Amount);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub enum CoinOrTokenId {
    Coin,
    TokenId(TokenId),
}

impl CoinOrTokenId {
    pub fn from_output_value(value: &OutputValue) -> Option<Self> {
        match value {
            OutputValue::Coin(_) => Some(Self::Coin),
            OutputValue::TokenV0(_) => None,
            OutputValue::TokenV1(id, _) => Some(Self::TokenId(*id)),
        }
    }

    pub fn to_output_value(&self, amount: Amount) -> OutputValue {
        match self {
            CoinOrTokenId::Coin => OutputValue::Coin(amount),
            CoinOrTokenId::TokenId(id) => OutputValue::TokenV1(*id, amount),
        }
    }

    pub fn token_id(&self) -> Option<TokenId> {
        match self {
            CoinOrTokenId::Coin => None,
            CoinOrTokenId::TokenId(id) => Some(*id),
        }
    }
}
