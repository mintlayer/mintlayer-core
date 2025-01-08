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

use serialization::{Decode, Encode};

use crate::{
    chain::tokens::{NftIssuanceV0, TokenData, TokenId, TokenIssuanceV0, TokenTransfer},
    primitives::Amount,
};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum OutputValue {
    #[codec(index = 0)]
    Coin(Amount),
    #[codec(index = 1)]
    TokenV0(Box<TokenData>),
    #[codec(index = 2)]
    TokenV1(TokenId, Amount),
}

impl OutputValue {
    pub fn coin_amount(&self) -> Option<Amount> {
        match self {
            OutputValue::Coin(v) => Some(*v),
            OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => None,
        }
    }
}

impl From<TokenData> for OutputValue {
    fn from(d: TokenData) -> Self {
        Self::TokenV0(Box::new(d))
    }
}

impl From<TokenTransfer> for OutputValue {
    fn from(d: TokenTransfer) -> Self {
        TokenData::TokenTransfer(d).into()
    }
}

impl From<NftIssuanceV0> for OutputValue {
    fn from(d: NftIssuanceV0) -> Self {
        TokenData::NftIssuance(Box::new(d)).into()
    }
}

impl From<TokenIssuanceV0> for OutputValue {
    fn from(d: TokenIssuanceV0) -> Self {
        TokenData::TokenIssuance(Box::new(d)).into()
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum RpcOutputValue {
    Coin { amount: Amount },
    Token { id: TokenId, amount: Amount },
}

impl RpcOutputValue {
    pub fn from_output_value(value: &OutputValue) -> Option<Self> {
        match value {
            OutputValue::Coin(amount) => Some(RpcOutputValue::Coin { amount: *amount }),
            OutputValue::TokenV0(_) => None,
            OutputValue::TokenV1(id, amount) => Some(RpcOutputValue::Token {
                id: *id,
                amount: *amount,
            }),
        }
    }
    pub fn amount(&self) -> Amount {
        match self {
            RpcOutputValue::Coin { amount } | RpcOutputValue::Token { id: _, amount } => *amount,
        }
    }

    pub fn token_id(&self) -> Option<TokenId> {
        match self {
            RpcOutputValue::Coin { amount: _ } => None,
            RpcOutputValue::Token { id, amount: _ } => Some(*id),
        }
    }
}

impl From<RpcOutputValue> for OutputValue {
    fn from(value: RpcOutputValue) -> Self {
        match value {
            RpcOutputValue::Coin { amount } => OutputValue::Coin(amount),
            RpcOutputValue::Token { id, amount } => OutputValue::TokenV1(id, amount),
        }
    }
}
