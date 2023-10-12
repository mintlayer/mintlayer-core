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

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize)]
pub enum OutputValue {
    Coin(Amount),
    TokenV0(Box<TokenData>),
    TokenV1(TokenId, Amount),
}

impl OutputValue {
    pub fn coin_amount(&self) -> Option<Amount> {
        match self {
            OutputValue::Coin(v) => Some(*v),
            OutputValue::TokenV0(_) | OutputValue::TokenV1(_, _) => None,
        }
    }

    pub fn token_data(&self) -> Option<&TokenData> {
        match self {
            OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => None,
            OutputValue::TokenV0(d) => Some(d),
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
