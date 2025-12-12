// Copyright (c) 2021-2025 RBB S.r.l
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

use crate::{
    chain::{
        output_value::{OutputValue, RpcOutputValue},
        tokens::TokenId,
    },
    primitives::Amount,
};

#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Copy,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum RpcCurrency {
    Coin,
    Token(TokenId),
}

impl RpcCurrency {
    pub fn from_output_value(output_value: &OutputValue) -> Option<Self> {
        match output_value {
            OutputValue::Coin(_) => Some(Self::Coin),
            OutputValue::TokenV0(_) => None,
            OutputValue::TokenV1(id, _) => Some(Self::Token(*id)),
        }
    }

    pub fn from_rpc_output_value(output_value: &RpcOutputValue) -> Self {
        match output_value {
            RpcOutputValue::Coin { .. } => Self::Coin,
            RpcOutputValue::Token { id, .. } => Self::Token(*id),
        }
    }

    pub fn into_output_value(&self, amount: Amount) -> OutputValue {
        match self {
            Self::Coin => OutputValue::Coin(amount),
            Self::Token(id) => OutputValue::TokenV1(*id, amount),
        }
    }
}
