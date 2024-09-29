// Copyright (c) 2024 RBB S.r.l
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

use rpc_description::HasValueHint;

use crate::{
    chain::{output_value::OutputValue, tokens::TokenId, AccountNonce, Destination},
    primitives::Amount,
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
#[serde(tag = "type", content = "content")]
pub enum RpcOrderValue {
    Coin { amount: Amount },
    Token { id: TokenId, amount: Amount },
}

impl RpcOrderValue {
    pub fn from_output_value(value: &OutputValue) -> Option<Self> {
        match value {
            OutputValue::Coin(amount) => Some(RpcOrderValue::Coin { amount: *amount }),
            OutputValue::TokenV0(_) => None,
            OutputValue::TokenV1(id, amount) => Some(RpcOrderValue::Token {
                id: *id,
                amount: *amount,
            }),
        }
    }

    pub fn amount(&self) -> Amount {
        match self {
            RpcOrderValue::Coin { amount } | RpcOrderValue::Token { id: _, amount } => *amount,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, HasValueHint)]
pub struct RpcOrderInfo {
    pub conclude_key: Destination,

    pub initially_asked: RpcOrderValue,
    pub initially_given: RpcOrderValue,

    // left to offer
    pub give_balance: Amount,
    // how much more is expected to get in return
    pub ask_balance: Amount,

    pub nonce: Option<AccountNonce>,
}
