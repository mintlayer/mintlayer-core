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

use std::collections::BTreeMap;

use common::{address::RpcAddress, chain::tokens::TokenId, primitives::amount::RpcAmountOut};

/// Balances of coins and tokens
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct Balances {
    coins: RpcAmountOut,
    tokens: BTreeMap<RpcAddress<TokenId>, RpcAmountOut>,
}

impl Balances {
    pub fn new(coins: RpcAmountOut, tokens: BTreeMap<RpcAddress<TokenId>, RpcAmountOut>) -> Self {
        Self { coins, tokens }
    }

    pub fn coins(&self) -> &RpcAmountOut {
        &self.coins
    }

    pub fn tokens(&self) -> &BTreeMap<RpcAddress<TokenId>, RpcAmountOut> {
        &self.tokens
    }

    pub fn into_coins_and_tokens(
        self,
    ) -> (RpcAmountOut, BTreeMap<RpcAddress<TokenId>, RpcAmountOut>) {
        let Self { coins, tokens } = self;
        (coins, tokens)
    }
}
