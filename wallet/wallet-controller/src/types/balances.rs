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

use common::{chain::tokens::TokenId, primitives::DecimalAmount};

/// Balances of coins and tokens
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, rpc_description::HasValueHint)]
pub struct Balances {
    coins: DecimalAmount,
    tokens: BTreeMap<TokenId, DecimalAmount>,
}

impl Balances {
    pub fn new(coins: DecimalAmount, tokens: BTreeMap<TokenId, DecimalAmount>) -> Self {
        Self { coins, tokens }
    }

    pub fn coins(&self) -> DecimalAmount {
        self.coins
    }

    pub fn tokens(&self) -> &BTreeMap<TokenId, DecimalAmount> {
        &self.tokens
    }

    pub fn token(&self, token_id: &TokenId) -> DecimalAmount {
        self.tokens.get(token_id).copied().unwrap_or(DecimalAmount::ZERO)
    }

    pub fn into_coins_and_tokens(self) -> (DecimalAmount, BTreeMap<TokenId, DecimalAmount>) {
        let Self { coins, tokens } = self;
        (coins, tokens)
    }
}
