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

use super::{OutputValue, TokenData, TokenId};
use crate::{chain::Transaction, primitives::id::hash_encoded};

pub fn token_id(tx: &Transaction) -> Option<TokenId> {
    Some(hash_encoded(tx.inputs().get(0)?))
}

pub fn get_tokens_issuance_count(tx: &Transaction) -> usize {
    tx.outputs()
        .iter()
        .filter_map(|output| match output.value() {
            OutputValue::Coin(_) => None,
            OutputValue::Token(asset) => Some(asset),
        })
        .fold(0, |accum, asset| match asset {
            TokenData::TokenTransferV1 {
                token_id: _,
                amount: _,
            } => accum,
            TokenData::TokenIssuanceV1 {
                token_ticker: _,
                amount_to_issue: _,
                number_of_decimals: _,
                metadata_uri: _,
            } => accum + 1,
            TokenData::TokenBurnV1 {
                token_id: _,
                amount_to_burn: _,
            } => accum,
        })
}
