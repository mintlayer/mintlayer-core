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
use crate::{
    chain::{Transaction, TxOutput},
    primitives::id::hash_encoded,
};

pub fn token_id(tx: &Transaction) -> Option<TokenId> {
    Some(hash_encoded(tx.inputs().get(0)?))
}

pub fn is_tokens_issuance(output_value: &OutputValue) -> bool {
    match output_value {
        OutputValue::Coin(_) => false,
        OutputValue::Token(token_data) => match token_data {
            TokenData::TokenTransferV1 {
                token_id: _,
                amount: _,
            } => false,
            TokenData::TokenIssuanceV1 {
                token_ticker: _,
                amount_to_issue: _,
                number_of_decimals: _,
                metadata_uri: _,
            } => true,
            TokenData::TokenBurnV1 {
                token_id: _,
                amount_to_burn: _,
            } => false,
        },
    }
}

pub fn get_tokens_issuance_count(outputs: &[TxOutput]) -> usize {
    outputs.iter().filter(|&output| is_tokens_issuance(output.value())).count()
}
