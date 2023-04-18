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
        OutputValue::Token(token_data) => match **token_data {
            TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => true,
            TokenData::TokenTransfer(_) => false,
        },
    }
}

pub fn get_tokens_issuance_count(outputs: &[TxOutput]) -> usize {
    outputs
        .iter()
        .filter(|&output| match output {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                is_tokens_issuance(v)
            }
            TxOutput::CreateStakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::DecommissionPool(_, _, _, _)
            | TxOutput::DelegateStaking(_, _, _)
            | TxOutput::SpendShareFromDelegation(_, _, _) => false,
        })
        .count()
}
