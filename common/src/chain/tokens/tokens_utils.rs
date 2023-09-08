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

use super::{TokenData, TokenId, TokenIssuanceV1};
use crate::{
    chain::{output_value::OutputValue, Transaction, TxInput, TxOutput},
    primitives::id::hash_encoded,
};

pub fn token_id(tx: &Transaction) -> Option<TokenId> {
    Some(TokenId::new(hash_encoded(tx.inputs().get(0)?)))
}

pub fn get_tokens_issuance_v1(outputs: &[TxOutput]) -> Vec<&TokenIssuanceV1> {
    outputs
        .iter()
        .filter_map(|output| match output {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                match v {
                    OutputValue::Token(data) => match data.as_ref() {
                        TokenData::TokenIssuance(_)
                        | TokenData::NftIssuance(_)
                        | TokenData::TokenTransfer(_) => None,
                        TokenData::TokenIssuanceV1(issuance) => Some(issuance.as_ref()),
                    },
                    OutputValue::Coin(_) => None,
                }
            }
            TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => None,
        })
        .collect()
}

pub fn get_tokens_issuance_count(outputs: &[TxOutput]) -> usize {
    outputs.iter().filter(|&output| is_token_or_nft_issuance(output)).count()
}

pub fn get_tokens_reissuance_count(outputs: &[TxInput]) -> usize {
    outputs.iter().filter(|&input| is_token_reissuance(input)).count()
}

pub fn is_token_or_nft_issuance(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
            match v {
                OutputValue::Token(data) => match data.as_ref() {
                    TokenData::TokenIssuance(_)
                    | TokenData::NftIssuance(_)
                    | TokenData::TokenIssuanceV1(_) => true,
                    TokenData::TokenTransfer(_) => false,
                },
                OutputValue::Coin(_) => false,
            }
        }
        TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _) => false,
    }
}

pub fn is_token_reissuance(input: &TxInput) -> bool {
    match input {
        TxInput::Utxo(_) => false,
        TxInput::Account(account) => match account.account() {
            crate::chain::AccountSpending::Delegation(_, _) => false,
            crate::chain::AccountSpending::Token(_, _) => true,
        },
    }
}
