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

use super::{TokenData, TokenId, TokenIssuance};
use crate::{
    chain::{
        output_value::OutputValue, AccountSpending, TokenOutput, Transaction, TxInput, TxOutput,
    },
    primitives::id::hash_encoded,
};

pub fn token_id(tx: &Transaction) -> Option<TokenId> {
    Some(TokenId::new(hash_encoded(tx.inputs().get(0)?)))
}

pub fn get_tokens_issuance_versioned(outputs: &[TxOutput]) -> Vec<&TokenIssuance> {
    outputs
        .iter()
        .filter_map(|output| match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => None,
            TxOutput::Tokens(v) => match v {
                TokenOutput::IssueFungibleToken(v) => Some(v.as_ref()),
                TokenOutput::MintTokens(_, _, _)
                | TokenOutput::RedeemTokens(_, _)
                | TokenOutput::LockCirculatingSupply(_) => None,
            },
        })
        .collect()
}

pub fn get_tokens_issuance_count(outputs: &[TxOutput]) -> usize {
    outputs.iter().filter(|&output| is_token_or_nft_issuance(output)).count()
}

pub fn get_tokens_issuance_v0_count(outputs: &[TxOutput]) -> usize {
    outputs
        .iter()
        .filter(|&output| match output {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                match v {
                    OutputValue::TokenV0(data) => match data.as_ref() {
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => true,
                        TokenData::TokenTransfer(_) => false,
                    },
                    OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
                }
            }
            TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::Tokens(_) => false,
        })
        .count()
}

pub fn get_token_supply_change_count(inputs: &[TxInput]) -> usize {
    inputs
        .iter()
        .filter(|&input| match input {
            TxInput::Utxo(_) => false,
            TxInput::Account(account) => match account.account() {
                AccountSpending::Delegation(_, _) => false,
                AccountSpending::TokenSupply(_, _) => true,
            },
        })
        .count()
}

pub fn is_token_or_nft_issuance(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
            match v {
                OutputValue::TokenV0(data) => match data.as_ref() {
                    TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => true,
                    TokenData::TokenTransfer(_) => false,
                },
                OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
            }
        }
        TxOutput::Tokens(v) => match v {
            TokenOutput::IssueFungibleToken(_) => true,
            TokenOutput::MintTokens(_, _, _)
            | TokenOutput::RedeemTokens(_, _)
            | TokenOutput::LockCirculatingSupply(_) => false,
        },
        TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _) => false,
    }
}
