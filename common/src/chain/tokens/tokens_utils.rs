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

use smallvec::SmallVec;

use super::{TokenData, TokenId};
use crate::chain::{output_value::OutputValue, AccountCommand, TxInput, TxOutput};

pub fn get_tokens_issuance_count(outputs: &[TxOutput]) -> usize {
    outputs.iter().filter(|&output| is_token_or_nft_issuance(output)).count()
}

pub fn get_issuance_count_via_tokens_op(outputs: &[TxOutput]) -> usize {
    outputs
        .iter()
        .filter(|&output| match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => false,
            TxOutput::IssueFungibleToken(_) | TxOutput::IssueNft(_, _, _) => true,
        })
        .count()
}

pub fn get_token_supply_change_count(inputs: &[TxInput]) -> usize {
    inputs
        .iter()
        .filter(|&input| match input {
            TxInput::Utxo(_) | TxInput::Account(_) | TxInput::OrderAccountCommand(_) => false,
            TxInput::AccountCommand(_, op) => match op {
                AccountCommand::FreezeToken(_, _)
                | AccountCommand::UnfreezeToken(_)
                | AccountCommand::ChangeTokenAuthority(_, _)
                | AccountCommand::ChangeTokenMetadataUri(_, _)
                | AccountCommand::ConcludeOrder(_)
                | AccountCommand::FillOrder(_, _, _) => false,
                AccountCommand::MintTokens(_, _)
                | AccountCommand::UnmintTokens(_)
                | AccountCommand::LockTokenSupply(_) => true,
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
        TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::Htlc(_, _)
        | TxOutput::CreateOrder(_) => false,
        TxOutput::IssueFungibleToken(_) | TxOutput::IssueNft(_, _, _) => true,
    }
}

/// Get any non-V0 token referenced by this output, ignoring `IssueFungibleToken`.
pub fn get_referenced_token_ids_ignore_issuance(output: &TxOutput) -> SmallVec<[TokenId; 2]> {
    match output {
        TxOutput::Transfer(v, _)
        | TxOutput::LockThenTransfer(v, _, _)
        | TxOutput::Burn(v)
        | TxOutput::Htlc(v, _) => SmallVec::from_iter(token_id_from_output_value(v)),
        | TxOutput::CreateOrder(data) => {
            // Note: order's ask and give currencies are always different.
            SmallVec::from_iter(
                [token_id_from_output_value(data.ask()), token_id_from_output_value(data.give())]
                    .into_iter()
                    .flatten(),
            )
        }
        TxOutput::CreateStakePool(_, _)
        | TxOutput::ProduceBlockFromStake(_, _)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::IssueFungibleToken(_) => SmallVec::new(),
        TxOutput::IssueNft(token_id, _, _) => SmallVec::from_iter([*token_id]),
    }
}

fn token_id_from_output_value(v: &OutputValue) -> Option<TokenId> {
    match v {
        OutputValue::Coin(_) | OutputValue::TokenV0(_) => None,
        OutputValue::TokenV1(token_id, _) => Some(*token_id),
    }
}
