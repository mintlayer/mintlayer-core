// Copyright (c) 2023 RBB S.r.l
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

use common::{
    chain::{
        htlc::{HashedTimelockContract, HtlcSecretHash},
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            IsTokenFreezable, IsTokenUnfreezable, Metadata, NftIssuance, NftIssuanceV0, TokenId,
            TokenIssuance, TokenIssuanceV1, TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountSpending, DelegationId, Destination, OrderData,
        OrderId, PoolId, TxInput, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, H256},
};
use serialization::extras::non_empty_vec::DataOrNoVec;

use super::VRF_KEYS;

#[allow(dead_code)]
fn update_functions_below_if_new_outputs_were_added(output: TxOutput) {
    // If you're getting a compiler error here, it means that you added a new output type.
    // Please update the functions in this file and include your output type where appropriate
    match output {
        TxOutput::Transfer(_, _) => unimplemented!(),
        TxOutput::LockThenTransfer(_, _, _) => unimplemented!(),
        TxOutput::Burn(_) => unimplemented!(),
        TxOutput::CreateStakePool(_, _) => unimplemented!(),
        TxOutput::ProduceBlockFromStake(_, _) => unimplemented!(),
        TxOutput::CreateDelegationId(_, _) => unimplemented!(),
        TxOutput::DelegateStaking(_, _) => unimplemented!(),
        TxOutput::IssueFungibleToken(_) => unimplemented!(),
        TxOutput::IssueNft(_, _, _) => unimplemented!(),
        TxOutput::DataDeposit(_) => unimplemented!(),
        TxOutput::Htlc(_, _) => unimplemented!(),
        TxOutput::CreateOrder(_) => unimplemented!(),
    }
}

pub fn all_outputs() -> [TxOutput; 12] {
    [
        transfer(),
        htlc(),
        burn(),
        lock_then_transfer(),
        stake_pool(),
        produce_block(),
        create_delegation(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
        data_deposit(),
        create_order(),
    ]
}

pub fn valid_tx_outputs() -> [TxOutput; 11] {
    [
        transfer(),
        htlc(),
        burn(),
        lock_then_transfer(),
        stake_pool(),
        create_delegation(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
        data_deposit(),
        create_order(),
    ]
}

pub fn valid_tx_inputs_utxos() -> [TxOutput; 6] {
    [
        transfer(),
        htlc(),
        lock_then_transfer(),
        stake_pool(),
        produce_block(),
        issue_nft(),
    ]
}

pub fn invalid_tx_inputs_utxos() -> [TxOutput; 6] {
    [
        burn(),
        delegate_staking(),
        create_delegation(),
        issue_tokens(),
        data_deposit(),
        create_order(),
    ]
}

pub fn invalid_block_reward_for_pow() -> [TxOutput; 11] {
    [
        transfer(),
        htlc(),
        burn(),
        stake_pool(),
        produce_block(),
        create_delegation(),
        delegate_staking(),
        issue_nft(),
        issue_tokens(),
        data_deposit(),
        create_order(),
    ]
}

pub fn all_account_inputs() -> [TxInput; 9] {
    [
        TxInput::from_account(
            AccountNonce::new(0),
            AccountSpending::DelegationBalance(DelegationId::new(H256::zero()), Amount::ZERO),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::MintTokens(TokenId::zero(), Amount::ZERO),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::UnmintTokens(TokenId::zero()),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::LockTokenSupply(TokenId::zero()),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::FreezeToken(TokenId::zero(), IsTokenUnfreezable::No),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::UnfreezeToken(TokenId::zero()),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::ChangeTokenAuthority(TokenId::zero(), Destination::AnyoneCanSpend),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::ConcludeOrder(OrderId::zero()),
        ),
        TxInput::from_command(
            AccountNonce::new(0),
            AccountCommand::FillOrder(OrderId::zero(), Amount::ZERO, Destination::AnyoneCanSpend),
        ),
    ]
}

pub fn transfer() -> TxOutput {
    TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)
}

pub fn htlc() -> TxOutput {
    TxOutput::Htlc(
        OutputValue::Coin(Amount::ZERO),
        Box::new(HashedTimelockContract {
            secret_hash: HtlcSecretHash::zero(),
            spend_key: Destination::AnyoneCanSpend,
            refund_timelock: OutputTimeLock::ForSeconds(1),
            refund_key: Destination::AnyoneCanSpend,
        }),
    )
}

pub fn burn() -> TxOutput {
    TxOutput::Burn(OutputValue::Coin(Amount::ZERO))
}

pub fn lock_then_transfer() -> TxOutput {
    TxOutput::LockThenTransfer(
        OutputValue::Coin(Amount::ZERO),
        Destination::AnyoneCanSpend,
        OutputTimeLock::ForBlockCount(1),
    )
}

pub fn stake_pool_id() -> PoolId {
    PoolId::new(H256::zero())
}

pub fn stake_pool() -> TxOutput {
    TxOutput::CreateStakePool(stake_pool_id(), Box::new(stake_pool_data()))
}

pub fn stake_pool_data() -> StakePoolData {
    StakePoolData::new(
        Amount::ZERO,
        Destination::AnyoneCanSpend,
        VRF_KEYS.1.clone(),
        Destination::AnyoneCanSpend,
        PerThousand::new(0).unwrap(),
        Amount::ZERO,
    )
}

pub fn produce_block() -> TxOutput {
    TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, stake_pool_id())
}

pub fn create_delegation() -> TxOutput {
    TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, stake_pool_id())
}

pub fn delegate_staking() -> TxOutput {
    TxOutput::DelegateStaking(Amount::ZERO, DelegationId::new(H256::zero()))
}

pub fn issue_tokens() -> TxOutput {
    TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(TokenIssuanceV1 {
        token_ticker: Vec::new(),
        number_of_decimals: 0,
        metadata_uri: Vec::new(),
        total_supply: TokenTotalSupply::Unlimited,
        authority: Destination::AnyoneCanSpend,
        is_freezable: IsTokenFreezable::No,
    })))
}

pub fn data_deposit() -> TxOutput {
    TxOutput::DataDeposit(vec![])
}

pub fn create_order() -> TxOutput {
    TxOutput::CreateOrder(Box::new(OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::Coin(Amount::ZERO),
        OutputValue::Coin(Amount::ZERO),
    )))
}

pub fn issue_nft() -> TxOutput {
    TxOutput::IssueNft(
        TokenId::new(H256::zero()),
        Box::new(NftIssuance::V0(NftIssuanceV0 {
            metadata: Metadata {
                creator: None,
                name: Vec::new(),
                description: Vec::new(),
                ticker: Vec::new(),
                icon_uri: DataOrNoVec::from(None),
                additional_metadata_uri: DataOrNoVec::from(None),
                media_uri: DataOrNoVec::from(None),
                media_hash: Vec::new(),
            },
        })),
        Destination::AnyoneCanSpend,
    )
}

pub fn is_stake_pool(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..)
        | TxOutput::IssueFungibleToken(..)
        | TxOutput::IssueNft(..)
        | TxOutput::DataDeposit(..)
        | TxOutput::Htlc(..)
        | TxOutput::CreateOrder(..) => false,
        TxOutput::CreateStakePool(..) => true,
    }
}

pub fn is_produce_block(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::CreateStakePool(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..)
        | TxOutput::IssueFungibleToken(..)
        | TxOutput::IssueNft(..)
        | TxOutput::DataDeposit(..)
        | TxOutput::Htlc(..)
        | TxOutput::CreateOrder(..) => false,
        TxOutput::ProduceBlockFromStake(..) => true,
    }
}
