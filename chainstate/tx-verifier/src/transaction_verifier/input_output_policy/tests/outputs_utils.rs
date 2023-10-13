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
        output_value::OutputValue,
        stakelock::StakePoolData,
        timelock::OutputTimeLock,
        tokens::{
            Metadata, NftIssuance, NftIssuanceV0, TokenId, TokenIssuance, TokenIssuanceV1,
            TokenTotalSupply,
        },
        DelegationId, Destination, PoolId, TokenOutput, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount, H256},
};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
use serialization::extras::non_empty_vec::DataOrNoVec;

#[allow(dead_code)]
fn update_functions_below_if_new_outputs_were_added(output: TxOutput) {
    match output {
        TxOutput::Transfer(_, _) => unimplemented!(),
        TxOutput::LockThenTransfer(_, _, _) => unimplemented!(),
        TxOutput::Burn(_) => unimplemented!(),
        TxOutput::CreateStakePool(_, _) => unimplemented!(),
        TxOutput::ProduceBlockFromStake(_, _) => unimplemented!(),
        TxOutput::CreateDelegationId(_, _) => unimplemented!(),
        TxOutput::DelegateStaking(_, _) => unimplemented!(),
        TxOutput::TokensOp(token) => match token {
            TokenOutput::IssueFungibleToken(_) => unimplemented!(),
            TokenOutput::IssueNft(_, _, _) => unimplemented!(),
        },
    }
}

pub fn all_outputs() -> [TxOutput; 9] {
    [
        transfer(),
        burn(),
        lock_then_transfer(),
        stake_pool(),
        produce_block(),
        create_delegation(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
    ]
}

pub fn valid_tx_outputs() -> [TxOutput; 8] {
    [
        transfer(),
        burn(),
        lock_then_transfer(),
        stake_pool(),
        create_delegation(),
        delegate_staking(),
        issue_tokens(),
        issue_nft(),
    ]
}

pub fn valid_tx_inputs() -> [TxOutput; 5] {
    [transfer(), lock_then_transfer(), stake_pool(), produce_block(), issue_nft()]
}

pub fn transfer() -> TxOutput {
    TxOutput::Transfer(OutputValue::Coin(Amount::ZERO), Destination::AnyoneCanSpend)
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

pub fn stake_pool() -> TxOutput {
    let (_, vrf_pub_key) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
    TxOutput::CreateStakePool(
        PoolId::new(H256::zero()),
        Box::new(StakePoolData::new(
            Amount::ZERO,
            Destination::AnyoneCanSpend,
            vrf_pub_key,
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        )),
    )
}

pub fn produce_block() -> TxOutput {
    TxOutput::ProduceBlockFromStake(Destination::AnyoneCanSpend, PoolId::new(H256::zero()))
}

pub fn create_delegation() -> TxOutput {
    TxOutput::CreateDelegationId(Destination::AnyoneCanSpend, PoolId::new(H256::zero()))
}

pub fn delegate_staking() -> TxOutput {
    TxOutput::DelegateStaking(Amount::ZERO, DelegationId::new(H256::zero()))
}

pub fn issue_tokens() -> TxOutput {
    TxOutput::TokensOp(TokenOutput::IssueFungibleToken(Box::new(
        TokenIssuance::V1(TokenIssuanceV1 {
            token_ticker: Vec::new(),
            number_of_decimals: 0,
            metadata_uri: Vec::new(),
            total_supply: TokenTotalSupply::Unlimited,
            reissuance_controller: Destination::AnyoneCanSpend,
        }),
    )))
}

pub fn issue_nft() -> TxOutput {
    TxOutput::TokensOp(TokenOutput::IssueNft(
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
    ))
}

pub fn is_stake_pool(output: &TxOutput) -> bool {
    match output {
        TxOutput::Transfer(..)
        | TxOutput::LockThenTransfer(..)
        | TxOutput::Burn(..)
        | TxOutput::ProduceBlockFromStake(..)
        | TxOutput::CreateDelegationId(..)
        | TxOutput::DelegateStaking(..)
        | TxOutput::TokensOp(..) => false,
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
        | TxOutput::TokensOp(..) => false,
        TxOutput::ProduceBlockFromStake(..) => true,
    }
}
