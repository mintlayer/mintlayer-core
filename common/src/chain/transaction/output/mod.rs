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

use crate::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        tokens::{OutputValue, TokenData},
        DelegationId, PoolId,
    },
    primitives::{Amount, Id},
};
use script::Script;
use serialization::{Decode, Encode};

use self::{stakelock::StakePoolData, timelock::OutputTimeLock};

pub mod classic_multisig;
pub mod stakelock;
pub mod timelock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    #[codec(index = 0)]
    AnyoneCanSpend, // zero verification; used primarily for testing. Never use this for real money
    #[codec(index = 1)]
    Address(PublicKeyHash),
    #[codec(index = 2)]
    PublicKey(crypto::key::PublicKey),
    #[codec(index = 3)]
    ScriptHash(Id<Script>),
    #[codec(index = 4)]
    ClassicMultisig(PublicKeyHash),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum TxOutput {
    #[codec(index = 0)]
    Transfer(OutputValue, Destination),
    #[codec(index = 1)]
    LockThenTransfer(OutputValue, Destination, OutputTimeLock),
    #[codec(index = 2)]
    Burn(OutputValue),
    /// Output type that is used to create a stake pool
    #[codec(index = 3)]
    CreateStakePool(PoolId, Box<StakePoolData>),
    /// Output type that represents spending of a stake pool output in a block reward
    /// in order to produce a block
    #[codec(index = 4)]
    ProduceBlockFromStake(Destination, PoolId),
    #[codec(index = 5)]
    CreateDelegationId(Destination, PoolId),
    #[codec(index = 6)]
    DelegateStaking(Amount, DelegationId),
}

impl TxOutput {
    pub fn timelock(&self) -> Option<&OutputTimeLock> {
        match self {
            TxOutput::Transfer(_, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _) => None,
            TxOutput::LockThenTransfer(_, _, tl) => Some(tl),
        }
    }

    pub fn is_token_or_nft_issuence(&self) -> bool {
        match self {
            TxOutput::Transfer(v, _) | TxOutput::LockThenTransfer(v, _, _) | TxOutput::Burn(v) => {
                match v {
                    OutputValue::Token(data) => match data.as_ref() {
                        TokenData::TokenIssuance(_) | TokenData::NftIssuance(_) => true,
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
}
