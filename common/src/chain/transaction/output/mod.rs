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
    chain::{tokens::OutputValue, PoolId},
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
    StakePool(Box<StakePoolData>),
    /// Output type that represents spending of a stake pool output in a block reward
    /// in order to produce a block
    #[codec(index = 4)]
    ProduceBlockFromStake(Amount, Destination, PoolId),
}

impl TxOutput {
    // TODO: this has to go
    pub fn destination(&self) -> Option<&Destination> {
        match self {
            TxOutput::Transfer(_, d) => Some(d),
            TxOutput::LockThenTransfer(_, d, _) => Some(d),
            TxOutput::Burn(_) => None,
            TxOutput::StakePool(d) => Some(d.staker()),
            TxOutput::ProduceBlockFromStake(_, d, _) => Some(d),
        }
    }

    pub fn is_burn(&self) -> bool {
        match self {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::StakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _, _) => false,
            TxOutput::Burn(_) => true,
        }
    }
}

impl TxOutput {
    pub fn value(&self) -> OutputValue {
        match self {
            TxOutput::Transfer(v, _) => v.clone(),
            TxOutput::LockThenTransfer(v, _, _) => v.clone(),
            TxOutput::Burn(v) => v.clone(),
            TxOutput::StakePool(d) => OutputValue::Coin(d.value()),
            TxOutput::ProduceBlockFromStake(v, _, _) => OutputValue::Coin(*v),
        }
    }

    pub fn has_timelock(&self) -> bool {
        match self {
            TxOutput::Transfer(_, _)
            | TxOutput::Burn(_)
            | TxOutput::StakePool(_)
            | TxOutput::ProduceBlockFromStake(_, _, _) => false,
            TxOutput::LockThenTransfer(_, _, _) => true,
        }
    }
}
