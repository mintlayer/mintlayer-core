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

use crate::{address::pubkeyhash::PublicKeyHash, chain::tokens::OutputValue, primitives::Id};
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum OutputPurpose {
    #[codec(index = 0)]
    Transfer(Destination),
    #[codec(index = 1)]
    LockThenTransfer(Destination, OutputTimeLock),
    #[codec(index = 2)]
    Burn,
    /// Output type that is used to create a stake pool
    #[codec(index = 3)]
    StakePool(Box<StakePoolData>),
    /// Output type that represents a spending of a stake pool output in order to produce a block
    #[codec(index = 4)]
    StakedOutput(Box<StakePoolData>, OutputTimeLock),
}

impl OutputPurpose {
    pub fn destination(&self) -> Option<&Destination> {
        match self {
            OutputPurpose::Transfer(d) => Some(d),
            OutputPurpose::LockThenTransfer(d, _) => Some(d),
            OutputPurpose::Burn => None,
            OutputPurpose::StakePool(d) => Some(d.staker()),
            OutputPurpose::StakedOutput(d, _) => Some(d.staker()),
        }
    }

    pub fn is_burn(&self) -> bool {
        match self {
            OutputPurpose::Transfer(_)
            | OutputPurpose::LockThenTransfer(_, _)
            | OutputPurpose::StakePool(_)
            | OutputPurpose::StakedOutput(_, _) => false,
            OutputPurpose::Burn => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TxOutput {
    value: OutputValue,
    purpose: OutputPurpose,
}

impl TxOutput {
    pub fn new(value: OutputValue, purpose: OutputPurpose) -> Self {
        TxOutput { value, purpose }
    }

    pub fn value(&self) -> &OutputValue {
        &self.value
    }

    pub fn purpose(&self) -> &OutputPurpose {
        &self.purpose
    }

    pub fn has_timelock(&self) -> bool {
        match &self.purpose {
            OutputPurpose::Transfer(_) | OutputPurpose::Burn | OutputPurpose::StakePool(_) => false,
            OutputPurpose::LockThenTransfer(_, _) | OutputPurpose::StakedOutput(_, _) => true,
        }
    }
}
