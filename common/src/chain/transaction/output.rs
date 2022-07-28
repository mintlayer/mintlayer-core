// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{address::pubkeyhash::PublicKeyHash, chain::tokens::OutputValue, primitives::Id};
use script::Script;
use serialization::{Decode, Encode};

use self::timelock::OutputTimeLock;

pub mod timelock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    #[codec(index = 0)]
    Address(PublicKeyHash), // Address type to be added
    #[codec(index = 1)]
    PublicKey(crypto::key::PublicKey), // Key type to be added
    #[codec(index = 2)]
    ScriptHash(Id<Script>),
    #[codec(index = 3)]
    AnyoneCanSpend, // zero verification; used primarily for testing. Never use this for real money
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum OutputPurpose {
    #[codec(index = 0)]
    Transfer(Destination),
    #[codec(index = 1)]
    LockThenTransfer(Destination, OutputTimeLock),
    #[codec(index = 2)]
    StakeLock(Destination),
}

impl OutputPurpose {
    pub fn destination(&self) -> &Destination {
        match self {
            OutputPurpose::Transfer(d) => d,
            OutputPurpose::LockThenTransfer(d, _) => d,
            OutputPurpose::StakeLock(d) => d,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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
}
