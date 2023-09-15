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
    address::{pubkeyhash::PublicKeyHash, traits::Addressable, AddressError},
    chain::{
        output_value::OutputValue, tokens::TokenIssuanceVersioned, ChainConfig, DelegationId,
        PoolId,
    },
    primitives::{Amount, Id},
};
use script::Script;
use serialization::{hex::HexEncode, Decode, DecodeAll, Encode};

use self::{stakelock::StakePoolData, timelock::OutputTimeLock};

pub mod classic_multisig;
pub mod output_value;
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

impl serde::Serialize for Destination {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", self.hex_encode()))
    }
}

impl Addressable for Destination {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.destination_address_prefix(self)
    }

    fn encode_to_bytes_for_address(&self) -> Vec<u8> {
        self.encode()
    }

    fn decode_from_bytes_from_address<T: AsRef<[u8]>>(address_bytes: T) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::decode_all(&mut address_bytes.as_ref())
            .map_err(|e| AddressError::DecodingError(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, serde::Serialize)]
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
    #[codec(index = 7)]
    TokenIssuance(Box<TokenIssuanceVersioned>),
    // FIXME: add NftIssuance at once?
}

impl TxOutput {
    pub fn timelock(&self) -> Option<&OutputTimeLock> {
        match self {
            TxOutput::Transfer(_, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::TokenIssuance(_) => None,
            TxOutput::LockThenTransfer(_, _, tl) => Some(tl),
        }
    }
}
