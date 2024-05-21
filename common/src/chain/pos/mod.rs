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

use std::str::FromStr;

use serialization::{Decode, DecodeAll, Encode};
use typename::TypeName;

use crate::{
    address::{hexified::HexifiedAddress, traits::Addressable, AddressError},
    primitives::{BlockCount, Id, H256},
    Uint256,
};

use super::{block::timestamp::BlockTimestamp, chaintrust, config::ChainType, ChainConfig};

pub mod config;
pub mod config_builder;

pub const DEFAULT_BLOCK_COUNT_TO_AVERAGE: usize = 100;
pub const DEFAULT_MATURITY_BLOCK_COUNT_V0: BlockCount = BlockCount::new(2000);
pub const DEFAULT_MATURITY_BLOCK_COUNT_V1: BlockCount = BlockCount::new(7200);

#[derive(Eq, PartialEq, TypeName)]
pub enum Pool {}
pub type PoolId = Id<Pool>;

#[derive(Eq, PartialEq, TypeName)]
pub enum Delegation {}
pub type DelegationId = Id<Delegation>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub struct PoSConsensusVersion(u32);

impl PoSConsensusVersion {
    /// Initial PoS implementation
    pub const V0: Self = Self(0);
    /// Incentivize pledging and prevent centralization with capped probability
    pub const V1: Self = Self(1);
}

impl serde::Serialize for PoolId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HexifiedAddress::serde_serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PoolId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HexifiedAddress::<Self>::serde_deserialize(deserializer)
    }
}

impl Addressable for PoolId {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.pool_id_address_prefix()
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

    fn json_wrapper_prefix() -> &'static str {
        "HexifiedPoolId"
    }
}

impl Addressable for DelegationId {
    type Error = AddressError;

    fn address_prefix(&self, chain_config: &ChainConfig) -> &str {
        chain_config.delegation_id_address_prefix()
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
    fn json_wrapper_prefix() -> &'static str {
        "HexifiedDelegationId"
    }
}

impl serde::Serialize for DelegationId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HexifiedAddress::serde_serialize(self, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DelegationId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HexifiedAddress::<Self>::serde_deserialize(deserializer)
    }
}

pub fn pos_initial_difficulty(chain_type: ChainType) -> Uint256 {
    match chain_type {
        // Note: Assuming that there is 1 initial staking pool in testnet the value for difficulty equals to
        // U256::MAX / min_stake_pool_pledge / block_time, dropping the least significant bytes for simplicity
        ChainType::Mainnet => Uint256([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000026,
        ]),
        ChainType::Testnet => Uint256([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000026,
        ]),
        ChainType::Signet => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
        ]),
        // Note: this is Uint256::MAX / min_stake_pool_pledge / 2, rounded down.
        // Using this value makes staking succeed quickly in tests. On the other hand, it also
        // guarantees some variety, ensuring that staking on top of genesis with a "typical"
        // test pool (with pledge = balance = min_stake_pool_pledge) will succeed on the first
        // attempted timestamp with the probability not bigger than 0.5.
        ChainType::Regtest => Uint256([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000900,
        ]),
    }
}

pub fn get_initial_randomness(chain_type: ChainType) -> H256 {
    let randomness_hex = match chain_type {
        ChainType::Mainnet => {
            // echo -n "Mintlayer-Mainnet" | sha256sum
            "46f3063737ebc80872b00b32337a327ee91455617c8104511f0868327af6e767"
        }
        ChainType::Testnet => {
            // echo -n "Mintlayer-Testnet" | sha256sum
            "0f1c74dcb7f686ae22a981a7626a62555f36617f9c7d4ae8de1acc3b44016a38"
        }
        ChainType::Regtest => {
            // echo -n "Mintlayer-Regtest" | sha256sum
            "d26b2b998698290ef82f649f82df95d4d30ed828c4207e8227875a11516c2f69"
        }
        ChainType::Signet => {
            // echo -n "Mintlayer-Signet" | sha256sum
            "31e3e4e4bd42db2ce4a9ff7fadb3e11b575a3d5e8e1575425d0378a57b526dd2"
        }
    };

    H256::from_str(randomness_hex).expect("nothing wrong")
}

pub fn get_pos_block_proof(
    prev_block_timestamp: BlockTimestamp,
    this_block_timestamp: BlockTimestamp,
) -> Option<Uint256> {
    let timestamp_diff = this_block_timestamp
        .as_int_seconds()
        .checked_sub(prev_block_timestamp.as_int_seconds())?;

    let block_proof = chaintrust::asymptote::calculate_block_proof(timestamp_diff);
    Some(block_proof)
}
