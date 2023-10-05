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

use std::{num::NonZeroU64, str::FromStr};

use serialization::{DecodeAll, Encode};
use typename::TypeName;

use crate::{
    address::{hexified::HexifiedAddress, traits::Addressable, AddressError},
    primitives::{per_thousand::PerThousand, BlockDistance, Id, H256},
    Uint256,
};

use super::{config::ChainType, ChainConfig};

#[derive(Eq, PartialEq, TypeName)]
pub enum Pool {}
pub type PoolId = Id<Pool>;

#[derive(Eq, PartialEq, TypeName)]
pub enum Delegation {}
pub type DelegationId = Id<Delegation>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct PoSConsensusVersion(u32);

impl PoSConsensusVersion {
    /// Initial PoS implementation
    pub const V0: Self = Self(0);
    /// Incentivize pledging and prevent centralization with capped probability
    pub const V1: Self = Self(1);
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PoSChainConfig {
    /// The lowest possible difficulty
    target_limit: Uint256,
    /// Time interval in secs between the blocks targeted by the difficulty adjustment algorithm
    target_block_time: NonZeroU64,
    /// The distance required to pass to allow spending the decommission pool
    decommission_maturity_distance: BlockDistance,
    /// The distance required to pass to allow spending delegation share
    spend_share_maturity_distance: BlockDistance,
    /// Max number of blocks required to calculate average block time. Min is 2
    block_count_to_average_for_blocktime: usize,
    /// The limit on how much the difficulty can go up or down after each block
    difficulty_change_limit: PerThousand,
    /// Version of the consensus protocol
    consensus_version: PoSConsensusVersion,
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

impl PoSChainConfig {
    pub fn new(
        target_limit: Uint256,
        target_block_time: u64,
        decommission_maturity_distance: BlockDistance,
        spend_share_maturity_distance: BlockDistance,
        block_count_to_average_for_blocktime: usize,
        difficulty_change_limit: PerThousand,
        consensus_version: PoSConsensusVersion,
    ) -> Option<Self> {
        let target_block_time = NonZeroU64::new(target_block_time)?;
        if block_count_to_average_for_blocktime < 2 {
            return None;
        }

        Some(Self {
            target_limit,
            target_block_time,
            decommission_maturity_distance,
            spend_share_maturity_distance,
            block_count_to_average_for_blocktime,
            difficulty_change_limit,
            consensus_version,
        })
    }

    pub fn target_limit(&self) -> Uint256 {
        self.target_limit
    }

    pub fn target_block_time(&self) -> NonZeroU64 {
        self.target_block_time
    }

    pub fn decommission_maturity_distance(&self) -> BlockDistance {
        self.decommission_maturity_distance
    }

    pub fn spend_share_maturity_distance(&self) -> BlockDistance {
        self.spend_share_maturity_distance
    }

    pub fn block_count_to_average_for_blocktime(&self) -> usize {
        self.block_count_to_average_for_blocktime
    }

    pub fn difficulty_change_limit(&self) -> PerThousand {
        self.difficulty_change_limit
    }

    pub fn consensus_version(&self) -> PoSConsensusVersion {
        self.consensus_version
    }
}

const DEFAULT_BLOCK_COUNT_TO_AVERAGE: usize = 100;
const DEFAULT_MATURITY_DISTANCE: BlockDistance = BlockDistance::new(2000);

pub fn create_testnet_pos_config(consensus_version: PoSConsensusVersion) -> PoSChainConfig {
    let target_block_time = NonZeroU64::new(2 * 60).expect("cannot be 0");
    let target_limit = (Uint256::MAX / Uint256::from_u64(target_block_time.get()))
        .expect("Target block time cannot be zero as per NonZeroU64");

    PoSChainConfig {
        target_limit,
        target_block_time,
        decommission_maturity_distance: DEFAULT_MATURITY_DISTANCE,
        spend_share_maturity_distance: DEFAULT_MATURITY_DISTANCE,
        block_count_to_average_for_blocktime: DEFAULT_BLOCK_COUNT_TO_AVERAGE,
        difficulty_change_limit: PerThousand::new(1).expect("must be valid"),
        consensus_version,
    }
}

pub fn create_unittest_pos_config() -> PoSChainConfig {
    PoSChainConfig {
        target_limit: Uint256::MAX,
        target_block_time: NonZeroU64::new(2 * 60).expect("cannot be 0"),
        decommission_maturity_distance: DEFAULT_MATURITY_DISTANCE,
        spend_share_maturity_distance: DEFAULT_MATURITY_DISTANCE,
        block_count_to_average_for_blocktime: DEFAULT_BLOCK_COUNT_TO_AVERAGE,
        difficulty_change_limit: PerThousand::new(1).expect("must be valid"),
        consensus_version: PoSConsensusVersion::V1,
    }
}

pub fn create_regtest_pos_config(consensus_version: PoSConsensusVersion) -> PoSChainConfig {
    let target_block_time = NonZeroU64::new(2 * 60).expect("cannot be 0");
    let target_limit = (Uint256::MAX / Uint256::from_u64(target_block_time.get()))
        .expect("Target block time cannot be zero as per NonZeroU64");

    PoSChainConfig {
        target_limit,
        target_block_time,
        decommission_maturity_distance: DEFAULT_MATURITY_DISTANCE,
        spend_share_maturity_distance: DEFAULT_MATURITY_DISTANCE,
        block_count_to_average_for_blocktime: DEFAULT_BLOCK_COUNT_TO_AVERAGE,
        difficulty_change_limit: PerThousand::new(1).expect("must be valid"),
        consensus_version,
    }
}

pub fn pos_initial_difficulty(chain_type: ChainType) -> Uint256 {
    match chain_type {
        // TODO: Decide what to use on Mainnet.
        ChainType::Mainnet => unimplemented!(),
        // Note: Assuming that there is 1 initial staking pool in testnet the value for difficulty equals to
        // U256::MAX / min_stake_pool_pledge / block_time, dropping the least significant bytes for simplicity
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
        // Note: the value is Uint256::MAX / target_block_time which helps staking without long warm up.
        // It's hardcoded because division for Uint256 is not const
        ChainType::Regtest => Uint256([
            0x2222222222222222,
            0x2222222222222222,
            0x2222222222222222,
            0x0222222222222222,
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
