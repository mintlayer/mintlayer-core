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

use typename::TypeName;

use crate::{
    primitives::{per_thousand::PerThousand, BlockDistance, Id, H256},
    Uint256,
};

use super::config::ChainType;

#[derive(Eq, PartialEq, TypeName)]
pub enum Pool {}
pub type PoolId = Id<Pool>;

#[derive(Eq, PartialEq, TypeName)]
pub enum Delegation {}
pub type DelegationId = Id<Delegation>;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct PoSChainConfig {
    /// The lowest possible difficulty
    target_limit: Uint256,
    /// Time interval in secs between the blocks targeted by the difficulty adjustment algorithm
    target_block_time: NonZeroU64,
    /// The distance required to pass to allow spending the block reward
    reward_maturity_distance: BlockDistance,
    /// The distance required to pass to allow spending the decommission pool
    decommission_maturity_distance: BlockDistance,
    /// The distance required to pass to allow spending delegation share
    spend_share_maturity_distance: BlockDistance,
    /// Max number of blocks required to calculate average block time. Min is 2
    block_count_to_average_for_blocktime: usize,
    /// The limit on how much the difficulty can go up or down after each block
    difficulty_change_limit: PerThousand,
}

impl PoSChainConfig {
    pub fn new(
        target_limit: Uint256,
        target_block_time: u64,
        reward_maturity_distance: BlockDistance,
        decommission_maturity_distance: BlockDistance,
        spend_share_maturity_distance: BlockDistance,
        block_count_to_average_for_blocktime: usize,
        difficulty_change_limit: PerThousand,
    ) -> Option<Self> {
        let target_block_time = NonZeroU64::new(target_block_time)?;
        if block_count_to_average_for_blocktime < 2 {
            return None;
        }

        Some(Self {
            target_limit,
            target_block_time,
            reward_maturity_distance,
            decommission_maturity_distance,
            spend_share_maturity_distance,
            block_count_to_average_for_blocktime,
            difficulty_change_limit,
        })
    }

    pub fn target_limit(&self) -> Uint256 {
        self.target_limit
    }

    pub fn target_block_time(&self) -> NonZeroU64 {
        self.target_block_time
    }

    pub fn reward_maturity_distance(&self) -> BlockDistance {
        self.reward_maturity_distance
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
}

pub fn create_testnet_pos_config() -> PoSChainConfig {
    PoSChainConfig {
        target_limit: Uint256::MAX,
        target_block_time: NonZeroU64::new(2 * 60).expect("cannot be 0"),
        reward_maturity_distance: 2000.into(),
        decommission_maturity_distance: 2000.into(),
        spend_share_maturity_distance: 2000.into(),
        block_count_to_average_for_blocktime: 5,
        difficulty_change_limit: PerThousand::new(100).expect("must be valid"),
    }
}

pub fn create_unittest_pos_config() -> PoSChainConfig {
    PoSChainConfig {
        target_limit: Uint256::MAX,
        target_block_time: NonZeroU64::new(2 * 60).expect("cannot be 0"),
        reward_maturity_distance: 2000.into(),
        decommission_maturity_distance: 2000.into(),
        spend_share_maturity_distance: 2000.into(),
        block_count_to_average_for_blocktime: 5,
        difficulty_change_limit: PerThousand::new(100).expect("must be valid"),
    }
}

pub const fn initial_difficulty(chain_type: ChainType) -> Uint256 {
    match chain_type {
        // TODO: Decide what to use on Mainnet.
        // The initial_difficulty value from testnet is probably too high,
        // because it takes a long time to converge on some stable level
        // (about 200..300 blocks for testnet because of the 10% swing limit).
        ChainType::Mainnet => unimplemented!(),
        ChainType::Testnet => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
        ]),
        ChainType::Signet | ChainType::Regtest => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
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
