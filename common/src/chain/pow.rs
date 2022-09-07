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

use crate::chain::config::ChainType;
use crate::primitives::BlockDistance;
use crate::Uint256;
use std::time::Duration;

/// Chain Parameters for Proof of Work.
///
/// See in Bitcoin's [chainparams.cpp](https://github.com/bitcoin/bitcoin/blob/eca694a4e78d54ce4e29b388b3e81b06e55c2293/src/chainparams.cpp)
#[derive(Debug)]
pub struct PoWChainConfig {
    no_retargeting: bool,
    /// Checks whether minimum difficulty can be used for the block
    allow_min_difficulty_blocks: bool,
    /// The lowest possible difficulty
    limit: Uint256,
    /// The distance required to pass to allow spending the block reward
    reward_maturity_distance: BlockDistance,
}

impl PoWChainConfig {
    pub(crate) const fn new(chain_type: ChainType) -> Self {
        PoWChainConfig {
            no_retargeting: no_retargeting(chain_type),
            allow_min_difficulty_blocks: allow_min_difficulty_blocks(chain_type),
            limit: limit(chain_type),
            // If block time is 2 minutes (which is my goal eventually), then 500 is equivalent to 100 in bitcoin's 10 minutes.
            reward_maturity_distance: BlockDistance::new(500),
        }
    }

    pub const fn no_retargeting(&self) -> bool {
        self.no_retargeting
    }

    pub const fn allow_min_difficulty_blocks(&self) -> bool {
        self.allow_min_difficulty_blocks
    }

    pub const fn limit(&self) -> Uint256 {
        self.limit
    }

    pub const fn reward_maturity_distance(&self) -> BlockDistance {
        self.reward_maturity_distance
    }

    /// The difficulty changes every 2016 blocks, or approximately 2 weeks.
    /// See Bitcoin's Protocol Rules of [Difficulty change](https://en.bitcoin.it/wiki/Protocol_rules)
    pub const fn target_timespan(&self) -> Duration {
        Duration::new(14 * 24 * 60 * 60, 0)
    }

    /// The average rate of generating a block is set to every 10 minutes
    pub const fn target_spacing(&self) -> Duration {
        Duration::new(10 * 60, 0)
    }

    /// A single retarget never changes the target by more than a factor of 4.
    /// See Bitcoin's [Target](https://en.bitcoin.it/wiki/Target) article.
    pub const fn max_retarget_factor(&self) -> u64 {
        4
    }
}

const fn no_retargeting(chain_type: ChainType) -> bool {
    match chain_type {
        ChainType::Mainnet | ChainType::Testnet | ChainType::Signet => false,
        ChainType::Regtest => true,
    }
}

const fn allow_min_difficulty_blocks(chain_type: ChainType) -> bool {
    match chain_type {
        ChainType::Mainnet | ChainType::Signet => false,
        ChainType::Testnet | ChainType::Regtest => true,
    }
}

pub(crate) const fn limit(chain_type: ChainType) -> Uint256 {
    match chain_type {
        ChainType::Mainnet | ChainType::Testnet => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x00000000FFFFFFFF,
        ]),
        ChainType::Signet => Uint256([
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x00000377AE000000,
        ]),
        ChainType::Regtest => Uint256([
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ]),
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::config::{create_mainnet, ChainType};
    use crate::chain::pow::{allow_min_difficulty_blocks, limit, no_retargeting};
    use crate::Uint256;

    #[test]
    fn check_mainnet_powconfig() {
        let cfg = create_mainnet();

        let mainnet_cfg = cfg.get_proof_of_work_config();

        assert_eq!(
            mainnet_cfg.no_retargeting(),
            no_retargeting(ChainType::Mainnet)
        );
        assert_eq!(
            mainnet_cfg.allow_min_difficulty_blocks(),
            allow_min_difficulty_blocks(ChainType::Mainnet)
        );
        assert_eq!(mainnet_cfg.limit(), limit(ChainType::Mainnet));

        assert!(!mainnet_cfg.no_retargeting());
        assert!(!mainnet_cfg.allow_min_difficulty_blocks());

        assert_eq!(
            mainnet_cfg.target_timespan().as_secs() % mainnet_cfg.target_spacing().as_secs(),
            0
        );

        if !mainnet_cfg.no_retargeting() {
            let target_max = Uint256([
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
            ]);

            let target_max =
                target_max / Uint256::from_u64(mainnet_cfg.target_timespan().as_secs() * 4);
            assert!(mainnet_cfg.limit() < target_max);
        }
    }
}
