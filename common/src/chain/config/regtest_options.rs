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

use std::{str::FromStr, time::Duration};

use clap::Args;

use crate::{
    chain::{
        config::{
            regtest::{create_regtest_pos_genesis, create_regtest_pow_genesis},
            Builder, ChainType, EmissionScheduleTabular,
        },
        pos::{
            DEFAULT_BLOCK_COUNT_TO_AVERAGE, DEFAULT_MATURITY_DISTANCE, DEFAULT_TARGET_BLOCK_TIME,
        },
        pos_initial_difficulty, ConsensusUpgrade, Destination, NetUpgrades, PoSChainConfig,
        PoSConsensusVersion,
    },
    primitives::{self, per_thousand::PerThousand, semver::SemVer, BlockHeight},
    Uint256,
};

use super::{regtest::GenesisStakingSettings, ChainConfig};

use anyhow::{anyhow, ensure, Result};
use paste::paste;

#[derive(Args, Clone, Debug)]
pub struct ChainConfigOptions {
    /// Magic bytes.
    #[clap(long)]
    pub chain_magic_bytes: Option<String>,

    /// The maximum future block offset in seconds.
    #[clap(long)]
    pub chain_max_future_block_time_offset: Option<u64>,

    /// The software version (major.minor.path).
    #[clap(long)]
    pub software_version: Option<String>,

    /// Target block spacing in seconds.
    #[clap(long)]
    pub chain_target_block_spacing: Option<u64>,

    /// Coin decimals.
    #[clap(long)]
    pub chain_coin_decimals: Option<u8>,

    /// Emission schedule (`<initial_supply>+<initial_subsidy>[, <height>+<subsidy>]`).
    pub chain_emission_schedule: Option<String>,

    /// The maximum block header size in bytes.
    #[clap(long)]
    pub chain_max_block_header_size: Option<usize>,

    /// The maximum transactions size in block in bytes.
    #[clap(long)]
    pub chain_max_block_size_with_standard_txs: Option<usize>,

    /// The maximum smart contracts size ib block in bytes.
    #[clap(long)]
    pub chain_max_block_size_with_smart_contracts: Option<usize>,

    /// Initial difficulty for the chain in Compact representation.
    #[clap(long)]
    pub chain_initial_difficulty: Option<u32>,

    /// PoS NetUpgrade override after Genesis
    #[clap(long)]
    pub chain_pos_netupgrades: Option<bool>,

    /// PoS NetUpgrade override after Genesis with upgrade of consensus version from V0 to V1
    /// at specific height
    #[clap(long)]
    pub chain_pos_netupgrades_v0_to_v1: Option<u64>,

    /// Genesis block timestamp in seconds since UNIX epoch.
    #[clap(long)]
    pub chain_genesis_block_timestamp: Option<u64>,

    /// PoS Genesis staking settings
    #[clap(long, default_value_t)]
    pub chain_genesis_staking_settings: GenesisStakingSettings,
}

pub fn regtest_chain_config(options: &ChainConfigOptions) -> Result<ChainConfig> {
    let ChainConfigOptions {
        chain_magic_bytes,
        chain_max_future_block_time_offset,
        software_version: chain_software_version,
        chain_target_block_spacing,
        chain_coin_decimals,
        chain_emission_schedule,
        chain_max_block_header_size,
        chain_max_block_size_with_standard_txs,
        chain_max_block_size_with_smart_contracts,
        chain_pos_netupgrades,
        chain_pos_netupgrades_v0_to_v1,
        chain_initial_difficulty,
        chain_genesis_block_timestamp,
        chain_genesis_staking_settings,
    } = options;

    let mut builder = Builder::new(ChainType::Regtest);

    macro_rules! update_builder {
        ($field: ident) => {
            update_builder!($field, std::convert::identity)
        };
        ($field: ident, $converter: stmt) => {
            paste! {
                if let Some(val) = [<chain_ $field>] {
                    builder = builder.$field($converter(val.to_owned()));
                }
            }
        };
        ($field: ident, $converter: stmt, map_err) => {
            paste! {
                if let Some(val) = [<chain_ $field>] {
                    builder = builder.$field($converter(val.to_owned()).map_err(|e| anyhow!(e))?);
                }
            }
        };
    }

    let magic_bytes_from_string = |magic_string: String| -> Result<[u8; 4]> {
        ensure!(magic_string.len() == 4, "Invalid size of magic_bytes");
        let mut result: [u8; 4] = [0; 4];
        for (i, byte) in magic_string.bytes().enumerate() {
            result[i] = byte;
        }
        Ok(result)
    };
    update_builder!(magic_bytes, magic_bytes_from_string, map_err);
    update_builder!(max_future_block_time_offset, Duration::from_secs);
    update_builder!(software_version, SemVer::try_from, map_err);
    update_builder!(target_block_spacing, Duration::from_secs);
    update_builder!(coin_decimals);
    if let Some(val) = chain_emission_schedule {
        builder =
            builder.emission_schedule_tabular(EmissionScheduleTabular::from_str(val.as_str())?);
    }
    update_builder!(max_block_header_size);
    update_builder!(max_block_size_with_standard_txs);
    update_builder!(max_block_size_with_smart_contracts);

    if chain_pos_netupgrades.unwrap_or(false) {
        builder = builder.consensus_upgrades(NetUpgrades::regtest_with_pos()).genesis_custom(
            create_regtest_pos_genesis(
                chain_genesis_staking_settings.clone(),
                *chain_genesis_block_timestamp,
                Destination::AnyoneCanSpend,
            ),
        );
    } else {
        builder = builder.genesis_custom(create_regtest_pow_genesis(
            *chain_genesis_block_timestamp,
            Destination::AnyoneCanSpend,
        ));
    }

    if let Some(upgrade_height) = chain_pos_netupgrades_v0_to_v1 {
        let target_block_time = DEFAULT_TARGET_BLOCK_TIME;
        let target_limit = (Uint256::MAX / Uint256::from_u64(target_block_time.get()))
            .expect("Target block time cannot be zero as per NonZeroU64");

        builder = builder
            .consensus_upgrades(
                NetUpgrades::initialize(vec![
                    (BlockHeight::zero(), ConsensusUpgrade::IgnoreConsensus),
                    (
                        BlockHeight::new(1),
                        ConsensusUpgrade::PoS {
                            initial_difficulty: Some(
                                chain_initial_difficulty
                                    .map(primitives::Compact)
                                    .unwrap_or(pos_initial_difficulty(ChainType::Regtest).into()),
                            ),
                            config: PoSChainConfig::new(
                                target_limit,
                                target_block_time,
                                DEFAULT_MATURITY_DISTANCE,
                                DEFAULT_MATURITY_DISTANCE,
                                DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                                PerThousand::new(1).expect("must be valid"),
                                PoSConsensusVersion::V0,
                            ),
                        },
                    ),
                    (
                        (*upgrade_height).into(),
                        ConsensusUpgrade::PoS {
                            initial_difficulty: None,
                            config: PoSChainConfig::new(
                                target_limit,
                                target_block_time,
                                DEFAULT_MATURITY_DISTANCE,
                                DEFAULT_MATURITY_DISTANCE,
                                DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                                PerThousand::new(1).expect("must be valid"),
                                PoSConsensusVersion::V1,
                            ),
                        },
                    ),
                ])
                .expect("NetUpgrades init cannot fail"),
            )
            .genesis_custom(create_regtest_pos_genesis(
                chain_genesis_staking_settings.clone(),
                *chain_genesis_block_timestamp,
                Destination::AnyoneCanSpend,
            ));
    }

    Ok(builder.build())
}
