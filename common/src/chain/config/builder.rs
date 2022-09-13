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

use super::emission_schedule::{self, *};
use super::{create_mainnet_genesis, create_unit_test_genesis, ChainConfig, ChainType};

use crate::chain::{
    ConsensusUpgrade, Destination, Genesis, NetUpgrades, PoWChainConfig, UpgradeVersion,
};
use crate::primitives::Amount;
use crate::primitives::{id::WithId, semver::SemVer, BlockHeight};

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

impl ChainType {
    fn default_genesis_init(&self) -> GenesisBlockInit {
        match self {
            ChainType::Mainnet => GenesisBlockInit::Mainnet,
            ChainType::Testnet => todo!("Testnet genesis"),
            ChainType::Regtest => GenesisBlockInit::TEST,
            ChainType::Signet => GenesisBlockInit::TEST,
        }
    }

    fn default_net_upgrades(&self) -> NetUpgrades<UpgradeVersion> {
        match self {
            ChainType::Mainnet | ChainType::Regtest => {
                let pow_config = PoWChainConfig::new(*self);
                let upgrades = vec![
                    (
                        BlockHeight::new(0),
                        UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
                    ),
                    (
                        BlockHeight::new(1),
                        UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoW {
                            initial_difficulty: pow_config.limit().into(),
                        }),
                    ),
                ];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
            ChainType::Testnet => todo!("Testnet upgrades"),
            ChainType::Signet => NetUpgrades::unit_tests(),
        }
    }
}

// Builder support types

#[derive(Clone)]
enum EmissionScheduleInit {
    Mainnet,
    Table(emission_schedule::EmissionScheduleTabular),
    Fn(std::sync::Arc<emission_schedule::EmissionScheduleFn>),
}

#[derive(Clone)]
enum GenesisBlockInit {
    UnitTest { premine_destination: Destination },
    Mainnet,
    Custom(Genesis),
}

impl GenesisBlockInit {
    pub const TEST: Self = GenesisBlockInit::UnitTest {
        premine_destination: Destination::AnyoneCanSpend,
    };
}

/// Builder for [ChainConfig]
#[derive(Clone)]
pub struct Builder {
    chain_type: ChainType,
    address_prefix: String,
    magic_bytes: [u8; 4],
    max_future_block_time_offset: Duration,
    version: SemVer,
    target_block_spacing: Duration,
    coin_decimals: u8,
    max_block_header_size: usize,
    max_block_size_with_standard_txs: usize,
    max_block_size_with_smart_contracts: usize,
    net_upgrades: NetUpgrades<UpgradeVersion>,
    genesis_block: GenesisBlockInit,
    emission_schedule: EmissionScheduleInit,
    token_min_issuance_fee: Amount,
    token_max_uri_len: usize,
    token_max_dec_count: u8,
    token_max_ticker_len: usize,
    token_max_issuance_allowed: usize,
}

impl Builder {
    /// A new chain config builder, with given chain type as a basis
    pub fn new(chain_type: ChainType) -> Self {
        Self {
            chain_type,
            address_prefix: chain_type.default_address_prefix().to_string(),
            coin_decimals: Mlt::DECIMALS,
            magic_bytes: chain_type.default_magic_bytes(),
            version: SemVer::new(0, 1, 0),
            max_block_header_size: super::MAX_BLOCK_HEADER_SIZE,
            max_block_size_with_standard_txs: super::MAX_BLOCK_TXS_SIZE,
            max_block_size_with_smart_contracts: super::MAX_BLOCK_CONTRACTS_SIZE,
            max_future_block_time_offset: super::DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET,
            target_block_spacing: super::DEFAULT_TARGET_BLOCK_SPACING,
            genesis_block: chain_type.default_genesis_init(),
            emission_schedule: EmissionScheduleInit::Mainnet,
            net_upgrades: chain_type.default_net_upgrades(),
            token_min_issuance_fee: super::TOKEN_MIN_ISSUANCE_FEE,
            token_max_uri_len: super::TOKEN_MAX_URI_LEN,
            token_max_dec_count: super::TOKEN_MAX_DEC_COUNT,
            token_max_ticker_len: super::TOKEN_MAX_TICKER_LEN,
            token_max_issuance_allowed: super::TOKEN_MAX_ISSUANCE_ALLOWED,
        }
    }

    /// New builder initialized with test chain config
    pub fn test_chain() -> Self {
        Self::new(ChainType::Mainnet)
            .net_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
    }

    /// Build the chain config
    pub fn build(self) -> ChainConfig {
        let Self {
            chain_type,
            address_prefix,
            coin_decimals,
            magic_bytes,
            version,
            max_block_header_size,
            max_block_size_with_standard_txs,
            max_block_size_with_smart_contracts,
            max_future_block_time_offset,
            target_block_spacing,
            genesis_block,
            emission_schedule,
            net_upgrades,
            token_min_issuance_fee,
            token_max_uri_len,
            token_max_dec_count,
            token_max_ticker_len,
            token_max_issuance_allowed,
        } = self;

        let emission_schedule = match emission_schedule {
            EmissionScheduleInit::Fn(f) => EmissionSchedule::from_arc_fn(f),
            EmissionScheduleInit::Table(t) => t.schedule(),
            EmissionScheduleInit::Mainnet => {
                emission_schedule::mainnet_schedule_table(target_block_spacing).schedule()
            }
        };

        let genesis_block = match genesis_block {
            GenesisBlockInit::Mainnet => create_mainnet_genesis(),
            GenesisBlockInit::Custom(genesis) => genesis,
            GenesisBlockInit::UnitTest {
                premine_destination,
            } => create_unit_test_genesis(premine_destination),
        };
        let genesis_block = Arc::new(WithId::new(genesis_block));

        ChainConfig {
            chain_type,
            address_prefix,
            coin_decimals,
            magic_bytes,
            version,
            max_block_header_size,
            max_block_size_with_standard_txs,
            max_block_size_with_smart_contracts,
            max_future_block_time_offset,
            target_block_spacing,
            genesis_block,
            height_checkpoint_data: BTreeMap::new(),
            emission_schedule,
            net_upgrades,
            token_min_issuance_fee,
            token_max_uri_len,
            token_max_dec_count,
            token_max_ticker_len,
            token_max_issuance_allowed,
        }
    }
}

macro_rules! builder_method {
    ($name:ident: $type:ty) => {
        #[doc = concat!("Set the `", stringify!($name), "` field.")]
        #[must_use = "chain::config::Builder dropped prematurely"]
        pub fn $name(mut self, $name: $type) -> Self {
            self.$name = $name;
            self
        }
    };
}

impl Builder {
    builder_method!(chain_type: ChainType);
    builder_method!(address_prefix: String);
    builder_method!(magic_bytes: [u8; 4]);
    builder_method!(max_future_block_time_offset: Duration);
    builder_method!(version: SemVer);
    builder_method!(target_block_spacing: Duration);
    builder_method!(coin_decimals: u8);
    builder_method!(max_block_header_size: usize);
    builder_method!(max_block_size_with_standard_txs: usize);
    builder_method!(max_block_size_with_smart_contracts: usize);
    builder_method!(net_upgrades: NetUpgrades<UpgradeVersion>);

    /// Set the genesis block to be the unit test version
    pub fn genesis_unittest(mut self, premine_destination: Destination) -> Self {
        self.genesis_block = GenesisBlockInit::UnitTest {
            premine_destination,
        };
        self
    }

    /// Set genesis block to be the mainnet genesis
    pub fn genesis_mainnet(mut self) -> Self {
        self.genesis_block = GenesisBlockInit::Mainnet;
        self
    }

    /// Specify a custom genesis block
    pub fn genesis_custom(mut self, genesis: Genesis) -> Self {
        self.genesis_block = GenesisBlockInit::Custom(genesis);
        self
    }

    /// Set emission schedule to the mainnet schedule
    pub fn emission_schedule_mainnet(mut self) -> Self {
        self.emission_schedule = EmissionScheduleInit::Mainnet;
        self
    }

    /// Initialize an emission schedule using a table
    pub fn emission_schedule_tabular(mut self, es: EmissionScheduleTabular) -> Self {
        self.emission_schedule = EmissionScheduleInit::Table(es);
        self
    }

    /// Initialize an emission schedule using a function
    pub fn emission_schedule_fn(mut self, f: Box<emission_schedule::EmissionScheduleFn>) -> Self {
        self.emission_schedule = EmissionScheduleInit::Fn(f.into());
        self
    }
}
