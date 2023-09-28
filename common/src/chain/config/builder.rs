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

use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc, time::Duration};

use crate::{
    chain::{
        config::{
            create_mainnet_genesis, create_testnet_genesis, create_unit_test_genesis,
            emission_schedule, ChainConfig, ChainType, EmissionScheduleTabular,
        },
        get_initial_randomness,
        pos::{
            DEFAULT_BLOCK_COUNT_TO_AVERAGE, DEFAULT_MATURITY_DISTANCE, DEFAULT_TARGET_BLOCK_TIME,
        },
        pos_initial_difficulty,
        pow::PoWChainConfigBuilder,
        tokens::TokenIssuanceVersion,
        CoinUnit, ConsensusUpgrade, Destination, GenBlock, Genesis, NetUpgrades, PoSChainConfig,
        PoSConsensusVersion, PoWChainConfig, UpgradeVersion,
    },
    primitives::{
        id::WithId, per_thousand::PerThousand, semver::SemVer, Amount, BlockDistance, BlockHeight,
        Id, Idable, H256,
    },
    Uint256,
};
use crypto::key::hdkd::child_number::ChildNumber;

impl ChainType {
    fn default_genesis_init(&self) -> GenesisBlockInit {
        match self {
            ChainType::Mainnet => GenesisBlockInit::Mainnet,
            ChainType::Testnet => GenesisBlockInit::Testnet,
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
            ChainType::Testnet => {
                let target_block_time = DEFAULT_TARGET_BLOCK_TIME;
                let target_limit = (Uint256::MAX / Uint256::from_u64(target_block_time.get()))
                    .expect("Target block time cannot be zero as per NonZeroU64");

                let upgrades = vec![
                    (
                        BlockHeight::new(0),
                        UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
                    ),
                    (
                        BlockHeight::new(1),
                        UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                            initial_difficulty: Some(
                                pos_initial_difficulty(ChainType::Testnet).into(),
                            ),
                            config: PoSChainConfig::new(
                                target_limit,
                                target_block_time,
                                DEFAULT_MATURITY_DISTANCE,
                                DEFAULT_MATURITY_DISTANCE,
                                DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                                PerThousand::new(1).expect("must be valid"),
                                PoSConsensusVersion::V0,
                                TokenIssuanceVersion::V0,
                            ),
                        }),
                    ),
                    (
                        // TODO: decide on proper height
                        BlockHeight::new(9999999999),
                        UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                            initial_difficulty: None,
                            config: PoSChainConfig::new(
                                target_limit,
                                target_block_time,
                                BlockDistance::new(7200),
                                BlockDistance::new(7200),
                                DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                                PerThousand::new(1).expect("must be valid"),
                                PoSConsensusVersion::V1,
                                TokenIssuanceVersion::V1,
                            ),
                        }),
                    ),
                ];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
            ChainType::Signet => NetUpgrades::unit_tests(),
        }
    }
}

// Builder support types

#[derive(Clone)]
enum EmissionScheduleInit {
    Mainnet,
    Table(EmissionScheduleTabular),
}

#[derive(Clone)]
enum GenesisBlockInit {
    UnitTest { premine_destination: Destination },
    Mainnet,
    Testnet,
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
    bip44_coin_type: ChildNumber,
    magic_bytes: [u8; 4],
    p2p_port: u16,
    default_rpc_port: u16,
    max_future_block_time_offset: Duration,
    software_version: SemVer,
    target_block_spacing: Duration,
    coin_decimals: u8,
    coin_ticker: &'static str,
    max_block_header_size: usize,
    max_block_size_with_standard_txs: usize,
    max_block_size_with_smart_contracts: usize,
    max_no_signature_data_size: usize,
    max_depth_for_reorg: BlockDistance,
    epoch_length: NonZeroU64,
    sealed_epoch_distance_from_tip: usize,
    initial_randomness: H256,
    net_upgrades: NetUpgrades<UpgradeVersion>,
    genesis_block: GenesisBlockInit,
    emission_schedule: EmissionScheduleInit,
    token_min_issuance_fee: Amount,
    token_min_supply_change_fee: Amount,
    token_max_uri_len: usize,
    token_max_dec_count: u8,
    token_max_ticker_len: usize,
    token_max_name_len: usize,
    token_max_description_len: usize,
    token_min_hash_len: usize,
    token_max_hash_len: usize,
    empty_consensus_reward_maturity_distance: BlockDistance,
    max_classic_multisig_public_keys_count: usize,
    min_stake_pool_pledge: Amount,
}

impl Builder {
    /// A new chain config builder, with given chain type as a basis
    pub fn new(chain_type: ChainType) -> Self {
        Self {
            chain_type,
            bip44_coin_type: chain_type.default_bip44_coin_type(),
            coin_decimals: CoinUnit::DECIMALS,
            coin_ticker: chain_type.coin_ticker(),
            magic_bytes: chain_type.default_magic_bytes(),
            p2p_port: chain_type.default_p2p_port(),
            default_rpc_port: chain_type.default_rpc_port(),
            software_version: SemVer::try_from(env!("CARGO_PKG_VERSION"))
                .expect("invalid CARGO_PKG_VERSION value"),
            max_block_header_size: super::MAX_BLOCK_HEADER_SIZE,
            max_block_size_with_standard_txs: super::MAX_BLOCK_TXS_SIZE,
            max_block_size_with_smart_contracts: super::MAX_BLOCK_CONTRACTS_SIZE,
            max_no_signature_data_size: super::MAX_TX_NO_SIG_WITNESS_SIZE,
            max_future_block_time_offset: super::DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET,
            max_depth_for_reorg: super::DEFAULT_MAX_DEPTH_FOR_REORG,
            epoch_length: super::DEFAULT_EPOCH_LENGTH,
            sealed_epoch_distance_from_tip: super::DEFAULT_SEALED_EPOCH_DISTANCE_FROM_TIP,
            initial_randomness: get_initial_randomness(chain_type),
            target_block_spacing: super::DEFAULT_TARGET_BLOCK_SPACING,
            genesis_block: chain_type.default_genesis_init(),
            emission_schedule: EmissionScheduleInit::Mainnet,
            net_upgrades: chain_type.default_net_upgrades(),
            token_min_issuance_fee: super::TOKEN_MIN_ISSUANCE_FEE,
            token_min_supply_change_fee: super::TOKEN_MIN_SUPPLY_CHANGE_FEE,
            token_max_uri_len: super::TOKEN_MAX_URI_LEN,
            token_max_dec_count: super::TOKEN_MAX_DEC_COUNT,
            token_max_ticker_len: super::TOKEN_MAX_TICKER_LEN,
            token_max_name_len: super::TOKEN_MAX_NAME_LEN,
            token_max_description_len: super::TOKEN_MAX_DESCRIPTION_LEN,
            token_min_hash_len: super::TOKEN_MIN_HASH_LEN,
            token_max_hash_len: super::TOKEN_MAX_HASH_LEN,
            empty_consensus_reward_maturity_distance: BlockDistance::new(0),
            max_classic_multisig_public_keys_count: super::MAX_CLASSIC_MULTISIG_PUBLIC_KEYS_COUNT,
            min_stake_pool_pledge: super::MIN_STAKE_POOL_PLEDGE,
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
            bip44_coin_type,
            coin_decimals,
            coin_ticker,
            magic_bytes,
            p2p_port,
            default_rpc_port,
            software_version,
            max_block_header_size,
            max_block_size_with_standard_txs,
            max_block_size_with_smart_contracts,
            max_future_block_time_offset,
            max_no_signature_data_size,
            max_depth_for_reorg,
            epoch_length,
            sealed_epoch_distance_from_tip,
            initial_randomness,
            target_block_spacing,
            genesis_block,
            emission_schedule,
            net_upgrades,
            token_min_issuance_fee,
            token_min_supply_change_fee,
            token_max_uri_len,
            token_max_dec_count,
            token_max_ticker_len,
            token_max_name_len,
            token_max_description_len,
            token_min_hash_len,
            token_max_hash_len,
            empty_consensus_reward_maturity_distance,
            max_classic_multisig_public_keys_count,
            min_stake_pool_pledge,
        } = self;

        let emission_table = match emission_schedule {
            EmissionScheduleInit::Table(t) => t,
            EmissionScheduleInit::Mainnet => {
                emission_schedule::mainnet_schedule_table(target_block_spacing)
            }
        };
        let final_supply = emission_table.final_supply();
        let emission_schedule = emission_table.schedule();

        let genesis_block = match genesis_block {
            GenesisBlockInit::Mainnet => create_mainnet_genesis(),
            GenesisBlockInit::Testnet => create_testnet_genesis(),
            GenesisBlockInit::Custom(genesis) => genesis,
            GenesisBlockInit::UnitTest {
                premine_destination,
            } => create_unit_test_genesis(premine_destination),
        };
        let genesis_block = Arc::new(WithId::new(genesis_block));

        let height_checkpoint_data = vec![(0.into(), genesis_block.get_id().into())]
            .into_iter()
            .collect::<BTreeMap<BlockHeight, Id<GenBlock>>>()
            .into();

        let pow_chain_config = {
            let (_, genesis_upgrade_version) = net_upgrades
                .version_at_height(BlockHeight::new(0))
                .expect("Genesis must have an upgrade version");

            let limit = match genesis_upgrade_version {
                UpgradeVersion::SomeUpgrade => None,
                UpgradeVersion::ConsensusUpgrade(consensus_upgrade) => match consensus_upgrade {
                    ConsensusUpgrade::IgnoreConsensus | ConsensusUpgrade::PoS { .. } => None,
                    ConsensusUpgrade::PoW { initial_difficulty } => {
                        let limit = (*initial_difficulty)
                            .try_into()
                            .expect("Genesis initial difficulty to be valid");
                        Some(limit)
                    }
                },
            };

            PoWChainConfigBuilder::new(chain_type).limit(limit).build()
        };

        ChainConfig {
            chain_type,
            bip44_coin_type,
            coin_decimals,
            coin_ticker,
            magic_bytes,
            p2p_port,
            default_rpc_port,
            software_version,
            max_block_header_size,
            max_block_size_with_standard_txs,
            max_block_size_with_smart_contracts,
            max_future_block_time_offset,
            max_no_signature_data_size,
            max_depth_for_reorg,
            pow_chain_config,
            epoch_length,
            sealed_epoch_distance_from_tip,
            initial_randomness,
            target_block_spacing,
            genesis_block,
            height_checkpoint_data,
            emission_schedule,
            final_supply,
            net_upgrades,
            token_min_issuance_fee,
            token_min_supply_change_fee,
            token_max_uri_len,
            token_max_dec_count,
            token_max_ticker_len,
            empty_consensus_reward_maturity_distance,
            token_max_name_len,
            token_max_description_len,
            token_min_hash_len,
            token_max_hash_len,
            max_classic_multisig_public_keys_count,
            min_stake_pool_pledge,
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
    builder_method!(bip44_coin_type: ChildNumber);
    builder_method!(magic_bytes: [u8; 4]);
    builder_method!(p2p_port: u16);
    builder_method!(max_future_block_time_offset: Duration);
    builder_method!(software_version: SemVer);
    builder_method!(target_block_spacing: Duration);
    builder_method!(coin_decimals: u8);
    builder_method!(max_block_header_size: usize);
    builder_method!(max_block_size_with_standard_txs: usize);
    builder_method!(max_block_size_with_smart_contracts: usize);
    builder_method!(max_depth_for_reorg: BlockDistance);
    builder_method!(net_upgrades: NetUpgrades<UpgradeVersion>);
    builder_method!(empty_consensus_reward_maturity_distance: BlockDistance);
    builder_method!(epoch_length: NonZeroU64);
    builder_method!(sealed_epoch_distance_from_tip: usize);

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

    /// Set genesis block to be the testnet genesis
    pub fn genesis_testnet(mut self) -> Self {
        self.genesis_block = GenesisBlockInit::Testnet;
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
}
