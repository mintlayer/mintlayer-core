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

use std::{collections::BTreeMap, net::SocketAddr, num::NonZeroU64, sync::Arc, time::Duration};

use crate::{
    chain::{
        config::{
            create_mainnet_genesis, create_testnet_genesis, create_unit_test_genesis,
            emission_schedule, ChainConfig, ChainType, EmissionScheduleTabular,
        },
        get_initial_randomness,
        pos::{
            DEFAULT_BLOCK_COUNT_TO_AVERAGE, DEFAULT_MATURITY_BLOCK_COUNT_V0,
            DEFAULT_MATURITY_BLOCK_COUNT_V1,
        },
        pos_initial_difficulty,
        pow::PoWChainConfigBuilder,
        tokens::TokenIssuanceVersion,
        ChainstateUpgrade, CoinUnit, ConsensusUpgrade, Destination, GenBlock, Genesis, NetUpgrades,
        PoSChainConfig, PoSConsensusVersion, PoWChainConfig, RewardDistributionVersion,
    },
    primitives::{
        id::WithId, per_thousand::PerThousand, semver::SemVer, Amount, BlockCount, BlockDistance,
        BlockHeight, Id, Idable, H256,
    },
    Uint256,
};
use crypto::key::hdkd::child_number::ChildNumber;

// The fork, at which we upgrade consensus to dis-incentivize large pools + enable tokens v1
const TESTNET_TOKEN_FORK_HEIGHT: BlockHeight = BlockHeight::new(78440);
// The fork, at which we upgrade chainstate to distribute reward to staker proportionally to its balance
const TESTNET_STAKER_REWARD_FORK_HEIGHT: BlockHeight = BlockHeight::new(138244);

impl ChainType {
    fn default_genesis_init(&self) -> GenesisBlockInit {
        match self {
            ChainType::Mainnet => GenesisBlockInit::Mainnet,
            ChainType::Testnet => GenesisBlockInit::Testnet,
            ChainType::Regtest => GenesisBlockInit::TEST,
            ChainType::Signet => GenesisBlockInit::TEST,
        }
    }

    fn default_data_in_no_signature_witness_allowed(&self) -> bool {
        match self {
            ChainType::Mainnet => false,
            ChainType::Regtest | ChainType::Testnet | ChainType::Signet => true,
        }
    }

    fn default_consensus_upgrades(
        &self,
        target_block_spacing: Duration,
    ) -> NetUpgrades<ConsensusUpgrade> {
        match self {
            ChainType::Mainnet | ChainType::Regtest => {
                let pow_config = PoWChainConfig::new(*self);
                let upgrades = vec![
                    (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
                    (
                        BlockHeight::new(1),
                        ConsensusUpgrade::PoW {
                            initial_difficulty: pow_config.limit().into(),
                        },
                    ),
                ];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
            ChainType::Testnet => {
                let target_limit = (Uint256::MAX
                    / Uint256::from_u64(target_block_spacing.as_secs()))
                .expect("Target block time cannot be zero as per NonZeroU64");

                let upgrades = vec![
                    (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
                    (
                        BlockHeight::new(1),
                        ConsensusUpgrade::PoS {
                            initial_difficulty: Some(
                                pos_initial_difficulty(ChainType::Testnet).into(),
                            ),
                            config: PoSChainConfig::new(
                                target_limit,
                                DEFAULT_MATURITY_BLOCK_COUNT_V0,
                                DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                                PerThousand::new(1).expect("must be valid"),
                                PoSConsensusVersion::V0,
                            ),
                        },
                    ),
                    (
                        TESTNET_TOKEN_FORK_HEIGHT,
                        ConsensusUpgrade::PoS {
                            initial_difficulty: None,
                            config: PoSChainConfig::new(
                                target_limit,
                                DEFAULT_MATURITY_BLOCK_COUNT_V1,
                                DEFAULT_BLOCK_COUNT_TO_AVERAGE,
                                PerThousand::new(1).expect("must be valid"),
                                PoSConsensusVersion::V1,
                            ),
                        },
                    ),
                ];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
            ChainType::Signet => NetUpgrades::unit_tests(),
        }
    }

    fn default_chainstate_upgrades(&self) -> NetUpgrades<ChainstateUpgrade> {
        match self {
            ChainType::Mainnet | ChainType::Regtest | ChainType::Signet => {
                let upgrades = vec![(
                    BlockHeight::new(0),
                    ChainstateUpgrade::new(TokenIssuanceVersion::V1, RewardDistributionVersion::V1),
                )];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
            ChainType::Testnet => {
                let upgrades = vec![
                    (
                        BlockHeight::new(0),
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V0,
                            RewardDistributionVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_TOKEN_FORK_HEIGHT,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_STAKER_REWARD_FORK_HEIGHT,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                        ),
                    ),
                ];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
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
    dns_seeds: Vec<&'static str>,
    predefined_peer_addresses: Vec<SocketAddr>,
    default_node_rpc_port: u16,
    default_wallet_rpc_port: u16,
    max_future_block_time_offset: Duration,
    software_version: SemVer,
    target_block_spacing: Duration,
    coin_decimals: u8,
    coin_ticker: &'static str,
    max_block_header_size: usize,
    max_block_size_with_standard_txs: usize,
    max_block_size_with_smart_contracts: usize,
    data_in_no_signature_witness_allowed: bool,
    data_in_no_signature_witness_max_size: usize,
    max_depth_for_reorg: BlockDistance,
    epoch_length: NonZeroU64,
    sealed_epoch_distance_from_tip: usize,
    initial_randomness: H256,
    consensus_upgrades: NetUpgrades<ConsensusUpgrade>,
    chainstate_upgrades: NetUpgrades<ChainstateUpgrade>,
    genesis_block: GenesisBlockInit,
    emission_schedule: EmissionScheduleInit,
    data_deposit_max_size: usize,
    data_deposit_fee: Amount,
    fungible_token_issuance_fee: Amount,
    nft_issuance_fee: Amount,
    token_supply_change_fee: Amount,
    token_freeze_fee: Amount,
    token_change_authority_fee: Amount,
    token_max_uri_len: usize,
    token_max_dec_count: u8,
    token_max_ticker_len: usize,
    token_max_name_len: usize,
    token_max_description_len: usize,
    token_min_hash_len: usize,
    token_max_hash_len: usize,
    empty_consensus_reward_maturity_block_count: BlockCount,
    max_classic_multisig_public_keys_count: usize,
    min_stake_pool_pledge: Amount,
}

impl Builder {
    /// A new chain config builder, with given chain type as a basis
    pub fn new(chain_type: ChainType) -> Self {
        let target_block_spacing = super::DEFAULT_TARGET_BLOCK_SPACING;
        let consensus_upgrades = chain_type.default_consensus_upgrades(target_block_spacing);

        Self {
            chain_type,
            bip44_coin_type: chain_type.default_bip44_coin_type(),
            coin_decimals: CoinUnit::DECIMALS,
            coin_ticker: chain_type.coin_ticker(),
            magic_bytes: chain_type.default_magic_bytes(),
            p2p_port: chain_type.default_p2p_port(),
            dns_seeds: chain_type.dns_seeds(),
            predefined_peer_addresses: chain_type.predefined_peer_addresses(),
            default_node_rpc_port: chain_type.default_node_rpc_port(),
            default_wallet_rpc_port: chain_type.default_wallet_rpc_port(),
            software_version: SemVer::try_from(env!("CARGO_PKG_VERSION"))
                .expect("invalid CARGO_PKG_VERSION value"),
            max_block_header_size: super::MAX_BLOCK_HEADER_SIZE,
            max_block_size_with_standard_txs: super::MAX_BLOCK_TXS_SIZE,
            max_block_size_with_smart_contracts: super::MAX_BLOCK_CONTRACTS_SIZE,
            data_in_no_signature_witness_allowed: chain_type
                .default_data_in_no_signature_witness_allowed(),
            data_in_no_signature_witness_max_size: super::TX_DATA_IN_NO_SIG_WITNESS_MAX_SIZE,
            max_future_block_time_offset: super::DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET,
            max_depth_for_reorg: super::DEFAULT_MAX_DEPTH_FOR_REORG,
            epoch_length: super::DEFAULT_EPOCH_LENGTH,
            sealed_epoch_distance_from_tip: super::DEFAULT_SEALED_EPOCH_DISTANCE_FROM_TIP,
            initial_randomness: get_initial_randomness(chain_type),
            target_block_spacing,
            genesis_block: chain_type.default_genesis_init(),
            emission_schedule: EmissionScheduleInit::Mainnet,
            consensus_upgrades,
            chainstate_upgrades: chain_type.default_chainstate_upgrades(),
            data_deposit_max_size: super::DATA_DEPOSIT_MAX_SIZE,
            data_deposit_fee: super::DATA_DEPOSIT_MIN_FEE,
            fungible_token_issuance_fee: super::FUNGIBLE_TOKEN_MIN_ISSUANCE_FEE,
            nft_issuance_fee: super::NFT_MIN_ISSUANCE_FEE,
            token_supply_change_fee: super::TOKEN_MIN_SUPPLY_CHANGE_FEE,
            token_freeze_fee: super::TOKEN_MIN_FREEZE_FEE,
            token_change_authority_fee: super::TOKEN_CHANGE_AUTHORITY_FEE,
            token_max_uri_len: super::TOKEN_MAX_URI_LEN,
            token_max_dec_count: super::TOKEN_MAX_DEC_COUNT,
            token_max_ticker_len: super::TOKEN_MAX_TICKER_LEN,
            token_max_name_len: super::TOKEN_MAX_NAME_LEN,
            token_max_description_len: super::TOKEN_MAX_DESCRIPTION_LEN,
            token_min_hash_len: super::TOKEN_MIN_HASH_LEN,
            token_max_hash_len: super::TOKEN_MAX_HASH_LEN,
            empty_consensus_reward_maturity_block_count: BlockCount::new(0),
            max_classic_multisig_public_keys_count: super::MAX_CLASSIC_MULTISIG_PUBLIC_KEYS_COUNT,
            min_stake_pool_pledge: super::MIN_STAKE_POOL_PLEDGE,
        }
    }

    /// New builder initialized with test chain config
    pub fn test_chain() -> Self {
        Self::new(ChainType::Testnet)
            .consensus_upgrades(NetUpgrades::unit_tests())
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
            dns_seeds,
            predefined_peer_addresses,
            default_node_rpc_port,
            default_wallet_rpc_port,
            software_version,
            max_block_header_size,
            max_block_size_with_standard_txs,
            max_block_size_with_smart_contracts,
            max_future_block_time_offset,
            data_in_no_signature_witness_allowed,
            data_in_no_signature_witness_max_size,
            max_depth_for_reorg,
            epoch_length,
            sealed_epoch_distance_from_tip,
            initial_randomness,
            target_block_spacing,
            genesis_block,
            emission_schedule,
            consensus_upgrades,
            chainstate_upgrades,
            data_deposit_max_size,
            data_deposit_fee,
            fungible_token_issuance_fee,
            nft_issuance_fee,
            token_supply_change_fee,
            token_freeze_fee,
            token_change_authority_fee,
            token_max_uri_len,
            token_max_dec_count,
            token_max_ticker_len,
            token_max_name_len,
            token_max_description_len,
            token_min_hash_len,
            token_max_hash_len,
            empty_consensus_reward_maturity_block_count,
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
            let (_, genesis_upgrade_version) =
                consensus_upgrades.version_at_height(BlockHeight::new(0));

            let limit = match genesis_upgrade_version {
                ConsensusUpgrade::IgnoreConsensus | ConsensusUpgrade::PoS { .. } => None,
                ConsensusUpgrade::PoW { initial_difficulty } => {
                    let limit = (*initial_difficulty)
                        .try_into()
                        .expect("Genesis initial difficulty to be valid");
                    Some(limit)
                }
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
            dns_seeds,
            predefined_peer_addresses,
            default_node_rpc_port,
            default_wallet_rpc_port,
            software_version,
            max_block_header_size,
            max_block_size_with_standard_txs,
            max_block_size_with_smart_contracts,
            max_future_block_time_offset,
            data_in_no_signature_witness_allowed,
            data_in_no_signature_witness_max_size,
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
            consensus_upgrades,
            chainstate_upgrades,
            data_deposit_max_size,
            data_deposit_fee,
            fungible_token_issuance_fee,
            nft_issuance_fee,
            token_supply_change_fee,
            token_freeze_fee,
            token_change_authority_fee,
            token_max_uri_len,
            token_max_dec_count,
            token_max_ticker_len,
            empty_consensus_reward_maturity_block_count,
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
    builder_method!(dns_seeds: Vec<&'static str>);
    builder_method!(predefined_peer_addresses: Vec<SocketAddr>);
    builder_method!(max_future_block_time_offset: Duration);
    builder_method!(software_version: SemVer);
    builder_method!(target_block_spacing: Duration);
    builder_method!(coin_decimals: u8);
    builder_method!(data_in_no_signature_witness_allowed: bool);
    builder_method!(data_in_no_signature_witness_max_size: usize);
    builder_method!(max_block_header_size: usize);
    builder_method!(max_block_size_with_standard_txs: usize);
    builder_method!(max_block_size_with_smart_contracts: usize);
    builder_method!(max_depth_for_reorg: BlockDistance);
    builder_method!(consensus_upgrades: NetUpgrades<ConsensusUpgrade>);
    builder_method!(chainstate_upgrades: NetUpgrades<ChainstateUpgrade>);
    builder_method!(empty_consensus_reward_maturity_block_count: BlockCount);
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
