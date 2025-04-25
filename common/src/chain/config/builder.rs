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
        ChainstateUpgrade, ChainstateUpgradesBuilder, ChangeTokenMetadataUriActivated, CoinUnit,
        ConsensusUpgrade, DataDepositFeeVersion, Destination, FrozenTokensValidationVersion,
        GenBlock, Genesis, HtlcActivated, NetUpgrades, OrdersActivated, OrdersVersion,
        PoSChainConfig, PoSConsensusVersion, PoWChainConfig, RewardDistributionVersion,
        StakerDestinationUpdateForbidden, TokenIdGenerationVersion, TokenIssuanceVersion,
        TokensFeeVersion,
    },
    primitives::{
        id::WithId, per_thousand::PerThousand, semver::SemVer, Amount, BlockCount, BlockDistance,
        BlockHeight, Id, Idable, H256,
    },
    Uint256,
};
use crypto::key::hdkd::child_number::ChildNumber;

use super::{
    checkpoints::Checkpoints,
    checkpoints_data::{MAINNET_CHECKPOINTS, TESTNET_CHECKPOINTS},
    MagicBytes,
};

// The fork at which we upgrade consensus to dis-incentivize large pools + enable tokens v1
const TESTNET_FORK_HEIGHT_1_TOKENS_V1_AND_CONSENSUS_UPGRADE: BlockHeight = BlockHeight::new(78_440);
// The fork at which we upgrade chainstate to distribute reward to staker proportionally to their balance
// and change various tokens fees
const TESTNET_FORK_HEIGHT_2_STAKER_REWARD_AND_TOKENS_FEE: BlockHeight = BlockHeight::new(138_244);
// The fork at which txs with htlc outputs become valid, data deposit fee and size, max future block time offset changed
const TESTNET_FORK_HEIGHT_3_HTLC_AND_DATA_DEPOSIT_FEE: BlockHeight = BlockHeight::new(297_550);
// The fork at which order outputs become valid
const TESTNET_FORK_HEIGHT_4_ORDERS: BlockHeight = BlockHeight::new(325_180);
// The fork at which we enable orders v1 and prohibit updating the staker destination in ProduceBlockFromStake.
const TESTNET_FORK_HEIGHT_5_ORDERS_V1_AND_STAKER_DESTINATION_UPDATE_PROHIBITION: BlockHeight =
    BlockHeight::new(999_999_999);

// The fork at which txs with htlc and orders outputs become valid
const MAINNET_FORK_HEIGHT_1_HTLC_AND_ORDERS: BlockHeight = BlockHeight::new(254_740);
// The fork at which we enable orders v1 and prohibit updating the staker destination in ProduceBlockFromStake.
const MAINNET_FORK_HEIGHT_2_ORDERS_V1_AND_STAKER_DESTINATION_UPDATE_PROHIBITION: BlockHeight =
    BlockHeight::new(999_999_999);

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
            ChainType::Mainnet => {
                let target_limit = (Uint256::MAX
                    / Uint256::from_u64(target_block_spacing.as_secs()))
                .expect("Target block time cannot be zero as per NonZeroU64");

                let upgrades = vec![
                    (BlockHeight::new(0), ConsensusUpgrade::IgnoreConsensus),
                    (
                        BlockHeight::new(1),
                        ConsensusUpgrade::PoS {
                            initial_difficulty: Some(
                                pos_initial_difficulty(ChainType::Mainnet).into(),
                            ),
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
            ChainType::Regtest => {
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
                        TESTNET_FORK_HEIGHT_1_TOKENS_V1_AND_CONSENSUS_UPGRADE,
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
            ChainType::Mainnet => ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
                TokenIssuanceVersion::V1,
                RewardDistributionVersion::V1,
                TokensFeeVersion::V1,
                DataDepositFeeVersion::V0,
                ChangeTokenMetadataUriActivated::No,
                FrozenTokensValidationVersion::V0,
                HtlcActivated::No,
                OrdersActivated::No,
                OrdersVersion::V0,
                StakerDestinationUpdateForbidden::No,
                TokenIdGenerationVersion::V0,
            ))
            .then(MAINNET_FORK_HEIGHT_1_HTLC_AND_ORDERS, |builder| {
                builder
                    .data_deposit_fee_version(DataDepositFeeVersion::V1)
                    .change_token_metadata_uri_activated(ChangeTokenMetadataUriActivated::Yes)
                    .frozen_tokens_validation_version(FrozenTokensValidationVersion::V1)
                    .htlc_activated(HtlcActivated::Yes)
                    .orders_activated(OrdersActivated::Yes)
            })
            .then(
                MAINNET_FORK_HEIGHT_2_ORDERS_V1_AND_STAKER_DESTINATION_UPDATE_PROHIBITION,
                |builder| {
                    builder
                        .orders_version(OrdersVersion::V1)
                        .staker_destination_update_forbidden(StakerDestinationUpdateForbidden::Yes)
                        .token_id_generation_version(TokenIdGenerationVersion::V1)
                },
            )
            .build(),
            ChainType::Regtest | ChainType::Signet => {
                let upgrades = vec![(
                    BlockHeight::new(0),
                    ChainstateUpgrade::new(
                        TokenIssuanceVersion::V1,
                        RewardDistributionVersion::V1,
                        TokensFeeVersion::V1,
                        DataDepositFeeVersion::V1,
                        ChangeTokenMetadataUriActivated::Yes,
                        FrozenTokensValidationVersion::V1,
                        HtlcActivated::Yes,
                        OrdersActivated::Yes,
                        OrdersVersion::V1,
                        StakerDestinationUpdateForbidden::Yes,
                        TokenIdGenerationVersion::V1,
                    ),
                )];
                NetUpgrades::initialize(upgrades).expect("net upgrades")
            }
            ChainType::Testnet => ChainstateUpgradesBuilder::new(ChainstateUpgrade::new(
                TokenIssuanceVersion::V0,
                RewardDistributionVersion::V0,
                TokensFeeVersion::V0,
                DataDepositFeeVersion::V0,
                ChangeTokenMetadataUriActivated::No,
                FrozenTokensValidationVersion::V0,
                HtlcActivated::No,
                OrdersActivated::No,
                OrdersVersion::V0,
                StakerDestinationUpdateForbidden::No,
                TokenIdGenerationVersion::V0,
            ))
            .then(
                TESTNET_FORK_HEIGHT_1_TOKENS_V1_AND_CONSENSUS_UPGRADE,
                |builder| builder.token_issuance_version(TokenIssuanceVersion::V1),
            )
            .then(
                TESTNET_FORK_HEIGHT_2_STAKER_REWARD_AND_TOKENS_FEE,
                |builder| {
                    builder
                        .reward_distribution_version(RewardDistributionVersion::V1)
                        .tokens_fee_version(TokensFeeVersion::V1)
                },
            )
            .then(TESTNET_FORK_HEIGHT_3_HTLC_AND_DATA_DEPOSIT_FEE, |builder| {
                builder
                    .data_deposit_fee_version(DataDepositFeeVersion::V1)
                    .change_token_metadata_uri_activated(ChangeTokenMetadataUriActivated::Yes)
                    .htlc_activated(HtlcActivated::Yes)
            })
            .then(TESTNET_FORK_HEIGHT_4_ORDERS, |builder| {
                builder
                    .frozen_tokens_validation_version(FrozenTokensValidationVersion::V1)
                    .orders_activated(OrdersActivated::Yes)
            })
            .then(
                TESTNET_FORK_HEIGHT_5_ORDERS_V1_AND_STAKER_DESTINATION_UPDATE_PROHIBITION,
                |builder| {
                    builder
                        .orders_version(OrdersVersion::V1)
                        .staker_destination_update_forbidden(StakerDestinationUpdateForbidden::Yes)
                        .token_id_generation_version(TokenIdGenerationVersion::V1)
                },
            )
            .build(),
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
    checkpoints: Option<BTreeMap<BlockHeight, Id<GenBlock>>>,
    magic_bytes: MagicBytes,
    p2p_port: u16,
    dns_seeds: Vec<&'static str>,
    predefined_peer_addresses: Vec<SocketAddr>,
    default_rpc_port: u16,
    max_future_block_time_offset: Option<Duration>,
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
    data_deposit_max_size: Option<usize>,
    token_max_uri_len: usize,
    token_max_dec_count: u8,
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
            checkpoints: None,
            coin_decimals: CoinUnit::DECIMALS,
            coin_ticker: chain_type.coin_ticker(),
            magic_bytes: chain_type.magic_bytes(),
            p2p_port: chain_type.default_p2p_port(),
            dns_seeds: chain_type.dns_seeds(),
            predefined_peer_addresses: chain_type.predefined_peer_addresses(),
            default_rpc_port: chain_type.default_rpc_port(),
            software_version: SemVer::try_from(env!("CARGO_PKG_VERSION"))
                .expect("invalid CARGO_PKG_VERSION value"),
            max_block_header_size: super::MAX_BLOCK_HEADER_SIZE,
            max_block_size_with_standard_txs: super::MAX_BLOCK_TXS_SIZE,
            max_block_size_with_smart_contracts: super::MAX_BLOCK_CONTRACTS_SIZE,
            data_in_no_signature_witness_allowed: chain_type
                .default_data_in_no_signature_witness_allowed(),
            data_in_no_signature_witness_max_size: super::TX_DATA_IN_NO_SIG_WITNESS_MAX_SIZE,
            max_future_block_time_offset: None,
            max_depth_for_reorg: super::DEFAULT_MAX_DEPTH_FOR_REORG,
            epoch_length: super::DEFAULT_EPOCH_LENGTH,
            sealed_epoch_distance_from_tip: super::DEFAULT_SEALED_EPOCH_DISTANCE_FROM_TIP,
            initial_randomness: get_initial_randomness(chain_type),
            target_block_spacing,
            genesis_block: chain_type.default_genesis_init(),
            emission_schedule: EmissionScheduleInit::Mainnet,
            consensus_upgrades,
            chainstate_upgrades: chain_type.default_chainstate_upgrades(),
            data_deposit_max_size: None,
            token_max_uri_len: super::TOKEN_MAX_URI_LEN,
            token_max_dec_count: super::TOKEN_MAX_DEC_COUNT,
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
        // Note: there are tests that seem to depend on Testnet being used here instead of Regtest.
        Self::new(ChainType::Testnet)
            .consensus_upgrades(NetUpgrades::unit_tests())
            .genesis_unittest(Destination::AnyoneCanSpend)
            // Force empty checkpoints list, because a custom genesis is used.
            .checkpoints(BTreeMap::new())
    }

    /// Build the chain config
    pub fn build(self) -> ChainConfig {
        let Self {
            chain_type,
            bip44_coin_type,
            checkpoints,
            coin_decimals,
            coin_ticker,
            magic_bytes,
            p2p_port,
            dns_seeds,
            predefined_peer_addresses,
            default_rpc_port,
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
            token_max_uri_len,
            token_max_dec_count,
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
        let genesis_id = genesis_block.get_id();

        let height_checkpoint_data = {
            if let Some(checkpoints) = checkpoints {
                Checkpoints::new(checkpoints, genesis_id)
            } else {
                match chain_type {
                    ChainType::Mainnet => {
                        Checkpoints::new_static(&MAINNET_CHECKPOINTS, &genesis_id)
                    }
                    ChainType::Testnet => {
                        Checkpoints::new_static(&TESTNET_CHECKPOINTS, &genesis_id)
                    }
                    ChainType::Regtest | ChainType::Signet => {
                        Checkpoints::new(BTreeMap::new(), genesis_id)
                    }
                }
            }
            // Note: this can only panic on genesis mismatch.
            .expect("checkpoints creation must succeed")
        };

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
            default_rpc_port,
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
            token_max_uri_len,
            token_max_dec_count,
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
    builder_method!(magic_bytes: MagicBytes);
    builder_method!(p2p_port: u16);
    builder_method!(dns_seeds: Vec<&'static str>);
    builder_method!(predefined_peer_addresses: Vec<SocketAddr>);
    builder_method!(max_future_block_time_offset: Option<Duration>);
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
    builder_method!(data_deposit_max_size: Option<usize>);
    builder_method!(min_stake_pool_pledge: Amount);

    pub fn checkpoints(mut self, checkpoints: BTreeMap<BlockHeight, Id<GenBlock>>) -> Self {
        self.checkpoints = Some(checkpoints);
        self
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use randomness::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use crate::chain::config::{
        DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V1, DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
    };

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_max_future_block_offset(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        // Mainnet
        {
            let config = Builder::new(ChainType::Mainnet).build();

            let before_the_fork = BlockHeight::new(
                rng.gen_range(0..MAINNET_FORK_HEIGHT_1_HTLC_AND_ORDERS.into_int()),
            );
            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V1,
                config.max_future_block_time_offset(before_the_fork)
            );

            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
                config.max_future_block_time_offset(MAINNET_FORK_HEIGHT_1_HTLC_AND_ORDERS)
            );

            let after_the_fork = BlockHeight::new(
                rng.gen_range(MAINNET_FORK_HEIGHT_1_HTLC_AND_ORDERS.into_int()..u64::MAX),
            );
            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
                config.max_future_block_time_offset(after_the_fork)
            );
        }

        // Testnet
        {
            let config = Builder::new(ChainType::Testnet).build();

            let before_the_fork = BlockHeight::new(
                rng.gen_range(0..TESTNET_FORK_HEIGHT_3_HTLC_AND_DATA_DEPOSIT_FEE.into_int()),
            );
            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V1,
                config.max_future_block_time_offset(before_the_fork)
            );

            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
                config
                    .max_future_block_time_offset(TESTNET_FORK_HEIGHT_3_HTLC_AND_DATA_DEPOSIT_FEE)
            );

            let after_the_fork = BlockHeight::new(
                rng.gen_range(TESTNET_FORK_HEIGHT_3_HTLC_AND_DATA_DEPOSIT_FEE.into_int()..u64::MAX),
            );
            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
                config.max_future_block_time_offset(after_the_fork)
            );
        }

        // Regtest
        {
            let config = Builder::new(ChainType::Regtest).build();

            let height = BlockHeight::new(rng.gen::<u64>());
            assert_eq!(
                DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
                config.max_future_block_time_offset(height)
            );
        }

        // Custom
        {
            let custom_offset = Duration::from_secs(rng.gen::<u64>());
            let config = Builder::new(ChainType::Regtest)
                .max_future_block_time_offset(Some(custom_offset))
                .build();

            let height = BlockHeight::new(rng.gen::<u64>());
            assert_eq!(custom_offset, config.max_future_block_time_offset(height));
        }
    }

    #[test]
    fn chainstate_upgrades() {
        // Mainnet
        {
            let config = Builder::new(ChainType::Mainnet).build();

            assert_eq!(
                config.chainstate_upgrades(),
                &NetUpgrades::initialize(vec![
                    (
                        BlockHeight::new(0),
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V0,
                            ChangeTokenMetadataUriActivated::No,
                            FrozenTokensValidationVersion::V0,
                            HtlcActivated::No,
                            OrdersActivated::No,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        MAINNET_FORK_HEIGHT_1_HTLC_AND_ORDERS,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V1,
                            ChangeTokenMetadataUriActivated::Yes,
                            FrozenTokensValidationVersion::V1,
                            HtlcActivated::Yes,
                            OrdersActivated::Yes,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        MAINNET_FORK_HEIGHT_2_ORDERS_V1_AND_STAKER_DESTINATION_UPDATE_PROHIBITION,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V1,
                            ChangeTokenMetadataUriActivated::Yes,
                            FrozenTokensValidationVersion::V1,
                            HtlcActivated::Yes,
                            OrdersActivated::Yes,
                            OrdersVersion::V1,
                            StakerDestinationUpdateForbidden::Yes,
                            TokenIdGenerationVersion::V1,
                        ),
                    ),
                ])
                .unwrap()
            );
        }

        // Testnet
        {
            let config = Builder::new(ChainType::Testnet).build();

            assert_eq!(
                config.chainstate_upgrades(),
                &NetUpgrades::initialize(vec![
                    (
                        BlockHeight::new(0),
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V0,
                            RewardDistributionVersion::V0,
                            TokensFeeVersion::V0,
                            DataDepositFeeVersion::V0,
                            ChangeTokenMetadataUriActivated::No,
                            FrozenTokensValidationVersion::V0,
                            HtlcActivated::No,
                            OrdersActivated::No,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_FORK_HEIGHT_1_TOKENS_V1_AND_CONSENSUS_UPGRADE,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V0,
                            TokensFeeVersion::V0,
                            DataDepositFeeVersion::V0,
                            ChangeTokenMetadataUriActivated::No,
                            FrozenTokensValidationVersion::V0,
                            HtlcActivated::No,
                            OrdersActivated::No,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_FORK_HEIGHT_2_STAKER_REWARD_AND_TOKENS_FEE,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V0,
                            ChangeTokenMetadataUriActivated::No,
                            FrozenTokensValidationVersion::V0,
                            HtlcActivated::No,
                            OrdersActivated::No,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_FORK_HEIGHT_3_HTLC_AND_DATA_DEPOSIT_FEE,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V1,
                            ChangeTokenMetadataUriActivated::Yes,
                            FrozenTokensValidationVersion::V0,
                            HtlcActivated::Yes,
                            OrdersActivated::No,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_FORK_HEIGHT_4_ORDERS,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V1,
                            ChangeTokenMetadataUriActivated::Yes,
                            FrozenTokensValidationVersion::V1,
                            HtlcActivated::Yes,
                            OrdersActivated::Yes,
                            OrdersVersion::V0,
                            StakerDestinationUpdateForbidden::No,
                            TokenIdGenerationVersion::V0,
                        ),
                    ),
                    (
                        TESTNET_FORK_HEIGHT_5_ORDERS_V1_AND_STAKER_DESTINATION_UPDATE_PROHIBITION,
                        ChainstateUpgrade::new(
                            TokenIssuanceVersion::V1,
                            RewardDistributionVersion::V1,
                            TokensFeeVersion::V1,
                            DataDepositFeeVersion::V1,
                            ChangeTokenMetadataUriActivated::Yes,
                            FrozenTokensValidationVersion::V1,
                            HtlcActivated::Yes,
                            OrdersActivated::Yes,
                            OrdersVersion::V1,
                            StakerDestinationUpdateForbidden::Yes,
                            TokenIdGenerationVersion::V1,
                        ),
                    ),
                ])
                .unwrap()
            );
        }
    }
}
