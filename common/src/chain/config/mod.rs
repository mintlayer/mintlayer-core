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

mod builder;
mod checkpoints;
pub mod checkpoints_data;
pub mod emission_schedule;
pub mod regtest;
pub mod regtest_options;

use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    num::NonZeroU64,
    sync::Arc,
    time::Duration,
};

use hex::FromHex;
use serialization::{Decode, Encode};

use crypto::{
    key::{
        hdkd::{child_number::ChildNumber, u31::U31},
        PublicKey,
    },
    vrf::VRFPublicKey,
};
use strum::EnumIter;
use utils::const_nz_u64;

use crate::{
    chain::{
        block::timestamp::BlockTimestamp, transaction::Destination, upgrades::NetUpgrades,
        GenBlock, Genesis, PoWChainConfig, TxOutput,
    },
    primitives::{
        id::{Id, Idable, WithId},
        per_thousand::PerThousand,
        semver::SemVer,
        Amount, BlockCount, BlockDistance, BlockHeight, H256,
    },
};

use super::{
    output_value::OutputValue, stakelock::StakePoolData, ChainstateUpgrade,
    ChangeTokenMetadataUriActivated, ConsensusUpgrade, DataDepositFeeVersion, DestinationTag,
    FrozenTokensValidationVersion, HtlcActivated, OrdersActivated, OrdersVersion,
    RequiredConsensus, RewardDistributionVersion, StakerDestinationUpdateForbidden,
    TokenIdGenerationVersion, TokenIssuanceVersion, TokensFeeVersion,
};

use self::{
    checkpoints::Checkpoints,
    emission_schedule::{CoinUnit, DEFAULT_INITIAL_MINT},
};

pub use builder::Builder;
pub use emission_schedule::{EmissionSchedule, EmissionScheduleFn, EmissionScheduleTabular};

const DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V1: Duration = Duration::from_secs(120);
const DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2: Duration = Duration::from_secs(30);
const DEFAULT_TARGET_BLOCK_SPACING: Duration = Duration::from_secs(120);

const DEFAULT_EPOCH_LENGTH: NonZeroU64 =
    const_nz_u64!((5 * 24 * 60 * 60) / DEFAULT_TARGET_BLOCK_SPACING.as_secs());
const DEFAULT_SEALED_EPOCH_DISTANCE_FROM_TIP: usize = 2;

const DEFAULT_MAX_DEPTH_FOR_REORG: BlockDistance = BlockDistance::new(1000);

pub const BIP44_PATH: ChildNumber = ChildNumber::from_hardened(U31::from_u32_with_msb(44).0);
pub const MINTLAYER_COIN_TYPE: ChildNumber =
    ChildNumber::from_hardened(U31::from_u32_with_msb(0x4D4C).0);
pub const MINTLAYER_COIN_TYPE_TEST: ChildNumber =
    ChildNumber::from_hardened(U31::from_u32_with_msb(0x01).0);

pub type EpochIndex = u64;

#[derive(PartialEq, Eq, Copy, Clone, Encode, Decode)]
#[repr(transparent)]
pub struct MagicBytes([u8; 4]);

impl MagicBytes {
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub const fn bytes(&self) -> [u8; 4] {
        self.0
    }
}

impl Display for MagicBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(chain_type) = ChainType::from_magic_bytes(*self) {
            write!(f, "{}", chain_type.name())
        } else {
            write!(f, "{:?}", self)
        }
    }
}

impl Debug for MagicBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MagicBytes(0x")?;
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, EnumIter)]
pub enum ChainType {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl ChainType {
    pub const MAINNET_MAGIC_BYTES: MagicBytes = MagicBytes::new([0xB0, 0x07, 0x5F, 0xA0]);
    pub const TESTNET_MAGIC_BYTES: MagicBytes = MagicBytes::new([0x2b, 0x7e, 0x19, 0xf8]);
    pub const REGTEST_MAGIC_BYTES: MagicBytes = MagicBytes::new([0xaa, 0xbb, 0xcc, 0xdd]);
    pub const SIGNET_MAGIC_BYTES: MagicBytes = MagicBytes::new([0xf3, 0xf7, 0x7b, 0x45]);

    pub const fn name(&self) -> &'static str {
        match self {
            ChainType::Mainnet => "mainnet",
            ChainType::Testnet => "testnet",
            ChainType::Regtest => "regtest",
            ChainType::Signet => "signet",
        }
    }

    const fn coin_ticker(&self) -> &'static str {
        match self {
            ChainType::Mainnet => "ML",
            ChainType::Testnet => "TML",
            ChainType::Regtest => "RML",
            ChainType::Signet => "SML",
        }
    }

    const fn magic_bytes(&self) -> MagicBytes {
        match self {
            ChainType::Mainnet => Self::MAINNET_MAGIC_BYTES,
            ChainType::Testnet => Self::TESTNET_MAGIC_BYTES,
            ChainType::Regtest => Self::REGTEST_MAGIC_BYTES,
            ChainType::Signet => Self::SIGNET_MAGIC_BYTES,
        }
    }

    pub fn from_magic_bytes(magic_bytes: MagicBytes) -> Option<Self> {
        match magic_bytes {
            Self::MAINNET_MAGIC_BYTES => Some(ChainType::Mainnet),
            Self::TESTNET_MAGIC_BYTES => Some(ChainType::Testnet),
            Self::REGTEST_MAGIC_BYTES => Some(ChainType::Regtest),
            Self::SIGNET_MAGIC_BYTES => Some(ChainType::Signet),
            _ => None,
        }
    }

    const fn default_p2p_port(&self) -> u16 {
        match self {
            ChainType::Mainnet => 3031,
            ChainType::Testnet => 13031,
            ChainType::Regtest => 23031,
            ChainType::Signet => 33031,
        }
    }

    fn dns_seeds(&self) -> Vec<&'static str> {
        match self {
            ChainType::Mainnet => vec!["seed.mintlayer.org", "seed2.mintlayer.org"],
            ChainType::Testnet => vec!["testnet-seed.mintlayer.org"],
            ChainType::Regtest => Vec::new(),
            ChainType::Signet => Vec::new(),
        }
    }

    fn predefined_peer_addresses(&self) -> Vec<SocketAddr> {
        match self {
            ChainType::Mainnet => {
                vec![
                    "51.159.232.144:3031".parse().expect("Cannot fail"),
                    "51.159.179.229:3031".parse().expect("Cannot fail"),
                    "151.115.35.206:3031".parse().expect("Cannot fail"),
                    "172.232.50.132:3031".parse().expect("Cannot fail"),
                    "103.3.61.21:3031".parse().expect("Cannot fail"),
                ]
            }
            ChainType::Testnet => {
                vec![
                    "51.15.103.154:13031".parse().expect("Cannot fail"),
                    "51.15.59.248:13031".parse().expect("Cannot fail"),
                ]
            }
            ChainType::Regtest => Vec::new(),
            ChainType::Signet => Vec::new(),
        }
    }

    const fn default_rpc_port(&self) -> u16 {
        match self {
            ChainType::Mainnet => 3030,
            ChainType::Testnet => 13030,
            ChainType::Regtest => 23030,
            ChainType::Signet => 33030,
        }
    }

    const fn default_bip44_coin_type(&self) -> ChildNumber {
        match self {
            ChainType::Mainnet => MINTLAYER_COIN_TYPE,
            ChainType::Testnet | ChainType::Regtest | ChainType::Signet => MINTLAYER_COIN_TYPE_TEST,
        }
    }
}

fn address_prefix(chain_type: ChainType, destination_tag: DestinationTag) -> &'static str {
    match chain_type {
        ChainType::Mainnet => match destination_tag {
            DestinationTag::AnyoneCanSpend => "mxanyonecanspend",
            DestinationTag::PublicKeyHash => "mtc",
            DestinationTag::PublicKey => "mptc",
            DestinationTag::ScriptHash => "mstc",
            DestinationTag::ClassicMultisig => "mmtc",
        },
        ChainType::Testnet => match destination_tag {
            DestinationTag::AnyoneCanSpend => "txanyonecanspend",
            DestinationTag::PublicKeyHash => "tmt",
            DestinationTag::PublicKey => "tpmt",
            DestinationTag::ScriptHash => "tstc",
            DestinationTag::ClassicMultisig => "tmtc",
        },
        ChainType::Regtest => match destination_tag {
            DestinationTag::AnyoneCanSpend => "rxanyonecanspend",
            DestinationTag::PublicKeyHash => "rmt",
            DestinationTag::PublicKey => "rpmt",
            DestinationTag::ScriptHash => "rstc",
            DestinationTag::ClassicMultisig => "rmtc",
        },
        ChainType::Signet => match destination_tag {
            DestinationTag::AnyoneCanSpend => "sxanyonecanspend",
            DestinationTag::PublicKeyHash => "smt",
            DestinationTag::PublicKey => "spmt",
            DestinationTag::ScriptHash => "sstc",
            DestinationTag::ClassicMultisig => "smtc",
        },
    }
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    chain_type: ChainType,
    bip44_coin_type: ChildNumber,
    height_checkpoint_data: Checkpoints,
    consensus_upgrades: NetUpgrades<ConsensusUpgrade>,
    chainstate_upgrades: NetUpgrades<ChainstateUpgrade>,
    magic_bytes: MagicBytes,
    p2p_port: u16,
    dns_seeds: Vec<&'static str>,
    predefined_peer_addresses: Vec<SocketAddr>,
    default_rpc_port: u16,
    genesis_block: Arc<WithId<Genesis>>,
    max_future_block_time_offset: Option<Duration>,
    software_version: SemVer,
    target_block_spacing: Duration,
    coin_decimals: u8,
    coin_ticker: &'static str,
    emission_schedule: EmissionSchedule,
    final_supply: Option<CoinUnit>, // `None` if the supply increases indefinitely
    max_block_header_size: usize,
    max_block_size_with_standard_txs: usize,
    max_block_size_with_smart_contracts: usize,
    data_in_no_signature_witness_max_size: usize,
    data_in_no_signature_witness_allowed: bool,
    max_depth_for_reorg: BlockDistance,
    pow_chain_config: PoWChainConfig,
    epoch_length: NonZeroU64,
    sealed_epoch_distance_from_tip: usize,
    initial_randomness: H256,
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

impl ChainConfig {
    /// Bech32m addresses in this chain will use this prefix
    #[must_use]
    pub fn destination_address_prefix(&self, destination_tag: DestinationTag) -> &'static str {
        address_prefix(self.chain_type, destination_tag)
    }

    #[must_use]
    pub fn pool_id_address_prefix(&self) -> &'static str {
        match self.chain_type {
            ChainType::Mainnet => "mpool",
            ChainType::Testnet => "tpool",
            ChainType::Regtest => "rpool",
            ChainType::Signet => "spool",
        }
    }

    #[must_use]
    pub fn delegation_id_address_prefix(&self) -> &'static str {
        match self.chain_type {
            ChainType::Mainnet => "mdelg",
            ChainType::Testnet => "tdelg",
            ChainType::Regtest => "rdelg",
            ChainType::Signet => "sdelg",
        }
    }

    #[must_use]
    pub fn token_id_address_prefix(&self) -> &'static str {
        match self.chain_type {
            ChainType::Mainnet => "mmltk",
            ChainType::Testnet => "tmltk",
            ChainType::Regtest => "rmltk",
            ChainType::Signet => "smltk",
        }
    }

    #[must_use]
    pub fn order_id_address_prefix(&self) -> &'static str {
        match self.chain_type {
            ChainType::Mainnet => "mordr",
            ChainType::Testnet => "tordr",
            ChainType::Regtest => "rordr",
            ChainType::Signet => "sordr",
        }
    }

    #[must_use]
    pub fn vrf_public_key_address_prefix(&self) -> &'static str {
        match self.chain_type {
            ChainType::Mainnet => "mvrfpk",
            ChainType::Testnet => "tvrfpk",
            ChainType::Regtest => "rvrfpk",
            ChainType::Signet => "svrfpk",
        }
    }

    /// The BIP44 coin type for this chain
    #[must_use]
    pub fn bip44_coin_type(&self) -> ChildNumber {
        self.bip44_coin_type
    }

    /// The genesis block id of the chain
    #[must_use]
    pub fn genesis_block_id(&self) -> Id<GenBlock> {
        self.genesis_block.get_id().into()
    }

    /// The genesis block of the chain
    #[must_use]
    pub fn genesis_block(&self) -> &Arc<WithId<Genesis>> {
        &self.genesis_block
    }

    /// The bytes that are used to prefix p2p communication to uniquely identify this chain
    #[must_use]
    pub fn magic_bytes(&self) -> &MagicBytes {
        &self.magic_bytes
    }

    /// The port that the p2p server will listen on
    #[must_use]
    pub fn p2p_port(&self) -> u16 {
        self.p2p_port
    }

    /// The list of addresses of dns seeds.
    #[must_use]
    pub fn dns_seeds(&self) -> &[&str] {
        &self.dns_seeds
    }

    /// The list of predefined peer addresses.
    #[must_use]
    pub fn predefined_peer_addresses(&self) -> &[SocketAddr] {
        &self.predefined_peer_addresses
    }

    /// The default port that the rpc server will listen on
    #[must_use]
    pub fn default_rpc_port(&self) -> u16 {
        self.default_rpc_port
    }

    /// The current version of this software.
    #[must_use]
    pub fn software_version(&self) -> &SemVer {
        &self.software_version
    }

    /// The chain of this config (mainnet, testnet, regtest, etc...)
    #[must_use]
    pub fn chain_type(&self) -> &ChainType {
        &self.chain_type
    }

    /// The mechanism by which we define changes in the chain, including consensus and other upgrades/forks
    #[must_use]
    pub fn consensus_upgrades(&self) -> &NetUpgrades<ConsensusUpgrade> {
        &self.consensus_upgrades
    }

    /// The mechanism by which we define changes in the chain, including consensus and other upgrades/forks
    #[must_use]
    pub fn chainstate_upgrades(&self) -> &NetUpgrades<ChainstateUpgrade> {
        &self.chainstate_upgrades
    }

    /// Checkpoints enforced by the chain, as in, a block id vs height that must be satisfied
    #[must_use]
    pub fn height_checkpoints(&self) -> &Checkpoints {
        &self.height_checkpoint_data
    }

    /// The target time-distance between blocks
    #[must_use]
    pub fn target_block_spacing(&self) -> Duration {
        self.target_block_spacing
    }

    /// Block subsidy vs block height table
    #[must_use]
    pub fn emission_schedule(&self) -> &EmissionSchedule {
        &self.emission_schedule
    }

    /// The number of decimal places in the smallest unit of the coin
    #[must_use]
    pub fn coin_decimals(&self) -> u8 {
        self.coin_decimals
    }

    /// The coin ticker
    #[must_use]
    pub fn coin_ticker(&self) -> &'static str {
        self.coin_ticker
    }

    /// The maximum size of data attached to NoSignature witness
    #[must_use]
    pub fn data_in_no_signature_witness_max_size(&self) -> usize {
        self.data_in_no_signature_witness_max_size
    }

    /// Whether one is allowed to attach data to NoSignature witness
    #[must_use]
    pub fn data_in_no_signature_witness_allowed(&self) -> bool {
        self.data_in_no_signature_witness_allowed
    }

    /// The maximum offset of time from the current time the timestamp of a new block can be
    #[must_use]
    pub fn max_future_block_time_offset(&self, height: BlockHeight) -> Duration {
        self.max_future_block_time_offset.unwrap_or_else(|| {
            match self.as_ref().chainstate_upgrades().version_at_height(height).1.htlc_activated() {
                // Change of the offset has nothing to do with htlc, they just come in the same upgrade height
                HtlcActivated::Yes => DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V2,
                HtlcActivated::No => DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET_V1,
            }
        })
    }

    /// Length of an epoch in blocks
    #[must_use]
    pub fn epoch_length(&self) -> NonZeroU64 {
        self.epoch_length
    }

    /// Distance from the tip of the chain to the sealed state in epochs
    #[must_use]
    pub fn sealed_epoch_distance_from_tip(&self) -> usize {
        self.sealed_epoch_distance_from_tip
    }

    /// Given a block height, return the block subsidy at that height according to the emission schedule
    pub fn block_subsidy_at_height(&self, height: &BlockHeight) -> Amount {
        self.emission_schedule().subsidy(*height).to_amount_atoms()
    }

    /// The maximum size of a block header
    #[must_use]
    pub fn max_block_header_size(&self) -> usize {
        self.max_block_header_size
    }

    /// The maximum size of a block that uses standard transactions
    #[must_use]
    pub fn max_block_size_from_std_scripts(&self) -> usize {
        self.max_block_size_with_standard_txs
    }

    /// The maximum size of a block that uses smart contracts
    #[must_use]
    pub fn max_block_size_from_smart_contracts(&self) -> usize {
        self.max_block_size_with_smart_contracts
    }

    /// The maximum size of any transaction submitted to the node for the mempool
    pub fn max_tx_size_for_mempool(&self) -> usize {
        // Reserve some space in the block for the data it needs to store beyond the transaction
        // data itself, namely the transaction count due to how sequences of elements are encoded.
        const BLOCK_DATA_OVERHEAD: usize = 1000;

        let max_block_size = std::cmp::min(
            self.max_block_size_from_std_scripts(),
            self.max_block_size_from_smart_contracts(),
        );

        max_block_size.saturating_sub(BLOCK_DATA_OVERHEAD)
    }

    /// The initial randomness used for the first few epochs until sealed blocks kick in
    #[must_use]
    pub fn initial_randomness(&self) -> H256 {
        self.initial_randomness
    }

    /// Given a block height, return the epoch index at that height
    #[must_use]
    pub fn epoch_index_from_height(&self, height: &BlockHeight) -> EpochIndex {
        let height: u64 = (*height).into();
        height / self.epoch_length
    }

    /// Given a block height, return true if the block is the last block in that epoch
    #[must_use]
    pub fn is_last_block_in_epoch(&self, height: &BlockHeight) -> bool {
        let next_height: u64 = height.next_height().into();
        next_height % self.epoch_length() == 0
    }

    /// Given a block height, return true if a seal operation should run at this height
    #[must_use]
    pub fn is_due_for_epoch_seal(&self, height: &BlockHeight) -> bool {
        let sealed_epoch_distance_from_tip = self.sealed_epoch_distance_from_tip() as u64;
        let current_epoch_index = self.epoch_index_from_height(height);

        self.is_last_block_in_epoch(height) && current_epoch_index >= sealed_epoch_distance_from_tip
    }

    #[must_use]
    pub fn sealed_epoch_index(&self, height: &BlockHeight) -> Option<EpochIndex> {
        let current_epoch_index = self.epoch_index_from_height(height);
        let sealed_epoch_distance_from_tip = self.sealed_epoch_distance_from_tip() as u64;

        if self.is_last_block_in_epoch(height) {
            current_epoch_index.checked_sub(sealed_epoch_distance_from_tip)
        } else {
            // If an epoch is not full it must be taken into account increasing the distance to the sealed epoch
            current_epoch_index.checked_sub(sealed_epoch_distance_from_tip + 1)
        }
    }

    /// The maximum allowed size for data deposited in DataDeposit output
    pub fn data_deposit_max_size(&self, height: BlockHeight) -> usize {
        self.data_deposit_max_size.unwrap_or_else(|| {
            match self.chainstate_upgrades.version_at_height(height).1.data_deposit_fee_version() {
                DataDepositFeeVersion::V0 => DATA_DEPOSIT_MAX_SIZE_V0,
                DataDepositFeeVersion::V1 => DATA_DEPOSIT_MAX_SIZE_V1,
            }
        })
    }

    /// The fee for depositing data
    pub fn data_deposit_fee(&self, height: BlockHeight) -> Amount {
        match self.chainstate_upgrades.version_at_height(height).1.data_deposit_fee_version() {
            DataDepositFeeVersion::V0 => DATA_DEPOSIT_FEE_V0,
            DataDepositFeeVersion::V1 => DATA_DEPOSIT_FEE_V1,
        }
    }

    /// The fee for issuing a fungible token
    pub fn fungible_token_issuance_fee(&self) -> Amount {
        FUNGIBLE_TOKEN_ISSUANCE_FEE
    }

    /// The fee for issuing a NFT
    pub fn nft_issuance_fee(&self, height: BlockHeight) -> Amount {
        let fee_version = self.chainstate_upgrades.version_at_height(height).1.tokens_fee_version();
        match fee_version {
            TokensFeeVersion::V0 => NFT_ISSUANCE_FEE_V0,
            TokensFeeVersion::V1 => NFT_ISSUANCE_FEE_V1,
        }
    }

    /// The fee for changing supply of a token
    pub fn token_supply_change_fee(&self, height: BlockHeight) -> Amount {
        let fee_version = self.chainstate_upgrades.version_at_height(height).1.tokens_fee_version();
        match fee_version {
            TokensFeeVersion::V0 => TOKEN_SUPPLY_CHANGE_FEE_V0,
            TokensFeeVersion::V1 => TOKEN_SUPPLY_CHANGE_FEE_V1,
        }
    }

    /// The fee for freezing/unfreezing a token
    pub fn token_freeze_fee(&self, height: BlockHeight) -> Amount {
        let fee_version = self.chainstate_upgrades.version_at_height(height).1.tokens_fee_version();
        match fee_version {
            TokensFeeVersion::V0 => TOKEN_FREEZE_FEE_V0,
            TokensFeeVersion::V1 => TOKEN_FREEZE_FEE_V1,
        }
    }

    /// The fee for changing authority of a token
    pub fn token_change_authority_fee(&self, height: BlockHeight) -> Amount {
        let fee_version = self.chainstate_upgrades.version_at_height(height).1.tokens_fee_version();
        match fee_version {
            TokensFeeVersion::V0 => TOKEN_CHANGE_AUTHORITY_FEE_V0,
            TokensFeeVersion::V1 => TOKEN_CHANGE_AUTHORITY_FEE_V1,
        }
    }

    /// The fee for changing token metadata uri
    pub fn token_change_metadata_uri_fee(&self) -> Amount {
        TOKEN_CHANGE_METADATA_URI_FEE
    }

    /// The maximum length of a URI contained in a token
    #[must_use]
    pub fn token_max_uri_len(&self) -> usize {
        self.token_max_uri_len
    }

    /// The maximum number of decimals in a token (not coins, to be accurate, just for tokens)
    #[must_use]
    pub fn token_max_dec_count(&self) -> u8 {
        self.token_max_dec_count
    }

    /// The maximum length of a ticker of a token
    #[must_use]
    pub fn token_max_ticker_len(&self) -> usize {
        TOKEN_MAX_TICKER_LEN
    }

    /// The maximum length of a description of a token
    #[must_use]
    pub fn token_max_description_len(&self) -> usize {
        self.token_max_description_len
    }

    #[must_use]
    pub fn max_depth_for_reorg(&self) -> BlockDistance {
        self.max_depth_for_reorg
    }

    /// The maximum length of a name of a token
    #[must_use]
    pub fn token_max_name_len(&self) -> usize {
        self.token_max_name_len
    }

    /// The minimum length of a hash of a token
    #[must_use]
    pub fn min_hash_len(&self) -> usize {
        self.token_min_hash_len
    }

    /// The maximum length of a hash of a token
    #[must_use]
    pub fn max_hash_len(&self) -> usize {
        self.token_max_hash_len
    }

    /// The minimum number of blocks required for a block reward to mature
    #[must_use]
    pub fn empty_consensus_reward_maturity_block_count(&self) -> BlockCount {
        self.empty_consensus_reward_maturity_block_count
    }

    // TODO: this should be part of net-upgrades. There should be no canonical definition of PoW for any chain config
    #[must_use]
    pub fn get_proof_of_work_config(&self) -> &PoWChainConfig {
        &self.pow_chain_config
    }

    /// The minimum number of blocks required to be able to spend a utxo coming from a decommissioned pool
    #[must_use]
    pub fn staking_pool_spend_maturity_block_count(&self, block_height: BlockHeight) -> BlockCount {
        match self.consensus_upgrades.consensus_status(block_height) {
            RequiredConsensus::IgnoreConsensus | RequiredConsensus::PoW(_) => {
                self.empty_consensus_reward_maturity_block_count
            }
            RequiredConsensus::PoS(status) => {
                status.get_chain_config().staking_pool_spend_maturity_block_count()
            }
        }
    }

    /// The maximum number of public keys that can go into a classical multisig
    #[must_use]
    pub fn max_classic_multisig_public_keys_count(&self) -> usize {
        self.max_classic_multisig_public_keys_count
    }

    /// Min pledge required to create a stake pool
    pub fn min_stake_pool_pledge(&self) -> Amount {
        self.min_stake_pool_pledge
    }

    pub fn final_supply(&self) -> Option<CoinUnit> {
        self.final_supply
    }
}

impl AsRef<ChainConfig> for ChainConfig {
    fn as_ref(&self) -> &ChainConfig {
        self
    }
}

const MAX_BLOCK_HEADER_SIZE: usize = 1024;
const MAX_BLOCK_TXS_SIZE: usize = 1_048_576;
const MAX_BLOCK_CONTRACTS_SIZE: usize = 1_048_576;
const TX_DATA_IN_NO_SIG_WITNESS_MAX_SIZE: usize = 128;

const FUNGIBLE_TOKEN_ISSUANCE_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();

const NFT_ISSUANCE_FEE_V0: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const NFT_ISSUANCE_FEE_V1: Amount = CoinUnit::from_coins(5).to_amount_atoms();

const TOKEN_SUPPLY_CHANGE_FEE_V0: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_SUPPLY_CHANGE_FEE_V1: Amount = CoinUnit::from_coins(50).to_amount_atoms();

const TOKEN_FREEZE_FEE_V0: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_FREEZE_FEE_V1: Amount = CoinUnit::from_coins(50).to_amount_atoms();

const TOKEN_CHANGE_AUTHORITY_FEE_V0: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_CHANGE_AUTHORITY_FEE_V1: Amount = CoinUnit::from_coins(20).to_amount_atoms();

const TOKEN_CHANGE_METADATA_URI_FEE: Amount = CoinUnit::from_coins(20).to_amount_atoms();

const DATA_DEPOSIT_MAX_SIZE_V0: usize = 128;
const DATA_DEPOSIT_MAX_SIZE_V1: usize = 384;
const DATA_DEPOSIT_FEE_V0: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const DATA_DEPOSIT_FEE_V1: Amount = CoinUnit::from_coins(20).to_amount_atoms();

const TOKEN_MAX_DEC_COUNT: u8 = 18;
const TOKEN_MAX_TICKER_LEN: usize = 12;
const TOKEN_MIN_HASH_LEN: usize = 4;
const TOKEN_MAX_HASH_LEN: usize = 32;
const TOKEN_MAX_NAME_LEN: usize = 10;
const TOKEN_MAX_DESCRIPTION_LEN: usize = 100;
const TOKEN_MAX_URI_LEN: usize = 1024;
const MAX_CLASSIC_MULTISIG_PUBLIC_KEYS_COUNT: usize = 32;
const MIN_STAKE_POOL_PLEDGE: Amount = Amount::from_atoms(40_000 * CoinUnit::ATOMS_PER_COIN);

fn decode_hex<T: serialization::DecodeAll>(hex: &str) -> T {
    let bytes = Vec::from_hex(hex).expect("Hex decoding shouldn't fail");
    <T as serialization::DecodeAll>::decode_all(&mut bytes.as_slice())
        .expect("Decoding shouldn't fail")
}

fn create_mainnet_genesis() -> Genesis {
    let genesis_message = "In a free-market economy, every individual should be free to produce, \
        store, exchange assets and access financial markets without any constraints;
        6777eb86f0564cae116428628fa806617f665c8779cd871f5026794b8161989e; \
        827800 00000000000000000003b3f40a3c6f52dfdd60c0fb092acb97d30658b25f053c"
        .to_string();

    let decommission_dest = decode_hex::<Destination>("01add92ee6e5b953e13c112260a7daf7f8f1c4ffd2");

    let staker_pub_key = decode_hex::<PublicKey>(
        "00026c8621e9b0cbe2a9fd6ed86a45969191e45dd8c59b8e1a55bf0983f56a0ecc6c",
    );

    let vrf_pub_key = decode_hex::<VRFPublicKey>(
        "006ed44aeacbc2e2a87edd4862863b0c3dec29a33cf6e3edd2049545d547dedb76",
    );

    let initial_pool_amount = CoinUnit::from_coins(100_000).to_amount_atoms();
    let mint_output_amount = (DEFAULT_INITIAL_MINT - initial_pool_amount).expect("must be valid");

    let genesis_mint_pubkeyhash_hex_encoded = "017b5de99b602eeaae0fe02615eb624169edec1f92";
    let genesis_mint_destination = decode_hex::<Destination>(genesis_mint_pubkeyhash_hex_encoded);

    let mint_output = TxOutput::Transfer(
        OutputValue::Coin(mint_output_amount),
        genesis_mint_destination,
    );

    let initial_pool = TxOutput::CreateStakePool(
        H256::zero().into(),
        Box::new(StakePoolData::new(
            initial_pool_amount,
            Destination::PublicKey(staker_pub_key),
            vrf_pub_key,
            decommission_dest,
            PerThousand::new(50).expect("must be valid"),
            Amount::ZERO,
        )),
    );

    Genesis::new(
        genesis_message,
        BlockTimestamp::from_int_seconds(1706468400),
        vec![mint_output, initial_pool],
    )
}

fn create_testnet_genesis() -> Genesis {
    // We add 3_300_000_000 coins to the genesis mint account since it's just for testing. Nothing else changes.
    let extra_testnet_mint = Amount::from_atoms(3_300_000_000 * CoinUnit::ATOMS_PER_COIN);
    let total_amount = (extra_testnet_mint + DEFAULT_INITIAL_MINT).expect("Cannot fail");
    let initial_pool_amount = MIN_STAKE_POOL_PLEDGE;
    let mint_output_amount = (total_amount - initial_pool_amount).expect("must be valid");

    let genesis_message = String::new();

    // To get these values, use the `newpublickey` and `getvrfpublickey` wallet-cli commands

    let genesis_mint_destination = decode_hex::<PublicKey>(
        "0003e9d79eb6487c28dad9679461faa1ffcdbc52a10033e1ad625101a97db1ba8edd",
    );

    let mint_output = TxOutput::Transfer(
        OutputValue::Coin(mint_output_amount),
        Destination::PublicKey(genesis_mint_destination),
    );

    let decommission_pub_key = decode_hex::<PublicKey>(
        "000290acefad24844c5ac7ac2fef3e4df86a089f37df8abf39c6c41a3517287855f2",
    );
    let staker_pub_key = decode_hex::<PublicKey>(
        "00039d905e919a49d42af16daf8719bde9a8745624affe299ddc7c5ce8091b60e41e",
    );

    let vrf_pub_key = decode_hex::<VRFPublicKey>(
        "002895247c82f904ce01b13c89f17fecb7b670b4f3271a7f0459ad32056734757b",
    );

    let initial_pool = TxOutput::CreateStakePool(
        H256::zero().into(),
        Box::new(StakePoolData::new(
            initial_pool_amount,
            Destination::PublicKey(staker_pub_key),
            vrf_pub_key,
            Destination::PublicKey(decommission_pub_key),
            PerThousand::new(1000).expect("must be valid"),
            Amount::ZERO,
        )),
    );

    Genesis::new(
        genesis_message,
        BlockTimestamp::from_int_seconds(1690620112),
        vec![mint_output, initial_pool],
    )
}

fn create_unit_test_genesis(premine_destination: Destination) -> Genesis {
    let genesis_message = String::new();

    let output = TxOutput::Transfer(OutputValue::Coin(DEFAULT_INITIAL_MINT), premine_destination);

    Genesis::new(
        genesis_message,
        BlockTimestamp::from_int_seconds(1639975460),
        vec![output],
    )
}

pub fn create_mainnet() -> ChainConfig {
    Builder::new(ChainType::Mainnet).build()
}

pub fn create_testnet() -> ChainConfig {
    Builder::new(ChainType::Testnet).build()
}

pub fn create_regtest() -> ChainConfig {
    Builder::new(ChainType::Regtest).build()
}

pub fn create_unit_test_config_builder() -> Builder {
    Builder::new(ChainType::Regtest)
        .consensus_upgrades(NetUpgrades::unit_tests())
        .chainstate_upgrades(
            NetUpgrades::initialize(vec![(
                BlockHeight::zero(),
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
            )])
            .expect("cannot fail"),
        )
        .genesis_unittest(Destination::AnyoneCanSpend)
        .dns_seeds(vec![])
}

pub fn create_unit_test_config() -> ChainConfig {
    create_unit_test_config_builder().build()
}

/// This function ensure that IgnoreConsensus will never be used in anything other than regtest
pub fn assert_no_ignore_consensus_in_chain_config(chain_config: &ChainConfig) {
    match chain_config.chain_type() {
        ChainType::Regtest => {
            return;
        }
        ChainType::Mainnet | ChainType::Testnet | ChainType::Signet => {}
    }

    let upgrades = chain_config.consensus_upgrades();

    let all_upgrades = upgrades.all_upgrades();

    assert!(
        !all_upgrades.is_empty(),
        "Invalid chain config. There are no net-upgrades defined, not even for genesis."
    );

    assert!(
        all_upgrades.len() >= 2,
        "Invalid chain config. There must be at least 2 net-upgrades defined, one for genesis and one for the first block after genesis."
    );

    assert!(
        all_upgrades[0].0 == 0.into(),
        "Invalid chain config. The first net-upgrade must be at height 0"
    );

    assert!(
        upgrades.consensus_status(0.into()) == RequiredConsensus::IgnoreConsensus,
        "Invalid chain config. The genesis net-upgrade must be IgnoreConsensus"
    );

    assert!(
        upgrades.consensus_status(1.into()) != RequiredConsensus::IgnoreConsensus,
        "Invalid chain config. The net-upgrade at height 1 must not be IgnoreConsensus"
    );

    for upgrade in all_upgrades.iter().skip(1) {
        let upgrade_height = &upgrade.0;
        let upgrade_data = &upgrade.1;

        let consensus = upgrades.consensus_status(*upgrade_height);
        assert_ne!(
            RequiredConsensus::IgnoreConsensus,
            consensus,
            "Upgrade {:?} at height {} is ignoring consensus in net type {}. This is only allowed in regtest",
            upgrade_data,
            upgrade_height,
            chain_config.chain_type().name()
        )
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use strum::IntoEnumIterator as _;

    use crate::chain::config::checkpoints_data::{MAINNET_CHECKPOINTS, TESTNET_CHECKPOINTS};

    use super::*;

    #[test]
    fn mainnet_creation() {
        let config = create_mainnet();

        assert_eq!(2, config.consensus_upgrades.len());
        assert_eq!(config.chain_type(), &ChainType::Mainnet);
    }

    #[test]
    fn testnet_creation() {
        let config = create_testnet();

        assert_eq!(3, config.consensus_upgrades.len());
        assert_eq!(config.chain_type(), &ChainType::Testnet);
    }

    #[test]
    fn different_magic_bytes() {
        let config1 = Builder::new(ChainType::Regtest).build();
        let config2 = Builder::new(ChainType::Regtest)
            .magic_bytes(MagicBytes::new([1, 2, 3, 4]))
            .build();

        assert_ne!(config1.magic_bytes(), config2.magic_bytes());
    }

    #[test]
    fn chain_type_magic_bytes_correspondense() {
        for chain_type in ChainType::iter() {
            let magic_bytes = chain_type.magic_bytes();
            let chain_type_from_magic_bytes = ChainType::from_magic_bytes(magic_bytes);
            assert_eq!(chain_type_from_magic_bytes, Some(chain_type));
        }
    }

    #[test]
    fn magic_bytes_display() {
        assert_eq!(format!("{}", ChainType::Mainnet.magic_bytes()), "mainnet");
        assert_eq!(format!("{}", ChainType::Testnet.magic_bytes()), "testnet");
        assert_eq!(format!("{}", ChainType::Regtest.magic_bytes()), "regtest");
        assert_eq!(format!("{}", ChainType::Signet.magic_bytes()), "signet");
        assert_eq!(
            format!("{}", MagicBytes::new([0xAB, 0xCD, 0xEF, 0x12])),
            "MagicBytes(0xABCDEF12)"
        );
    }

    #[test]
    fn magic_bytes_debug() {
        assert_eq!(
            format!("{:?}", ChainType::Mainnet.magic_bytes()),
            "MagicBytes(0xB0075FA0)"
        );
        assert_eq!(
            format!("{:?}", ChainType::Testnet.magic_bytes()),
            "MagicBytes(0x2B7E19F8)"
        );
        assert_eq!(
            format!("{:?}", ChainType::Regtest.magic_bytes()),
            "MagicBytes(0xAABBCCDD)"
        );
        assert_eq!(
            format!("{:?}", ChainType::Signet.magic_bytes()),
            "MagicBytes(0xF3F77B45)"
        );
        assert_eq!(
            format!("{:?}", MagicBytes::new([0xAB, 0xCD, 0xEF, 0x12])),
            "MagicBytes(0xABCDEF12)"
        );
    }

    #[rstest]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(0), true)]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(1), true)]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(2), true)]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(3), true)]
    //----------------------------------------------------------------//
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(1), true)]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(2), true)]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(3), true)]
    //----------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(1), true)]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(2), false)]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(3), true)]
    //----------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(2), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(3), true)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(4), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(5), true)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(6), false)]
    //----------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(2), false)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(3), false)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(4), false)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(5), true)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(6), false)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(7), true)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(8), false)]
    fn is_due_for_epoch_seal(
        #[case] epoch_length: NonZeroU64,
        #[case] seal_to_tip_distance: usize,
        #[case] block_height: BlockHeight,
        #[case] expected: bool,
    ) {
        let config = Builder::test_chain()
            .epoch_length(epoch_length)
            .sealed_epoch_distance_from_tip(seal_to_tip_distance)
            .build();
        assert_eq!(expected, config.is_due_for_epoch_seal(&block_height));
    }

    #[rstest]
    #[case(NonZeroU64::new(1).unwrap(), BlockHeight::from(0), 0)]
    #[case(NonZeroU64::new(1).unwrap(), BlockHeight::from(1), 1)]
    #[case(NonZeroU64::new(1).unwrap(), BlockHeight::from(2), 2)]
    //---------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), BlockHeight::from(0), 0)]
    #[case(NonZeroU64::new(2).unwrap(), BlockHeight::from(1), 0)]
    #[case(NonZeroU64::new(2).unwrap(), BlockHeight::from(2), 1)]
    #[case(NonZeroU64::new(2).unwrap(), BlockHeight::from(3), 1)]
    //---------------------------------------------------------//
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(0), 0)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(1), 0)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(2), 0)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(3), 1)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(4), 1)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(5), 1)]
    fn epoch_index_from_height(
        #[case] epoch_length: NonZeroU64,
        #[case] block_height: BlockHeight,
        #[case] expected: EpochIndex,
    ) {
        let config = Builder::test_chain().epoch_length(epoch_length).build();
        assert_eq!(expected, config.epoch_index_from_height(&block_height));
    }

    #[rstest]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(0), Some(0))]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(1), Some(1))]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(2), Some(2))]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(3), Some(3))]
    #[case(NonZeroU64::new(1).unwrap(), 0, BlockHeight::from(4), Some(4))]
    //------------------------------------------------------------------//
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(0), None)]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(1), Some(0))]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(2), Some(1))]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(3), Some(2))]
    #[case(NonZeroU64::new(1).unwrap(), 1, BlockHeight::from(4), Some(3))]
    //------------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(0), None)]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(1), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(2), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(3), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(4), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(5), Some(2))]
    //------------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(0), None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(1), None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(2), None)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(3), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(4), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(5), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(6), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(7), Some(2))]
    //------------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(0), None)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(1), None)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(2), None)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(3), None)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(4), None)]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(5), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(6), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(7), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(8), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(9), Some(2))]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(10), Some(2))]
    #[case(NonZeroU64::new(2).unwrap(), 2, BlockHeight::from(11), Some(3))]
    //------------------------------------------------------------------//
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(0), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(1), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(2), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(3), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(4), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(5), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(6), None)]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(7), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(8), Some(0))]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(9), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(10), Some(1))]
    #[case(NonZeroU64::new(2).unwrap(), 3, BlockHeight::from(11), Some(2))]
    //------------------------------------------------------------------//
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(0), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(1), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(2), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(3), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(4), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(5), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(6), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(7), None)]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(8), Some(0))]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(9), Some(0))]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(10), Some(0))]
    #[case(NonZeroU64::new(3).unwrap(), 2, BlockHeight::from(11), Some(1))]
    fn sealed_epoch_index(
        #[case] epoch_length: NonZeroU64,
        #[case] seal_to_tip_distance: usize,
        #[case] block_height: BlockHeight,
        #[case] expected_epoch: Option<EpochIndex>,
    ) {
        let config = Builder::test_chain()
            .epoch_length(epoch_length)
            .sealed_epoch_distance_from_tip(seal_to_tip_distance)
            .build();
        assert_eq!(expected_epoch, config.sealed_epoch_index(&block_height));
    }

    #[test]
    fn test_ignore_consensus_in_mainnet() {
        let config = create_mainnet();

        assert_no_ignore_consensus_in_chain_config(&config);
    }

    #[test]
    #[should_panic(
        expected = "Invalid chain config. There must be at least 2 net-upgrades defined, one for genesis and one for the first block after genesis."
    )]
    fn test_ignore_consensus_outside_regtest_in_no_upgrades() {
        let config = Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::unit_tests())
            .build();

        assert_no_ignore_consensus_in_chain_config(&config);
    }

    #[test]
    #[should_panic(expected = "The net-upgrade at height 1 must not be IgnoreConsensus")]
    fn test_ignore_consensus_outside_regtest_with_deliberate_bad_upgrades() {
        let config = Builder::new(ChainType::Mainnet)
            .consensus_upgrades(NetUpgrades::deliberate_ignore_consensus_twice())
            .build();

        assert_no_ignore_consensus_in_chain_config(&config);
    }

    #[test]
    fn test_genesis_in_checkpoints() {
        for chain_type in ChainType::iter() {
            let config = Builder::new(chain_type).build();
            let checkpoint_at_0 =
                config.height_checkpoints().checkpoint_at_height(&BlockHeight::zero()).unwrap();
            assert_eq!(*checkpoint_at_0, config.genesis_block_id());
        }
    }

    #[test]
    fn test_checkpoints() {
        let config = Builder::new(ChainType::Mainnet).build();
        assert_eq!(
            *config.height_checkpoints().checkpoints_map(),
            *MAINNET_CHECKPOINTS
        );

        let config = Builder::new(ChainType::Testnet).build();

        assert_eq!(
            *config.height_checkpoints().checkpoints_map(),
            *TESTNET_CHECKPOINTS
        );
    }
}
