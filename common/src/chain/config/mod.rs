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
pub mod emission_schedule;
pub mod regtest;
pub mod regtest_options;
pub use builder::Builder;
use crypto::key::PublicKey;
use crypto::vrf::VRFPublicKey;
use emission_schedule::CoinUnit;
pub use emission_schedule::{EmissionSchedule, EmissionScheduleFn, EmissionScheduleTabular};

use std::{net::SocketAddr, num::NonZeroU64, sync::Arc, time::Duration};

use hex::FromHex;

use crate::chain::block::timestamp::BlockTimestamp;
use crate::chain::transaction::Destination;
use crate::chain::upgrades::NetUpgrades;
use crate::chain::PoWChainConfig;
use crate::chain::TxOutput;
use crate::chain::{GenBlock, Genesis};
use crate::primitives::id::{Id, Idable, WithId};
use crate::primitives::per_thousand::PerThousand;
use crate::primitives::semver::SemVer;
use crate::primitives::BlockCount;
use crate::primitives::{Amount, BlockDistance, BlockHeight, H256};
use crypto::key::hdkd::{child_number::ChildNumber, u31::U31};

use self::checkpoints::Checkpoints;
use self::emission_schedule::DEFAULT_INITIAL_MINT;
use super::output_value::OutputValue;
use super::tokens::TokenIssuanceVersion;
use super::{stakelock::StakePoolData, RequiredConsensus};
use super::{ChainstateUpgrade, ConsensusUpgrade};

const DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET: Duration = Duration::from_secs(120);
const DEFAULT_TARGET_BLOCK_SPACING: Duration = Duration::from_secs(120);
// DEFAULT_EPOCH_LENGTH = 3600
const DEFAULT_EPOCH_LENGTH: NonZeroU64 =
    match NonZeroU64::new((5 * 24 * 60 * 60) / DEFAULT_TARGET_BLOCK_SPACING.as_secs()) {
        Some(v) => v,
        None => panic!("epoch length cannot be 0"),
    };
const DEFAULT_SEALED_EPOCH_DISTANCE_FROM_TIP: usize = 2;

const DEFAULT_MAX_DEPTH_FOR_REORG: BlockDistance = BlockDistance::new(1000);

pub const BIP44_PATH: ChildNumber = ChildNumber::from_hardened(U31::from_u32_with_msb(44).0);
pub const MINTLAYER_COIN_TYPE: ChildNumber =
    ChildNumber::from_hardened(U31::from_u32_with_msb(0x4D4C).0);
pub const MINTLAYER_COIN_TYPE_TEST: ChildNumber =
    ChildNumber::from_hardened(U31::from_u32_with_msb(0x01).0);

pub type EpochIndex = u64;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainType {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

impl ChainType {
    pub const ALL: [ChainType; 4] = [Self::Mainnet, Self::Testnet, Self::Regtest, Self::Signet];

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

    const fn default_magic_bytes(&self) -> [u8; 4] {
        match self {
            ChainType::Mainnet => [0x1a, 0x64, 0xe5, 0xf1],
            ChainType::Testnet => [0x2b, 0x7e, 0x19, 0xf8],
            ChainType::Regtest => [0xaa, 0xbb, 0xcc, 0xdd],
            ChainType::Signet => [0xf3, 0xf7, 0x7b, 0x45],
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
            // TODO: Specify actual values
            ChainType::Mainnet => Vec::new(),
            ChainType::Testnet => vec!["testnet-seed.mintlayer.org"],
            ChainType::Regtest => Vec::new(),
            ChainType::Signet => Vec::new(),
        }
    }

    fn predefined_peer_addresses(&self) -> Vec<SocketAddr> {
        match self {
            // TODO: Specify actual values
            ChainType::Mainnet => Vec::new(),
            ChainType::Testnet => Vec::new(),
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

fn address_prefix(chain_type: ChainType, destination: &Destination) -> &'static str {
    match chain_type {
        ChainType::Mainnet => match destination {
            Destination::AnyoneCanSpend => "mxanyonecanspend",
            Destination::Address(_) => "mtc",
            Destination::PublicKey(_) => "mptc",
            Destination::ScriptHash(_) => "mstc",
            Destination::ClassicMultisig(_) => "mmtc",
        },
        ChainType::Testnet => match destination {
            Destination::AnyoneCanSpend => "txanyonecanspend",
            Destination::Address(_) => "tmt",
            Destination::PublicKey(_) => "tpmt",
            Destination::ScriptHash(_) => "tstc",
            Destination::ClassicMultisig(_) => "tmtc",
        },
        ChainType::Regtest => match destination {
            Destination::AnyoneCanSpend => "rxanyonecanspend",
            Destination::Address(_) => "rmt",
            Destination::PublicKey(_) => "rpmt",
            Destination::ScriptHash(_) => "rstc",
            Destination::ClassicMultisig(_) => "rmtc",
        },
        ChainType::Signet => match destination {
            Destination::AnyoneCanSpend => "sxanyonecanspend",
            Destination::Address(_) => "smt",
            Destination::PublicKey(_) => "spmt",
            Destination::ScriptHash(_) => "sstc",
            Destination::ClassicMultisig(_) => "smtc",
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
    magic_bytes: [u8; 4],
    p2p_port: u16,
    dns_seeds: Vec<&'static str>,
    predefined_peer_addresses: Vec<SocketAddr>,
    default_rpc_port: u16,
    genesis_block: Arc<WithId<Genesis>>,
    max_future_block_time_offset: Duration,
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

impl ChainConfig {
    /// Bech32m addresses in this chain will use this prefix
    #[must_use]
    pub fn destination_address_prefix(&self, destination: &Destination) -> &'static str {
        address_prefix(self.chain_type, destination)
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
    pub fn magic_bytes(&self) -> &[u8; 4] {
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
    pub fn max_future_block_time_offset(&self) -> &Duration {
        &self.max_future_block_time_offset
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
        std::cmp::min(
            self.max_block_size_from_std_scripts(),
            self.max_block_size_from_smart_contracts(),
        )
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
    pub fn data_deposit_max_size(&self) -> usize {
        self.data_deposit_max_size
    }

    /// The fee for depositing data
    pub fn data_deposit_fee(&self) -> Amount {
        self.data_deposit_fee
    }

    /// The fee for issuing a fungible token
    pub fn fungible_token_issuance_fee(&self) -> Amount {
        self.fungible_token_issuance_fee
    }

    /// The fee for issuing a NFT
    pub fn nft_issuance_fee(&self) -> Amount {
        self.nft_issuance_fee
    }

    /// The fee for changing supply of a token
    pub fn token_supply_change_fee(&self) -> Amount {
        self.token_supply_change_fee
    }

    /// The fee for freezing/unfreezing a token
    pub fn token_freeze_fee(&self) -> Amount {
        self.token_freeze_fee
    }

    /// The fee for changing authority of a token
    pub fn token_change_authority_fee(&self) -> Amount {
        self.token_change_authority_fee
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
        self.token_max_ticker_len
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
const FUNGIBLE_TOKEN_MIN_ISSUANCE_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const NFT_MIN_ISSUANCE_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_MIN_SUPPLY_CHANGE_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_MIN_FREEZE_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_CHANGE_AUTHORITY_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const DATA_DEPOSIT_MAX_SIZE: usize = 128;
const DATA_DEPOSIT_MIN_FEE: Amount = CoinUnit::from_coins(100).to_amount_atoms();
const TOKEN_MAX_DEC_COUNT: u8 = 18;
const TOKEN_MAX_TICKER_LEN: usize = 5;
const TOKEN_MIN_HASH_LEN: usize = 4;
const TOKEN_MAX_HASH_LEN: usize = 32;
const TOKEN_MAX_NAME_LEN: usize = 10;
const TOKEN_MAX_DESCRIPTION_LEN: usize = 100;
const TOKEN_MAX_URI_LEN: usize = 1024;
const MAX_CLASSIC_MULTISIG_PUBLIC_KEYS_COUNT: usize = 16;
const MIN_STAKE_POOL_PLEDGE: Amount = Amount::from_atoms(40_000 * CoinUnit::ATOMS_PER_COIN);

fn decode_hex<T: serialization::DecodeAll>(hex: &str) -> T {
    let bytes = Vec::from_hex(hex).expect("Hex decoding shouldn't fail");
    <T as serialization::DecodeAll>::decode_all(&mut bytes.as_slice())
        .expect("Decoding shouldn't fail")
}

fn create_mainnet_genesis() -> Genesis {
    // TODO: replace this with our mint key
    // Private key: "0080732e24bb0b704cb455e233b539f2c63ab411989a54984f84a6a2eb2e933e160f"
    // Public key:  "008090f5aee58be97ce2f7c014fa97ffff8c459a0c491f8124950724a187d134e25c"
    // Public key hash:  "8640e6a3d3d53c7dffe2790b0e147c9a77197033"
    let genesis_mint_pubkeyhash_hex_encoded = "018640e6a3d3d53c7dffe2790b0e147c9a77197033";
    let genesis_mint_destination = decode_hex::<Destination>(genesis_mint_pubkeyhash_hex_encoded);

    let genesis_message = String::new();

    // TODO: replace this with the real genesis mint value
    let output = TxOutput::Transfer(
        OutputValue::Coin(DEFAULT_INITIAL_MINT),
        genesis_mint_destination,
    );

    Genesis::new(
        genesis_message,
        BlockTimestamp::from_int_seconds(1639975460),
        vec![output],
    )
}

fn create_testnet_genesis() -> Genesis {
    // We add 3_600_000_000 coins to the genesis mint account since it's just for testing. Nothing else changes.
    let extra_testnet_mint = Amount::from_atoms(3_600_000_000 * CoinUnit::ATOMS_PER_COIN);
    let total_amount = (extra_testnet_mint + DEFAULT_INITIAL_MINT).expect("Cannot fail");
    let initial_pool_amount = MIN_STAKE_POOL_PLEDGE;
    let mint_output_amount = (total_amount - initial_pool_amount).expect("must be valid");

    let genesis_message = String::new();

    // To get these values, use the `newpublickey` and `getvrfpublickey` wallet-cli commands

    let genesis_mint_destination = decode_hex::<PublicKey>(
        "0003e9d79eb6487c28dad9679461faa1ffcdbc52a10033e1ad625101a97db1ba8edd",
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

    let mint_output = TxOutput::Transfer(
        OutputValue::Coin(mint_output_amount),
        Destination::PublicKey(genesis_mint_destination),
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
    Builder::new(ChainType::Testnet)
        .consensus_upgrades(NetUpgrades::unit_tests())
        .chainstate_upgrades(
            NetUpgrades::initialize(vec![(
                BlockHeight::zero(),
                ChainstateUpgrade::new(TokenIssuanceVersion::V1),
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

    assert!(all_upgrades.len() >= 2, "Invalid chain config. There must be at least 2 net-upgrades defined, one for genesis and one for the first block after genesis.");

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
    use super::*;
    use rstest::rstest;

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
        let config2 = Builder::new(ChainType::Regtest).magic_bytes([1, 2, 3, 4]).build();

        assert_ne!(config1.magic_bytes(), config2.magic_bytes());
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
}
