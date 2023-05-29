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
pub use builder::Builder;
use crypto::key::PublicKey;
use crypto::vrf::VRFPublicKey;
pub use emission_schedule::{EmissionSchedule, EmissionScheduleFn, EmissionScheduleTabular};

use hex::FromHex;

use crate::chain::block::timestamp::BlockTimestamp;
use crate::chain::tokens::OutputValue;
use crate::chain::transaction::Destination;
use crate::chain::upgrades::NetUpgrades;
use crate::chain::TxOutput;
use crate::chain::{GenBlock, Genesis};
use crate::chain::{PoWChainConfig, UpgradeVersion};
use crate::primitives::id::{Id, Idable, WithId};
use crate::primitives::per_thousand::PerThousand;
use crate::primitives::semver::SemVer;
use crate::primitives::{Amount, BlockDistance, BlockHeight, H256};
use crypto::key::hdkd::{child_number::ChildNumber, u31::U31};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use self::checkpoints::Checkpoints;
use super::{stakelock::StakePoolData, RequiredConsensus};

const DEFAULT_MAX_FUTURE_BLOCK_TIME_OFFSET: Duration = Duration::from_secs(120);
const DEFAULT_TARGET_BLOCK_SPACING: Duration = Duration::from_secs(120);
const DEFAULT_EPOCH_LENGTH: NonZeroU64 =
    match NonZeroU64::new((5 * 24 * 60 * 60) / DEFAULT_TARGET_BLOCK_SPACING.as_secs()) {
        Some(v) => v,
        None => panic!("epoch length cannot be 0"),
    };
const DEFAULT_SEALED_EPOCH_DISTANCE_FROM_TIP: usize = 2;

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
    pub const fn name(&self) -> &'static str {
        match self {
            ChainType::Mainnet => "mainnet",
            ChainType::Testnet => "testnet",
            ChainType::Regtest => "regtest",
            ChainType::Signet => "signet",
        }
    }

    const fn default_address_prefix(&self) -> &'static str {
        match self {
            ChainType::Mainnet => "mtc",
            ChainType::Testnet => "tmt",
            ChainType::Regtest => "rmt",
            ChainType::Signet => "smt",
        }
    }

    const fn default_magic_bytes(&self) -> [u8; 4] {
        match self {
            ChainType::Mainnet => [0x1a, 0x64, 0xe5, 0xf1],
            ChainType::Testnet => [0x2b, 0x7e, 0x19, 0xf6],
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

    const fn default_bip44_coin_type(&self) -> ChildNumber {
        match self {
            ChainType::Mainnet => MINTLAYER_COIN_TYPE,
            ChainType::Testnet | ChainType::Regtest | ChainType::Signet => MINTLAYER_COIN_TYPE_TEST,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    chain_type: ChainType,
    address_prefix: String,
    bip44_coin_type: ChildNumber,
    height_checkpoint_data: Checkpoints,
    net_upgrades: NetUpgrades<UpgradeVersion>,
    magic_bytes: [u8; 4],
    p2p_port: u16,
    genesis_block: Arc<WithId<Genesis>>,
    max_future_block_time_offset: Duration,
    version: SemVer,
    target_block_spacing: Duration,
    coin_decimals: u8,
    emission_schedule: EmissionSchedule,
    max_block_header_size: usize,
    max_block_size_with_standard_txs: usize,
    max_block_size_with_smart_contracts: usize,
    max_no_signature_data_size: usize,
    epoch_length: NonZeroU64,
    sealed_epoch_distance_from_tip: usize,
    initial_randomness: H256,
    token_min_issuance_fee: Amount,
    token_max_uri_len: usize,
    token_max_dec_count: u8,
    token_max_ticker_len: usize,
    token_max_name_len: usize,
    token_max_description_len: usize,
    token_min_hash_len: usize,
    token_max_hash_len: usize,
    empty_consensus_reward_maturity_distance: BlockDistance,
    max_classic_multisig_public_keys_count: usize,
}

impl ChainConfig {
    /// Bech32m addresses in this chain will use this prefix
    #[must_use]
    pub fn address_prefix(&self) -> &str {
        &self.address_prefix
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

    /// The current version of the protocol that this chain is running
    #[must_use]
    pub fn version(&self) -> &SemVer {
        &self.version
    }

    /// The chain of this config (mainnet, testnet, regtest, etc...)
    #[must_use]
    pub fn chain_type(&self) -> &ChainType {
        &self.chain_type
    }

    /// The mechanism by which we define changes in the chain, including consensus and other upgrades/forks
    #[must_use]
    pub fn net_upgrade(&self) -> &NetUpgrades<UpgradeVersion> {
        &self.net_upgrades
    }

    /// Checkpoints enforced by the chain, as in, a block id vs height that must be satisfied
    #[must_use]
    pub fn height_checkpoints(&self) -> &Checkpoints {
        &self.height_checkpoint_data
    }

    /// The target time-distance between blocks
    #[must_use]
    pub fn target_block_spacing(&self) -> &Duration {
        &self.target_block_spacing
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

    /// The maximum size of data attached to NoSignature witness
    #[must_use]
    pub fn max_no_signature_data_size(&self) -> usize {
        self.max_no_signature_data_size
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
    pub fn max_block_size_from_txs(&self) -> usize {
        self.max_block_size_with_standard_txs
    }

    /// The maximum size of a block that uses smart contracts
    #[must_use]
    pub fn max_block_size_from_smart_contracts(&self) -> usize {
        self.max_block_size_with_smart_contracts
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

    /// The fee for issuing a token
    pub fn token_min_issuance_fee(&self) -> Amount {
        self.token_min_issuance_fee
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
    pub fn empty_consensus_reward_maturity_distance(&self) -> BlockDistance {
        self.empty_consensus_reward_maturity_distance
    }

    // TODO: this should be part of net-upgrades. There should be no canonical definition of PoW for any chain config
    #[must_use]
    pub const fn get_proof_of_work_config(&self) -> PoWChainConfig {
        PoWChainConfig::new(self.chain_type)
    }

    /// The minimum number of blocks required to be able to spend a utxo coming from a decommissioned pool
    #[must_use]
    pub fn decommission_pool_maturity_distance(&self, block_height: BlockHeight) -> BlockDistance {
        match self.net_upgrades.consensus_status(block_height) {
            RequiredConsensus::IgnoreConsensus | RequiredConsensus::PoW(_) => {
                self.empty_consensus_reward_maturity_distance
            }
            RequiredConsensus::PoS(status) => {
                status.get_chain_config().decommission_maturity_distance()
            }
        }
    }

    /// The number of blocks required to pass before a delegation share can be spent after taking it out of the delegation account
    #[must_use]
    pub fn spend_share_maturity_distance(&self, block_height: BlockHeight) -> BlockDistance {
        match self.net_upgrades.consensus_status(block_height) {
            RequiredConsensus::IgnoreConsensus | RequiredConsensus::PoW(_) => {
                self.empty_consensus_reward_maturity_distance
            }
            RequiredConsensus::PoS(status) => {
                status.get_chain_config().spend_share_maturity_distance()
            }
        }
    }

    /// The maximum number of public keys that can go into a classical multisig
    #[must_use]
    pub fn max_classic_multisig_public_keys_count(&self) -> usize {
        self.max_classic_multisig_public_keys_count
    }
}

impl AsRef<ChainConfig> for ChainConfig {
    fn as_ref(&self) -> &ChainConfig {
        self
    }
}

const MAX_BLOCK_HEADER_SIZE: usize = 1024;
const MAX_BLOCK_TXS_SIZE: usize = 524_288;
const MAX_BLOCK_CONTRACTS_SIZE: usize = 524_288;
const MAX_TX_NO_SIG_WITNESS_SIZE: usize = 128;
const TOKEN_MIN_ISSUANCE_FEE: Amount = Amount::from_atoms(10_000_000_000_000);
const TOKEN_MAX_DEC_COUNT: u8 = 18;
const TOKEN_MAX_TICKER_LEN: usize = 5;
const TOKEN_MIN_HASH_LEN: usize = 4;
const TOKEN_MAX_HASH_LEN: usize = 32;
const TOKEN_MAX_NAME_LEN: usize = 10;
const TOKEN_MAX_DESCRIPTION_LEN: usize = 100;
const TOKEN_MAX_URI_LEN: usize = 1024;
const MAX_CLASSIC_MULTISIG_PUBLIC_KEYS_COUNT: usize = 16;

fn create_mainnet_genesis() -> Genesis {
    // TODO: replace this with our mint key
    // Private key: "0080732e24bb0b704cb455e233b539f2c63ab411989a54984f84a6a2eb2e933e160f"
    // Public key:  "008090f5aee58be97ce2f7c014fa97ffff8c459a0c491f8124950724a187d134e25c"
    // Public key hash:  "8640e6a3d3d53c7dffe2790b0e147c9a77197033"
    let genesis_mint_pubkeyhash_hex_encoded = "018640e6a3d3d53c7dffe2790b0e147c9a77197033";
    let genesis_mint_pubkeyhash_encoded = Vec::from_hex(genesis_mint_pubkeyhash_hex_encoded)
        .expect("Hex decoding of pubkeyhash shouldn't fail");
    let genesis_mint_destination = <Destination as serialization::DecodeAll>::decode_all(
        &mut genesis_mint_pubkeyhash_encoded.as_slice(),
    )
    .expect("Decoding genesis mint destination shouldn't fail");

    let genesis_message = String::new();

    // TODO: replace this with the real genesis mint value
    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(100_000_000_000_000)),
        genesis_mint_destination,
    );

    Genesis::new(
        genesis_message,
        BlockTimestamp::from_int_seconds(1639975460),
        vec![output],
    )
}

fn decode_hex<T: serialization::DecodeAll>(hex: &str) -> T {
    let bytes = Vec::from_hex(hex).expect("Hex decoding shouldn't fail");
    <T as serialization::DecodeAll>::decode_all(&mut bytes.as_slice())
        .expect("Decoding shouldn't fail")
}

fn create_testnet_genesis() -> Genesis {
    // TODO: use coin_decimals instead of a fixed value
    const COIN: Amount = Amount::from_atoms(100000000000);

    let total_amount = (COIN * 100_000_000).expect("must be valid");
    let initial_pool_amount = (COIN * 40_000).expect("must be valid");
    let mint_output_amount = (total_amount - initial_pool_amount).expect("must be valid");

    let genesis_message = String::new();

    let genesis_mint_destination = decode_hex::<PublicKey>(
        "00027a9771bbb58170a0df36ed43e56490530f0f2f45b100c42f6f405af3ef21f54e",
    );
    let decommission_pub_key = decode_hex::<PublicKey>(
        "0002ea30f3bb179c58022dcf2f4fd2c88685695f9532d6a9dd071da8d7ac1fe91a7d",
    );
    let staker_pub_key = decode_hex::<PublicKey>(
        "0002884adf48b0b32ab3d66e1a8b46576dfacca5dd25b66603650de792de4dd2e483",
    );

    let vrf_pub_key = decode_hex::<VRFPublicKey>(
        "00d4b8138be57c1bddfff397ffc72ca0453131f8df364d2b6bf4a8c6558ed81d79",
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
            PerThousand::new(10).expect("must be valid"),
            (COIN * 100).expect("must be valid"),
        )),
    );

    Genesis::new(
        genesis_message,
        BlockTimestamp::from_int_seconds(1685025323),
        vec![mint_output, initial_pool],
    )
}

fn create_unit_test_genesis(premine_destination: Destination) -> Genesis {
    let genesis_message = String::new();

    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(100_000_000_000_000_000_000)),
        premine_destination,
    );

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

pub fn create_unit_test_config() -> ChainConfig {
    Builder::new(ChainType::Mainnet)
        .net_upgrades(NetUpgrades::unit_tests())
        .genesis_unittest(Destination::AnyoneCanSpend)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn mainnet_creation() {
        let config = create_mainnet();

        assert!(!config.net_upgrades.is_empty());
        assert_eq!(2, config.net_upgrades.len());
        assert_eq!(config.chain_type(), &ChainType::Mainnet);
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
}
