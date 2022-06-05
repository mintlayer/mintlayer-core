use hex::FromHex;

use crate::chain::block::Block;
use crate::chain::block::ConsensusData;
use crate::chain::signature::inputsig::InputWitness;
use crate::chain::transaction::Destination;
use crate::chain::transaction::Transaction;
use crate::chain::upgrades::ConsensusUpgrade;
use crate::chain::upgrades::NetUpgrades;
use crate::chain::{PoWChainConfig, UpgradeVersion};
use crate::primitives::id::{Id, H256};
use crate::primitives::Amount;
use crate::primitives::BlockDistance;
use crate::primitives::Idable;
use crate::primitives::{version::SemVer, BlockHeight};
use std::collections::BTreeMap;
use std::time::Duration;

const MAINNET_COIN_DECIMALS: u8 = 11;
const MAINNET_COIN_PREMINE: &str = "400_000_000";
const MAINNET_TOTAL_SUPPLY: &str = "599_990_800";

const DEFAULT_TARGET_BLOCK_SPACING: Duration = Duration::from_secs(120);

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    strum::Display,
    strum::EnumVariantNames,
    strum::EnumString,
)]
#[strum(serialize_all = "kebab-case")]
pub enum ChainType {
    Mainnet,
    Testnet,
    Regtest,
    Signet,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    chain_type: ChainType,
    address_prefix: String,
    rpc_port: u16,
    p2p_port: u16,
    height_checkpoint_data: BTreeMap<BlockHeight, Id<Block>>,
    net_upgrades: NetUpgrades<UpgradeVersion>,
    magic_bytes: [u8; 4],
    genesis_block: Block,
    genesis_block_id: Id<Block>,
    blockreward_maturity: BlockDistance,
    version: SemVer,
    target_block_spacing: Duration,
    coin_decimals: u8,
    emission_schedule: Vec<(BlockHeight, Amount)>,
}

impl ChainConfig {
    pub fn address_prefix(&self) -> &str {
        &self.address_prefix
    }

    pub fn genesis_block_id(&self) -> Id<Block> {
        self.genesis_block_id.clone()
    }

    pub fn genesis_block(&self) -> &Block {
        &self.genesis_block
    }

    pub fn magic_bytes(&self) -> &[u8; 4] {
        &self.magic_bytes
    }

    pub fn magic_bytes_as_u32(&self) -> u32 {
        u32::from_le_bytes(*self.magic_bytes())
    }

    pub fn version(&self) -> &SemVer {
        &self.version
    }

    pub fn chain_type(&self) -> &ChainType {
        &self.chain_type
    }

    pub fn net_upgrade(&self) -> &NetUpgrades<UpgradeVersion> {
        &self.net_upgrades
    }

    pub fn p2p_port(&self) -> u16 {
        self.p2p_port
    }

    pub fn rpc_port(&self) -> u16 {
        self.rpc_port
    }

    pub fn height_checkpoints(&self) -> &BTreeMap<BlockHeight, Id<Block>> {
        &self.height_checkpoint_data
    }

    pub fn target_block_spacing(&self) -> &Duration {
        &self.target_block_spacing
    }

    pub fn emission_schedule(&self) -> &Vec<(BlockHeight, Amount)> {
        &self.emission_schedule
    }

    pub fn coin_decimals(&self) -> u8 {
        self.coin_decimals
    }

    pub fn block_subsidy_at_height(&self, height_in: &BlockHeight) -> Amount {
        self.emission_schedule
            .iter()
            .filter(|(height_in_map, _amount)| height_in_map <= height_in)
            .rev()
            .next()
            .expect("This can never fail")
            .1
    }

    // TODO: this should be part of net-upgrades. There should be no canonical definition of PoW for any chain config
    pub const fn get_proof_of_work_config(&self) -> PoWChainConfig {
        PoWChainConfig::new(self.chain_type)
    }

    pub const fn get_blockreward_maturity(&self) -> &BlockDistance {
        &self.blockreward_maturity
    }
}

const MAINNET_ADDRESS_PREFIX: &str = "mtc";
#[allow(dead_code)]
const TESTNET_ADDRESS_PREFIX: &str = "tmt";
#[allow(dead_code)]
const REGTEST_ADDRESS_PREFIX: &str = "rmt";

// If block time is 2 minutes (which is my goal eventually), then 500 is equivalent to 100 in bitcoin's 10 minutes.
const MAINNET_BLOCKREWARD_MATURITY: BlockDistance = BlockDistance::new(500);
// DSA allows us to have blocks up to 1mb
pub const MAX_BLOCK_WEIGHT: usize = 1_048_576;

fn create_mainnet_genesis() -> Block {
    use crate::chain::transaction::{TxInput, TxOutput};

    // TODO: replace this with our mint key
    // Private key: "0080732e24bb0b704cb455e233b539f2c63ab411989a54984f84a6a2eb2e933e160f"
    // Pubub key:  "008090f5aee58be97ce2f7c014fa97ffff8c459a0c491f8124950724a187d134e25c"
    // Public key hash:  "8640e6a3d3d53c7dffe2790b0e147c9a77197033"
    // Destination:  "008640e6a3d3d53c7dffe2790b0e147c9a77197033"
    let genesis_mint_pubkeyhash_hex_encoded = "008640e6a3d3d53c7dffe2790b0e147c9a77197033";
    let genesis_mint_pubkeyhash_encoded = Vec::from_hex(genesis_mint_pubkeyhash_hex_encoded)
        .expect("Hex decoding of pubkeyhash shouldn't fail");
    let genesis_mint_destination = <Destination as parity_scale_codec::DecodeAll>::decode_all(
        &mut genesis_mint_pubkeyhash_encoded.as_slice(),
    )
    .expect("Decoding genesis mint destination shouldn't fail");

    let genesis_message = b"".to_vec();
    let input = TxInput::new(
        Id::<Transaction>::new(&H256::zero()).into(),
        0,
        InputWitness::NoSignature(Some(genesis_message)),
    );
    // TODO: replace this with the real genesis mint value
    let output = TxOutput::new(
        Amount::from_atoms(100000000000000),
        genesis_mint_destination,
    );
    let tx = Transaction::new(0, vec![input], vec![output], 0)
        .expect("Failed to create genesis coinbase transaction");

    Block::new(vec![tx], None, 1639975460, ConsensusData::None)
        .expect("Error creating genesis block")
}

fn create_unit_test_genesis(premine_destination: Destination) -> Block {
    use crate::chain::transaction::{TxInput, TxOutput};

    let genesis_message = b"".to_vec();
    let input = TxInput::new(
        Id::<Transaction>::new(&H256::zero()).into(),
        0,
        InputWitness::NoSignature(Some(genesis_message)),
    );

    let output = TxOutput::new(Amount::from_atoms(100000000000000), premine_destination);
    let tx = Transaction::new(0, vec![input], vec![output], 0)
        .expect("Failed to create genesis coinbase transaction");

    Block::new(vec![tx], None, 1639975460, ConsensusData::None)
        .expect("Error creating genesis block")
}

fn reward_in_year_to_reward_in_block<S: AsRef<str>>(
    target_block_spacing: &Duration,
    coin_decimals: u8,
    input: &[(u64, S)],
) -> Vec<(BlockHeight, Amount)> {
    let year_in_blocks = (365 * 24 * 60 * 60) / target_block_spacing.as_secs();
    let emission_schedule = input
        .into_iter()
        .map(|(year, s)| {
            (
                BlockHeight::new(1 + (*year as u64) * year_in_blocks),
                Amount::from_fixedpoint_str(s.as_ref(), coin_decimals).unwrap(),
            )
        })
        .collect::<Vec<(BlockHeight, Amount)>>();
    emission_schedule
}

fn assert_emission_schedule_is_sorted(schedule: &[(BlockHeight, Amount)]) {
    let mut schedule_clone = schedule.to_vec();
    schedule_clone.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(schedule_clone, schedule.to_vec());
}

fn calculate_total_emission(schedule: &[(BlockHeight, Amount)]) -> Amount {
    // the schedule cannot be empty
    assert!(!schedule.is_empty());
    // the first block subsidy must be for block of height 1
    assert_eq!(schedule.first().unwrap().0, BlockHeight::new(1));
    // the last reward must always be zero, otherwise the total is infinite
    assert_eq!(schedule.last().unwrap().1, Amount::from_atoms(0));
    // the heights must be sorted
    assert_emission_schedule_is_sorted(schedule);

    schedule
        .iter()
        .rfold((schedule[0].0, Amount::from_atoms(0)), |init, curr| {
            // blocks that have the same reward
            let block_count_in_segment: i64 = (init.0 - curr.0).unwrap().into();
            let total_amount_so_far = init.1;
            let subsidy_in_this_segment = curr.1;
            (
                curr.0,
                (total_amount_so_far
                    + (subsidy_in_this_segment * (block_count_in_segment as u128)).unwrap())
                .unwrap(),
            )
        })
        .1
}

pub fn make_mainnet_emission_schedule(
    target_block_spacing: &Duration,
    coin_decimals: u8,
    total_block_subsidy_to_check: Option<Amount>,
) -> Vec<(BlockHeight, Amount)> {
    let subsidy_per_block_in_year_n_str = [
        (0, "202"),
        (1, "151"),
        (2, "113"),
        (3, "85"),
        (4, "64"),
        (5, "48"),
        (6, "36"),
        (7, "27"),
        (8, "20"),
        (9, "15"),
        (10, "0"),
    ];

    let emission_schedule = reward_in_year_to_reward_in_block(
        target_block_spacing,
        coin_decimals,
        &subsidy_per_block_in_year_n_str,
    );

    if let Some(expected_total_block_subsidy) = total_block_subsidy_to_check {
        let calculated_total_emission = calculate_total_emission(&emission_schedule);

        assert_eq!(calculated_total_emission, expected_total_block_subsidy);
    }

    emission_schedule
}

pub fn create_mainnet() -> ChainConfig {
    let chain_type = ChainType::Mainnet;
    let pow_config = PoWChainConfig::new(chain_type);

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

    let genesis_block = create_mainnet_genesis();
    let genesis_block_id = genesis_block.get_id();

    let target_block_spacing = DEFAULT_TARGET_BLOCK_SPACING;

    let coin_decimals = MAINNET_COIN_DECIMALS;

    let expected_total_block_subsidy =
        (Amount::from_fixedpoint_str(MAINNET_TOTAL_SUPPLY, coin_decimals).unwrap()
            - Amount::from_fixedpoint_str(MAINNET_COIN_PREMINE, coin_decimals).unwrap())
        .unwrap();

    let emission_schedule = make_mainnet_emission_schedule(
        &target_block_spacing,
        coin_decimals,
        Some(expected_total_block_subsidy),
    );

    ChainConfig {
        chain_type,
        address_prefix: MAINNET_ADDRESS_PREFIX.to_owned(),
        height_checkpoint_data: BTreeMap::<BlockHeight, Id<Block>>::new(),
        net_upgrades: NetUpgrades::initialize(upgrades).expect("Should not fail"),
        rpc_port: 15234,
        p2p_port: 8978,
        magic_bytes: [0x1a, 0x64, 0xe5, 0xf1],
        genesis_block,
        genesis_block_id,
        version: SemVer::new(0, 1, 0),
        blockreward_maturity: MAINNET_BLOCKREWARD_MATURITY,
        target_block_spacing,
        coin_decimals,
        emission_schedule,
    }
}

pub fn create_regtest() -> ChainConfig {
    let chain_type = ChainType::Regtest;
    let pow_config = PoWChainConfig::new(chain_type);

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

    let genesis_block = create_unit_test_genesis(Destination::AnyoneCanSpend);
    let genesis_block_id = genesis_block.get_id();

    let target_block_spacing = DEFAULT_TARGET_BLOCK_SPACING;
    let coin_decimals = MAINNET_COIN_DECIMALS;

    let expected_total_block_subsidy =
        (Amount::from_fixedpoint_str(MAINNET_TOTAL_SUPPLY, coin_decimals).unwrap()
            - Amount::from_fixedpoint_str(MAINNET_COIN_PREMINE, coin_decimals).unwrap())
        .unwrap();

    let emission_schedule = make_mainnet_emission_schedule(
        &target_block_spacing,
        coin_decimals,
        Some(expected_total_block_subsidy),
    );

    ChainConfig {
        chain_type,
        address_prefix: REGTEST_ADDRESS_PREFIX.to_owned(),
        height_checkpoint_data: BTreeMap::<BlockHeight, Id<Block>>::new(),
        net_upgrades: NetUpgrades::initialize(upgrades).expect("Should not fail"),
        rpc_port: 11111,
        p2p_port: 22222,
        magic_bytes: [0xaa, 0xbb, 0xcc, 0xdd],
        genesis_block,
        genesis_block_id,
        version: SemVer::new(0, 1, 0),
        target_block_spacing,
        blockreward_maturity: MAINNET_BLOCKREWARD_MATURITY,
        coin_decimals: MAINNET_COIN_DECIMALS,
        emission_schedule,
    }
}

pub fn create_unit_test_config() -> ChainConfig {
    let genesis_block = create_unit_test_genesis(Destination::AnyoneCanSpend);
    let genesis_block_id = genesis_block.get_id();

    let target_block_spacing = DEFAULT_TARGET_BLOCK_SPACING;
    let coin_decimals = MAINNET_COIN_DECIMALS;

    let expected_total_block_subsidy =
        (Amount::from_fixedpoint_str(MAINNET_TOTAL_SUPPLY, coin_decimals).unwrap()
            - Amount::from_fixedpoint_str(MAINNET_COIN_PREMINE, coin_decimals).unwrap())
        .unwrap();

    let emission_schedule = make_mainnet_emission_schedule(
        &target_block_spacing,
        coin_decimals,
        Some(expected_total_block_subsidy),
    );

    ChainConfig {
        chain_type: ChainType::Mainnet,
        address_prefix: MAINNET_ADDRESS_PREFIX.to_owned(),
        height_checkpoint_data: BTreeMap::<BlockHeight, Id<Block>>::new(),
        net_upgrades: NetUpgrades::unit_tests(),
        rpc_port: 15234,
        p2p_port: 8978,
        magic_bytes: [0x1a, 0x64, 0xe5, 0xf1],
        genesis_block,
        genesis_block_id,
        version: SemVer::new(0, 1, 0),
        target_block_spacing,
        blockreward_maturity: MAINNET_BLOCKREWARD_MATURITY,
        coin_decimals,
        emission_schedule,
    }
}

pub struct TestChainConfig {
    net_upgrades: NetUpgrades<UpgradeVersion>,
    magic_bytes: [u8; 4],
}

impl Default for TestChainConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TestChainConfig {
    pub fn new() -> Self {
        Self {
            net_upgrades: NetUpgrades::unit_tests(),
            magic_bytes: [0x1a, 0x64, 0xe5, 0xf1],
        }
    }

    pub fn with_net_upgrades(mut self, net_upgrades: NetUpgrades<UpgradeVersion>) -> Self {
        self.net_upgrades = net_upgrades;
        self
    }

    pub fn with_magic_bytes(mut self, magic_bytes: [u8; 4]) -> Self {
        self.magic_bytes = magic_bytes;
        self
    }

    pub fn build(self) -> ChainConfig {
        let genesis_block = create_unit_test_genesis(Destination::AnyoneCanSpend);
        let genesis_block_id = genesis_block.get_id();

        let target_block_spacing = DEFAULT_TARGET_BLOCK_SPACING;
        let coin_decimals = MAINNET_COIN_DECIMALS;

        let expected_total_block_subsidy =
            (Amount::from_fixedpoint_str(MAINNET_TOTAL_SUPPLY, coin_decimals).unwrap()
                - Amount::from_fixedpoint_str(MAINNET_COIN_PREMINE, coin_decimals).unwrap())
            .unwrap();

        let emission_schedule = make_mainnet_emission_schedule(
            &target_block_spacing,
            coin_decimals,
            Some(expected_total_block_subsidy),
        );

        ChainConfig {
            chain_type: ChainType::Mainnet,
            address_prefix: MAINNET_ADDRESS_PREFIX.to_owned(),
            height_checkpoint_data: BTreeMap::<BlockHeight, Id<Block>>::new(),
            net_upgrades: self.net_upgrades,
            rpc_port: 15234,
            p2p_port: 8978,
            magic_bytes: self.magic_bytes,
            genesis_block,
            genesis_block_id,
            version: SemVer::new(0, 1, 0),
            target_block_spacing,
            blockreward_maturity: MAINNET_BLOCKREWARD_MATURITY,
            coin_decimals,
            emission_schedule,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_creation() {
        let config = create_mainnet();

        assert!(!config.net_upgrades.is_empty());
        assert_eq!(2, config.net_upgrades.len());
        assert_eq!(config.chain_type(), &ChainType::Mainnet);
    }

    #[test]
    fn mainnet_emission_schedule() {
        let config = create_mainnet();

        assert_eq!(config.coin_decimals(), MAINNET_COIN_DECIMALS);

        let blocks_per_year = 262800;

        // first year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(1)),
            Amount::from_fixedpoint_str("202", MAINNET_COIN_DECIMALS).unwrap()
        );
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2)),
            Amount::from_fixedpoint_str("202", MAINNET_COIN_DECIMALS).unwrap()
        );
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(5)),
            Amount::from_fixedpoint_str("202", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10000)),
            Amount::from_fixedpoint_str("202", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(blocks_per_year)),
            Amount::from_fixedpoint_str("202", MAINNET_COIN_DECIMALS).unwrap()
        );

        // second year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(blocks_per_year + 1)),
            Amount::from_fixedpoint_str("151", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(blocks_per_year + 2)),
            Amount::from_fixedpoint_str("151", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config
                .block_subsidy_at_height(&BlockHeight::new(blocks_per_year + blocks_per_year / 2)),
            Amount::from_fixedpoint_str("151", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2 * blocks_per_year)),
            Amount::from_fixedpoint_str("151", MAINNET_COIN_DECIMALS).unwrap()
        );

        // third year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2 * blocks_per_year + 1)),
            Amount::from_fixedpoint_str("113", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(2 * blocks_per_year + 2)),
            Amount::from_fixedpoint_str("113", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(
                2 * blocks_per_year + blocks_per_year / 2
            )),
            Amount::from_fixedpoint_str("113", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(3 * blocks_per_year)),
            Amount::from_fixedpoint_str("113", MAINNET_COIN_DECIMALS).unwrap()
        );

        // forth year
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(3 * blocks_per_year + 1)),
            Amount::from_fixedpoint_str("85", MAINNET_COIN_DECIMALS).unwrap()
        );

        // towards the end
        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10 * blocks_per_year)),
            Amount::from_fixedpoint_str("15", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10 * blocks_per_year + 1)),
            Amount::from_fixedpoint_str("0", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(10 * blocks_per_year + 2)),
            Amount::from_fixedpoint_str("0", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(11 * blocks_per_year + 2)),
            Amount::from_fixedpoint_str("0", MAINNET_COIN_DECIMALS).unwrap()
        );

        assert_eq!(
            config.block_subsidy_at_height(&BlockHeight::new(u64::MAX)),
            Amount::from_fixedpoint_str("0", MAINNET_COIN_DECIMALS).unwrap()
        );
    }

    #[test]
    fn total_emission() {
        {
            let schedule = [(BlockHeight::new(1), Amount::from_atoms(0))];
            assert_eq!(calculate_total_emission(&schedule), Amount::from_atoms(0));
        }

        {
            let schedule = [
                (BlockHeight::new(1), Amount::from_atoms(20)),
                (BlockHeight::new(11), Amount::from_atoms(0)),
            ];
            assert_eq!(calculate_total_emission(&schedule), Amount::from_atoms(200));
        }

        {
            let schedule = [
                (BlockHeight::new(1), Amount::from_atoms(20)),
                (BlockHeight::new(11), Amount::from_atoms(10)),
                (BlockHeight::new(51), Amount::from_atoms(0)),
            ];
            assert_eq!(
                calculate_total_emission(&schedule),
                Amount::from_atoms(200 + 400)
            );
        }

        {
            let schedule = [
                (BlockHeight::new(1), Amount::from_atoms(20)),
                (BlockHeight::new(11), Amount::from_atoms(10)),
                (BlockHeight::new(51), Amount::from_atoms(5)),
                (BlockHeight::new(101), Amount::from_atoms(0)),
            ];
            assert_eq!(
                calculate_total_emission(&schedule),
                Amount::from_atoms(200 + 400 + 250)
            );
        }
    }

    #[test]
    #[should_panic]
    fn total_emission_last_subsidy_must_be_zero() {
        {
            let schedule = [(BlockHeight::new(1), Amount::from_atoms(10))];
            assert_eq!(calculate_total_emission(&schedule), Amount::from_atoms(0));
        }
    }

    #[test]
    #[should_panic]
    fn total_emission_schedule_cannot_be_empty() {
        {
            assert_eq!(calculate_total_emission(&[]), Amount::from_atoms(0));
        }
    }

    #[test]
    fn chain_type_names() {
        use strum::VariantNames;

        assert_eq!(&ChainType::Mainnet.to_string(), "mainnet");
        assert_eq!(&ChainType::Testnet.to_string(), "testnet");

        for chain_type_str in ChainType::VARIANTS {
            let chain_type: ChainType = chain_type_str.parse().expect("cannot parse chain type");
            assert_eq!(&chain_type.to_string(), chain_type_str);
        }
    }

    #[test]
    fn different_magic_bytes() {
        let config1 = TestChainConfig::new().build();
        let config2 = TestChainConfig::new().with_magic_bytes([1, 2, 3, 4]).build();

        assert_ne!(config1.magic_bytes(), config2.magic_bytes(),);
    }
}
