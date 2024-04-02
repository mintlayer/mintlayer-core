// Copyright (c) 2023 RBB S.r.l
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

use std::num::NonZeroU64;

use chainstate_types::{BlockIndex, BlockIndexHandle, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{
        block::ConsensusData, ChainConfig, GenBlock, GenBlockId, PoSChainConfig, PoSStatus,
        RequiredConsensus,
    },
    primitives::{BlockDistance, BlockHeight, Compact, Id},
    Uint256, Uint512,
};
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

fn calculate_average_block_time<F>(
    pos_config: &PoSChainConfig,
    block_index: &BlockIndex,
    get_ancestor: F,
) -> Result<u64, ConsensusPoSError>
where
    F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    // Average is calculated based on 2 timestamps and then is divided by number of blocks in between.
    // Choose a block from the history that would be the start of a timespan.
    // It can cross net version but not genesis.
    let block_distance_to_average =
        BlockDistance::new(pos_config.block_count_to_average_for_blocktime() as i64 - 1);
    let block_height_to_start_averaging =
        (block_index.block_height() - block_distance_to_average).unwrap_or(BlockHeight::zero());

    ensure!(
        block_index.block_height() > block_height_to_start_averaging,
        ConsensusPoSError::EmptyTimespan
    );

    let time_span_start = get_ancestor(block_index, block_height_to_start_averaging)?
        .block_timestamp()
        .as_int_seconds();
    let current_block_time = block_index.block_timestamp().as_int_seconds();

    let timespan_difference = current_block_time
        .checked_sub(time_span_start)
        .ok_or(ConsensusPoSError::InvariantBrokenNotMonotonicBlockTime)?;
    let block_distance_in_timespan: i64 = (block_index.block_height()
        - block_height_to_start_averaging)
        .expect("cannot be negative")
        .into();

    let average = timespan_difference / block_distance_in_timespan as u64;

    Ok(average)
}

fn calculate_new_target(
    pos_config: &PoSChainConfig,
    prev_target: &Uint256,
    actual_block_time: u64,
    target_block_time: NonZeroU64,
) -> Result<Compact, ConsensusPoSError> {
    let actual_block_time = if actual_block_time == 0 {
        Uint512::ONE
    } else {
        Uint512::from_u64(actual_block_time)
    };

    let prev_target: Uint512 = (*prev_target).into();

    let new_target = {
        let numerator =
            (prev_target * actual_block_time).expect("Source types are smaller than these types");
        let denominator = Uint512::from_u64(target_block_time.get());
        (numerator / denominator).expect("Target block time is not zero given its type")
    };

    let difficulty_change_limit = {
        let numerator = (prev_target
            * Uint512::from_u64(pos_config.difficulty_change_limit().value().into()))
        .expect("Original types are smaller");
        let denominator = Uint512::from_u64(1000);
        (numerator / denominator).expect("Denominator is not zero")
    };

    let lower_limit = (prev_target - difficulty_change_limit)
        .expect("Cannot fail because difficulty_change_limit is in [0, 1]");
    let upper_limit = (prev_target + difficulty_change_limit)
        .expect("Cannot fail because it was converted from Uint256 to Uint512");
    let new_target = num::clamp(new_target, lower_limit, upper_limit);
    let new_target = Uint256::try_from(new_target).unwrap_or(pos_config.target_limit());

    let new_target = std::cmp::min(new_target, pos_config.target_limit());
    Ok(Compact::from(new_target))
}

pub fn calculate_target_required_from_block_index<F>(
    chain_config: &ChainConfig,
    pos_status: &PoSStatus,
    prev_gen_block_index: &GenBlockIndex,
    get_ancestor: F,
) -> Result<Compact, ConsensusPoSError>
where
    F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    let pos_config = match pos_status {
        PoSStatus::Threshold {
            initial_difficulty,
            config,
        } => match initial_difficulty {
            Some(difficulty) => return Ok(*difficulty),
            None => config,
        },
        PoSStatus::Ongoing(config) => config,
    };

    let prev_block_index = match prev_gen_block_index {
        GenBlockIndex::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockIndex::Block(block_index) => block_index,
    };

    calculate_target_required_internal(chain_config, pos_config, prev_block_index, get_ancestor)
}

pub fn calculate_target_required(
    chain_config: &ChainConfig,
    pos_status: &PoSStatus,
    prev_block_id: Id<GenBlock>,
    block_index_handle: &impl BlockIndexHandle,
) -> Result<Compact, ConsensusPoSError> {
    let pos_config = match pos_status {
        PoSStatus::Threshold {
            initial_difficulty,
            config,
        } => match initial_difficulty {
            Some(difficulty) => return Ok(*difficulty),
            None => config,
        },
        PoSStatus::Ongoing(config) => config,
    };

    let prev_block_id = match prev_block_id.classify(chain_config) {
        GenBlockId::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockId::Block(id) => id,
    };

    let prev_block_index = block_index_handle
        .get_block_index(&prev_block_id)?
        .ok_or(ConsensusPoSError::PrevBlockIndexNotFound(prev_block_id))?;

    let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
        block_index_handle.get_ancestor(block_index, ancestor_height)
    };

    calculate_target_required_internal(chain_config, pos_config, &prev_block_index, get_ancestor)
}

fn calculate_target_required_internal<F>(
    chain_config: &ChainConfig,
    pos_config: &PoSChainConfig,
    prev_block_index: &BlockIndex,
    get_ancestor: F,
) -> Result<Compact, ConsensusPoSError>
where
    F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    // check if prev block is a net upgrade threshold
    match chain_config
        .consensus_upgrades()
        .consensus_status(prev_block_index.block_height())
    {
        RequiredConsensus::PoS(status) => match status {
            PoSStatus::Threshold {
                initial_difficulty,
                config: _,
            } => {
                if let Some(difficulty) = initial_difficulty {
                    return Ok(difficulty);
                }
            }
            PoSStatus::Ongoing(_) => { /*do nothing*/ }
        },
        RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
            panic!("Prev block's consensus status must be PoS because we are in Ongoing PoS net version")
        }
    };

    let prev_target: Uint256 = match prev_block_index.block_header().consensus_data() {
        ConsensusData::None | ConsensusData::PoW(_) => {
            panic!(
                "Prev block's consensus data must be PoS because we are in Ongoing PoS net version"
            )
        }
        ConsensusData::PoS(data) => {
            let compact_target = data.compact_target();
            compact_target
                .try_into()
                .map_err(|_| ConsensusPoSError::DecodingBitsFailed(compact_target))?
        }
    };

    let average_block_time =
        calculate_average_block_time(pos_config, prev_block_index, get_ancestor)?;

    let target_block_time = NonZeroU64::new(chain_config.target_block_spacing().as_secs())
        .ok_or(ConsensusPoSError::InvalidTargetBlockTime)?;

    calculate_new_target(
        pos_config,
        &prev_target,
        average_block_time,
        target_block_time,
    )
}

#[cfg(test)]
mod tests {
    use chainstate_types::{
        BlockIndex, BlockStatus, GenBlockIndex, GetAncestorError, PropertyQueryError,
    };
    use common::{
        chain::{
            block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward},
            config::Builder as ConfigBuilder,
            Block, ConsensusUpgrade, GenBlock, Genesis, NetUpgrades, PoSChainConfigBuilder, PoolId,
        },
        primitives::{per_thousand::PerThousand, Idable, H256},
    };
    use crypto::{
        random::{CryptoRng, Rng},
        vrf::{transcript::TranscriptAssembler, VRFKeyKind, VRFPrivateKey},
    };
    use itertools::Itertools;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    fn make_block(
        rng: &mut (impl Rng + CryptoRng),
        prev_block: Id<GenBlock>,
        timestamp: BlockTimestamp,
        target: Uint256,
    ) -> Block {
        let (sk, _) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let vrf_data = sk.produce_vrf_data(TranscriptAssembler::new(b"abc").finalize().into());
        Block::new(
            vec![],
            prev_block,
            timestamp,
            ConsensusData::PoS(Box::new(PoSData::new(
                vec![],
                vec![],
                PoolId::new(H256::zero()),
                vrf_data,
                Compact::from(target),
            ))),
            BlockReward::new(vec![]),
        )
        .unwrap()
    }

    struct TestBlockIndexHandle<'a> {
        chain_config: &'a ChainConfig,
        blocks: Vec<(BlockHeight, BlockIndex)>,
    }

    impl<'a> TestBlockIndexHandle<'a> {
        pub fn new(chain_config: &'a ChainConfig) -> Self {
            Self {
                blocks: Default::default(),
                chain_config,
            }
        }

        pub fn new_with_blocks(
            rng: &mut (impl Rng + CryptoRng),
            chain_config: &'a ChainConfig,
            timestamps: &[u64],
        ) -> Self {
            let mut best_block = chain_config.genesis_block_id();
            let blocks = timestamps
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    let height = i as u64 + 1;
                    let timestamp = BlockTimestamp::from_int_seconds(*t);
                    let block = make_block(rng, best_block, timestamp, Uint256::ZERO);
                    let block_index = BlockIndex::new(
                        &block,
                        Uint256::ZERO,
                        best_block,
                        height.into(),
                        timestamp,
                        0,
                        BlockStatus::new(),
                    );
                    best_block = block.get_id().into();
                    (height.into(), block_index)
                })
                .collect::<Vec<_>>();

            Self {
                blocks,
                chain_config,
            }
        }

        pub fn blocks_iter(&self) -> impl Iterator<Item = &BlockIndex> {
            self.blocks.iter().map(|(_, block_index)| block_index)
        }

        pub fn get_block_index_by_height(&self, height: BlockHeight) -> Option<&BlockIndex> {
            self.blocks
                .iter()
                .find(|(block_height, _)| height == *block_height)
                .map(|(_, b)| b)
        }

        pub fn add_block_index(&mut self, height: BlockHeight, block_index: BlockIndex) {
            self.blocks.push((height, block_index))
        }
    }

    impl<'a> BlockIndexHandle for TestBlockIndexHandle<'a> {
        fn get_block_index(
            &self,
            block_id: &Id<Block>,
        ) -> Result<Option<BlockIndex>, PropertyQueryError> {
            Ok(self
                .blocks
                .iter()
                .find(|(_, block)| block_id == block.block_id())
                .map(|(_, b)| b.clone()))
        }

        fn get_gen_block_index(
            &self,
            _block_id: &Id<GenBlock>,
        ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
            unimplemented!()
        }

        fn get_ancestor(
            &self,
            block_index: &BlockIndex,
            ancestor_height: BlockHeight,
        ) -> Result<GenBlockIndex, PropertyQueryError> {
            if !self.blocks.iter().any(|(_, block)| block_index.block_id() == block.block_id()) {
                // if block is not in the current index then it cannot have ancestor
                return Err(PropertyQueryError::GetAncestorError(
                    GetAncestorError::PrevBlockIndexNotFound((*block_index.block_id()).into()),
                ));
            }

            if ancestor_height == BlockHeight::new(0) {
                Ok(GenBlockIndex::genesis(self.chain_config))
            } else {
                Ok(self
                    .get_block_index_by_height(ancestor_height)
                    .ok_or(GetAncestorError::PrevBlockIndexNotFound(
                        (*block_index.block_id()).into(),
                    ))?
                    .clone()
                    .into_gen_block_index())
            }
        }

        fn get_block_reward(
            &self,
            _block_index: &BlockIndex,
        ) -> Result<Option<common::chain::block::BlockReward>, PropertyQueryError> {
            unimplemented!()
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_new_target_test(#[case] seed: Seed) {
        let target_block_time = NonZeroU64::new(120).unwrap();
        let mut rng = make_seedable_rng(seed);
        let config = PoSChainConfigBuilder::new_for_unit_test().build();
        {
            // average block time <= target block time
            let prev_target = Uint256::from_u64(rng.gen::<u64>());
            let average_block_time = target_block_time.get() / rng.gen_range(1..10);
            let new_target =
                calculate_new_target(&config, &prev_target, average_block_time, target_block_time)
                    .unwrap();
            assert!(new_target <= Compact::from(prev_target));
        }
        {
            // average block time >= target block time
            let prev_target = Uint256::from_u64(rng.gen::<u64>());
            let average_block_time = target_block_time.get() * rng.gen_range(1..10);
            let new_target =
                calculate_new_target(&config, &prev_target, average_block_time, target_block_time)
                    .unwrap();
            assert!(new_target >= Compact::from(prev_target));
        }
    }

    #[test]
    fn calculate_new_target_swing_limit() {
        let target_block_time = NonZeroU64::new(100).unwrap();
        let config = PoSChainConfigBuilder::new_for_unit_test()
            .block_count_to_average_for_blocktime(2)
            .difficulty_change_limit(PerThousand::new(100).unwrap())
            .build();

        {
            let actual_block_time = 1000; // 10 times bigger

            let prev_target = Uint256::from_u64(100);
            let expected_target = Uint256::from_u64(110); // only 10% times bigger

            let new_target =
                calculate_new_target(&config, &prev_target, actual_block_time, target_block_time)
                    .unwrap();
            assert_eq!(new_target, Compact::from(expected_target));
        }

        {
            let actual_block_time = 10; // 10 times smaller

            let prev_target = Uint256::from_u64(100);
            let expected_target = Uint256::from_u64(90); // only 10% times smaller

            let new_target =
                calculate_new_target(&config, &prev_target, actual_block_time, target_block_time)
                    .unwrap();
            assert_eq!(new_target, Compact::from(expected_target));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_new_target_too_easy(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let config = PoSChainConfigBuilder::new_for_unit_test()
            .targe_limit(Uint256::ZERO)
            .block_count_to_average_for_blocktime(2)
            .build();
        let target_block_time = NonZeroU64::new(120).unwrap();
        let prev_target = H256::random_using(&mut rng).into();
        let new_target = calculate_new_target(
            &config,
            &prev_target,
            target_block_time.get(),
            target_block_time,
        )
        .unwrap();

        assert_eq!(new_target, Compact::from(config.target_limit()));
    }

    #[test]
    fn calculate_new_target_with_overflow() {
        let config = PoSChainConfigBuilder::new_for_unit_test()
            .targe_limit(Uint256::ONE)
            .block_count_to_average_for_blocktime(2)
            .build();
        let target_block_time = NonZeroU64::new(1).unwrap();
        let prev_target = Uint256::MAX;
        let new_target =
            calculate_new_target(&config, &prev_target, u64::MAX, target_block_time).unwrap();

        assert_eq!(new_target, Compact::from(config.target_limit()));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_block_time_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = PoSChainConfigBuilder::new_for_unit_test()
            .block_count_to_average_for_blocktime(5)
            .build();
        let upgrades = vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(Uint256::MAX.into()),
                config: pos_config.clone(),
            },
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        let block_index_handle = TestBlockIndexHandle::new_with_blocks(
            &mut rng,
            &chain_config,
            &[10, 20, 60, 80, 100, 101, 102, 103],
        );

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        let average_block_time = calculate_average_block_time(
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(1)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 10);

        let average_block_time = calculate_average_block_time(
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(2)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 10);

        let average_block_time = calculate_average_block_time(
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(5)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 22);

        let average_block_time = calculate_average_block_time(
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(8)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 5);
    }

    // Average time between 2 block is the time difference itself
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_time_between_2_blocks(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = PoSChainConfigBuilder::new_for_unit_test()
            .block_count_to_average_for_blocktime(2)
            .build();
        let upgrades = vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(Uint256::MAX.into()),
                config: pos_config.clone(),
            },
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        let block_index_handle =
            TestBlockIndexHandle::new_with_blocks(&mut rng, &chain_config, &[10, 30]);

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        // calculating average between 2 blocks with timestamps 10 and 30 should give 20
        let average_block_time = calculate_average_block_time(
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(2)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 20);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_time_between_3_blocks(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = PoSChainConfigBuilder::new_for_unit_test()
            .block_count_to_average_for_blocktime(3)
            .build();
        let upgrades = vec![(
            BlockHeight::new(0),
            ConsensusUpgrade::PoS {
                initial_difficulty: Some(Uint256::MAX.into()),
                config: pos_config.clone(),
            },
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        let block_index_handle =
            TestBlockIndexHandle::new_with_blocks(&mut rng, &chain_config, &[10, 20, 40]);

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        let average_block_time = calculate_average_block_time(
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(3)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 15);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_block_time_no_ancestor(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = PoSChainConfigBuilder::new_for_unit_test().build();
        let net_upgrades = NetUpgrades::regtest_with_pos();
        let chain_config = ConfigBuilder::test_chain().consensus_upgrades(net_upgrades).build();

        let block_index_handle = TestBlockIndexHandle::new(&chain_config);
        let timestamp = BlockTimestamp::from_int_seconds(100);
        let random_block_id = Id::<Block>::new(H256::random_using(&mut rng));
        let random_block = make_block(&mut rng, random_block_id.into(), timestamp, Uint256::MAX);
        let random_block_index = BlockIndex::new(
            &random_block,
            Uint256::ZERO,
            random_block_id.into(),
            BlockHeight::new(1),
            timestamp,
            0,
            BlockStatus::new(),
        );

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        let res = calculate_average_block_time(&pos_config, &random_block_index, get_ancestor)
            .unwrap_err();
        assert_eq!(
            res,
            ConsensusPoSError::PropertyQueryError(PropertyQueryError::GetAncestorError(
                GetAncestorError::PrevBlockIndexNotFound(random_block.get_id().into())
            ))
        );
    }

    fn get_pos_status(chain_config: &ChainConfig, height: BlockHeight) -> PoSStatus {
        match chain_config.consensus_upgrades().consensus_status(height) {
            RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
                panic!("invalid consensus")
            }
            RequiredConsensus::PoS(pos_status) => pos_status,
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_target_required_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let target_limit_1 = Uint256::from_u64(rng.gen::<u64>());
        let target_limit_2 = Uint256::from_u64(rng.gen::<u64>());
        let pos_config_1 = PoSChainConfigBuilder::new_for_unit_test()
            .targe_limit(target_limit_1)
            .block_count_to_average_for_blocktime(2)
            .build();
        let pos_config_2 = PoSChainConfigBuilder::new_for_unit_test()
            .targe_limit(target_limit_2)
            .block_count_to_average_for_blocktime(5)
            .build();
        let upgrades = vec![
            (
                BlockHeight::new(0),
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(Compact::from(target_limit_1)),
                    config: pos_config_1,
                },
            ),
            (
                BlockHeight::new(3),
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(Compact::from(target_limit_2)),
                    config: pos_config_2,
                },
            ),
        ];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        let block_index_handle = TestBlockIndexHandle::new_with_blocks(
            &mut rng,
            &chain_config,
            &[1, 2, 6, 8, 10, 12, 14],
        );

        {
            // check with prev genesis
            let pos_status = get_pos_status(&chain_config, BlockHeight::new(1));
            let block_header = block_index_handle
                .get_block_index_by_height(BlockHeight::new(1))
                .unwrap()
                .block_header();
            let target = calculate_target_required(
                &chain_config,
                &pos_status,
                *block_header.prev_block_id(),
                &block_index_handle,
            )
            .unwrap();
            assert_eq!(target, Compact::from(target_limit_1));
        }

        {
            // check with ongoing net upgrade
            let pos_status = get_pos_status(&chain_config, BlockHeight::new(2));
            let block_header = block_index_handle
                .get_block_index_by_height(BlockHeight::new(2))
                .unwrap()
                .block_header();
            let target = calculate_target_required(
                &chain_config,
                &pos_status,
                *block_header.prev_block_id(),
                &block_index_handle,
            )
            .unwrap();
            assert_ne!(target, Compact::from(target_limit_1));
        }

        {
            // check net version threshold
            let pos_status = get_pos_status(&chain_config, BlockHeight::new(3));
            let block_header = block_index_handle
                .get_block_index_by_height(BlockHeight::new(3))
                .unwrap()
                .block_header();
            let target = calculate_target_required(
                &chain_config,
                &pos_status,
                *block_header.prev_block_id(),
                &block_index_handle,
            )
            .unwrap();
            assert_eq!(target, Compact::from(target_limit_2));
        }

        {
            // check with ongoing net upgrade
            let pos_status = get_pos_status(&chain_config, BlockHeight::new(7));
            let block_header = block_index_handle
                .get_block_index_by_height(BlockHeight::new(7))
                .unwrap()
                .block_header();
            let target = calculate_target_required(
                &chain_config,
                &pos_status,
                *block_header.prev_block_id(),
                &block_index_handle,
            )
            .unwrap();
            assert_ne!(target, Compact::from(target_limit_2));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn not_monotonic_block_time(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = PoSChainConfigBuilder::new_for_unit_test().build();
        let net_upgrades = NetUpgrades::regtest_with_pos();
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(50),
                vec![],
            ))
            .build();

        let block_index_handle =
            TestBlockIndexHandle::new_with_blocks(&mut rng, &chain_config, &[30, 20, 10]);

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        for i in 1..4 {
            let res = calculate_average_block_time(
                &pos_config,
                block_index_handle.get_block_index_by_height(BlockHeight::new(i)).unwrap(),
                get_ancestor,
            )
            .unwrap_err();
            assert_eq!(res, ConsensusPoSError::InvariantBrokenNotMonotonicBlockTime);
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_target_through_netupgrade(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let target_limit = Uint256::from_u64(rng.gen::<u64>());
        let pos_config = PoSChainConfigBuilder::new_for_unit_test()
            .targe_limit(target_limit)
            .block_count_to_average_for_blocktime(3)
            .build();
        let upgrades = vec![
            (
                BlockHeight::new(0),
                ConsensusUpgrade::PoS {
                    initial_difficulty: Some(Compact::from(target_limit)),
                    config: pos_config.clone(),
                },
            ),
            (
                BlockHeight::new(3),
                ConsensusUpgrade::PoS {
                    initial_difficulty: None,
                    config: pos_config,
                },
            ),
        ];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        let block_index_handle = TestBlockIndexHandle::new_with_blocks(
            &mut rng,
            &chain_config,
            &[1, 2, 6, 8, 10, 12, 14],
        );

        let pos_status = get_pos_status(&chain_config, BlockHeight::new(4));
        let block_header = block_index_handle
            .get_block_index_by_height(BlockHeight::new(4))
            .unwrap()
            .block_header();
        let target = calculate_target_required(
            &chain_config,
            &pos_status,
            *block_header.prev_block_id(),
            &block_index_handle,
        )
        .unwrap();
        assert_ne!(target, Compact::from(target_limit));
    }

    // The test can be enabled on demand to simulate the work of current DAA.
    // It will calculate and print block times for blocks that could be generated over 1_000_000 time slots
    // which is ideally 8333 blocks for 120s target time
    #[ignore]
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn difficulty_adjustment_simulation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let net_upgrades = NetUpgrades::regtest_with_pos();
        let chain_config = ConfigBuilder::test_chain()
            .consensus_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        // generator can be changed to provide different strategies for balance variation
        let pool_balance_generator = |_slot: u64| 1u64;

        let mut block_index_handle =
            TestBlockIndexHandle::new_with_blocks(&mut rng, &chain_config, &[120]);
        let mut tip_height = BlockHeight::one();
        let pos_status = get_pos_status(&chain_config, tip_height.next_height());

        println!("Test settings:\n block_count_to_average_for_blocktime: {},\n difficulty_change_limit: {:?}",
                                   pos_status.get_chain_config().block_count_to_average_for_blocktime(),
                                   pos_status.get_chain_config().difficulty_change_limit());

        for slot in 121..1_000_000 {
            let tip = block_index_handle.get_block_index_by_height(tip_height).unwrap();
            let tip_id = (*tip.block_id()).into();
            let block_timestamp = BlockTimestamp::from_int_seconds(slot);

            // calculate target based on the history data
            let target =
                calculate_target_required(&chain_config, &pos_status, tip_id, &block_index_handle)
                    .unwrap();
            let target = Uint256::try_from(target).unwrap();

            // generate random hash with uniform distr instead of using VRF that is much slower
            let current_hash = {
                let mut words = [0u64; 4];
                for w in &mut words {
                    *w = rng.gen::<u64>();
                }
                Uint256(words)
            };

            let pool_balance = Uint512::from_u64(pool_balance_generator(slot));
            let target_u512: Uint512 = target.into();
            let current_hash: Uint512 = current_hash.into();

            // add block if hash satisfies the target
            if current_hash <= (target_u512 * pool_balance).unwrap() {
                let block = make_block(&mut rng, tip_id, block_timestamp, target);
                tip_height = tip_height.next_height();
                let new_tip = BlockIndex::new(
                    &block,
                    Uint256::ZERO,
                    tip_id,
                    tip_height,
                    block_timestamp,
                    0,
                    BlockStatus::new(),
                );
                block_index_handle.add_block_index(tip_height, new_tip);
            }
        }
        println!("tip height {}", tip_height);

        // print result block times
        block_index_handle.blocks_iter().tuple_windows::<(_, _)>().for_each(|(a, b)| {
            let block_time =
                b.block_timestamp().as_int_seconds() - a.block_timestamp().as_int_seconds();
            println!("{}", block_time);
        });
    }
}
