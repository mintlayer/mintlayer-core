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
    chain_config: &ChainConfig,
    pos_config: &PoSChainConfig,
    block_index: &BlockIndex,
    get_ancestor: F,
) -> Result<u64, ConsensusPoSError>
where
    F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    // Determine net upgrade version that current block belongs to.
    // Across versions config parameters might change so it's invalid to mix versions for target calculations
    let (_, net_version) = chain_config
        .net_upgrade()
        .version_at_height(block_index.block_height())
        .expect("NetUpgrade must've been initialized");
    let net_version_range = chain_config
        .net_upgrade()
        .height_range(net_version)
        .expect("NetUpgrade must've been initialized");

    // Average is calculated based on 2 timestamps and then is divided by number of blocks in between.
    // Choose a block from the history that would be the start of a timespan.
    // It shouldn't cross net version range or genesis.
    let block_count_to_average =
        BlockDistance::new(pos_config.block_count_to_average_for_blocktime() as i64);
    let block_height_to_stare_averaging =
        (block_index.block_height() - block_count_to_average).unwrap_or(BlockHeight::zero());
    let timespan_start_height =
        std::cmp::max(net_version_range.start, block_height_to_stare_averaging);

    let time_span_start = get_ancestor(block_index, timespan_start_height)?
        .block_timestamp()
        .as_int_seconds();
    let current_block_time = block_index.block_timestamp().as_int_seconds();

    let timespan_difference = current_block_time
        .checked_sub(time_span_start)
        .ok_or(ConsensusPoSError::InvariantBrokenNotMonotonicBlockTime)?;
    let blocks_in_timespan: i64 = (block_index.block_height() - timespan_start_height)
        .expect("cannot be negative")
        .into();

    let average = timespan_difference / blocks_in_timespan as u64;

    Ok(average)
}

fn calculate_new_target(
    pos_config: &PoSChainConfig,
    prev_target: &Uint256,
    actual_block_time: u64,
) -> Result<Compact, ConsensusPoSError> {
    let actual_block_time = Uint512::from_u64(actual_block_time);
    let target_block_time = Uint512::from_u64(pos_config.target_block_time().get());
    ensure!(
        target_block_time > Uint512::ZERO,
        ConsensusPoSError::InvalidTargetBlockTime
    );
    let prev_target: Uint512 = (*prev_target).into();

    // TODO: limiting factor (mintlayer/mintlayer-core#787)
    let new_target = prev_target * actual_block_time / target_block_time;
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
            initial_difficulty, ..
        } => return Ok(*initial_difficulty),
        PoSStatus::Ongoing(config) => config,
    };

    let prev_block_index = match prev_gen_block_index {
        GenBlockIndex::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockIndex::Block(block_index) => block_index,
    };

    calculate_target_required_internal(chain_config, pos_config, prev_block_index, get_ancestor)
}

pub fn calculate_target_required<F>(
    chain_config: &ChainConfig,
    pos_status: &PoSStatus,
    prev_block_id: Id<GenBlock>,
    block_index_handle: &impl BlockIndexHandle,
    get_ancestor: F,
) -> Result<Compact, ConsensusPoSError>
where
    F: Fn(&BlockIndex, BlockHeight) -> Result<GenBlockIndex, PropertyQueryError>,
{
    let pos_config = match pos_status {
        PoSStatus::Threshold {
            initial_difficulty,
            config: _,
        } => return Ok(*initial_difficulty),
        PoSStatus::Ongoing(config) => config,
    };

    let prev_block_id = match prev_block_id.classify(chain_config) {
        GenBlockId::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockId::Block(id) => id,
    };

    let prev_block_index = block_index_handle
        .get_block_index(&prev_block_id)?
        .ok_or(ConsensusPoSError::PrevBlockIndexNotFound(prev_block_id))?;

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
    match chain_config.net_upgrade().consensus_status(prev_block_index.block_height()) {
        RequiredConsensus::PoS(status) => match status {
            PoSStatus::Threshold {
                initial_difficulty, ..
            } => return Ok(initial_difficulty),
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
        calculate_average_block_time(chain_config, pos_config, prev_block_index, get_ancestor)?;

    calculate_new_target(pos_config, &prev_target, average_block_time)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chainstate_types::{BlockIndex, GenBlockIndex, GetAncestorError, PropertyQueryError};
    use common::{
        chain::{
            block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward},
            config::Builder as ConfigBuilder,
            create_unittest_pos_config, Block, ConsensusUpgrade, GenBlock, Genesis, NetUpgrades,
            PoolId, UpgradeVersion,
        },
        primitives::{Idable, H256},
    };
    use crypto::{
        random::{CryptoRng, Rng},
        vrf::{transcript::TranscriptAssembler, VRFKeyKind, VRFPrivateKey},
    };
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    fn make_block(
        rng: &mut (impl Rng + CryptoRng),
        prev_block: Id<GenBlock>,
        timestamp: BlockTimestamp,
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
                Compact(rng.gen_range(1..1000)),
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
                    let block = make_block(rng, best_block, timestamp);
                    let block_index = BlockIndex::new(
                        &block,
                        Uint256::ZERO,
                        best_block,
                        height.into(),
                        timestamp,
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

        pub fn get_block_index_by_height(&self, height: BlockHeight) -> Option<&BlockIndex> {
            self.blocks
                .iter()
                .find(|(block_height, _)| height == *block_height)
                .map(|(_, b)| b)
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
                Ok(GenBlockIndex::Genesis(Arc::clone(
                    self.chain_config.genesis_block(),
                )))
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

        fn get_epoch_data(
            &self,
            _epoch_index: u64,
        ) -> Result<Option<chainstate_types::EpochData>, PropertyQueryError> {
            unimplemented!()
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_new_target_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let config = create_unittest_pos_config();
        {
            // average block time <= target block time
            let prev_target = Uint256::from_u64(rng.gen::<u64>());
            let average_block_time = config.target_block_time().get() / rng.gen_range(1..10);
            let new_target =
                calculate_new_target(&config, &prev_target, average_block_time).unwrap();
            assert!(new_target <= Compact::from(prev_target));
        }
        {
            // average block time >= target block time
            let prev_target = Uint256::from_u64(rng.gen::<u64>());
            let average_block_time = config.target_block_time().get() * rng.gen_range(1..10);
            let new_target =
                calculate_new_target(&config, &prev_target, average_block_time).unwrap();
            assert!(new_target >= Compact::from(prev_target));
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_new_target_too_easy(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let config = PoSChainConfig::new(Uint256::ZERO, 1, 1.into(), 1.into(), 2).unwrap();
        let prev_target = H256::random_using(&mut rng).into();
        let new_target =
            calculate_new_target(&config, &prev_target, config.target_block_time().get()).unwrap();

        assert_eq!(new_target, Compact::from(config.target_limit()));
    }

    #[test]
    fn calculate_new_target_with_overflow() {
        let config = PoSChainConfig::new(Uint256::ONE, 1, 1.into(), 1.into(), 2).unwrap();
        let prev_target = Uint256::MAX;
        let new_target = calculate_new_target(&config, &prev_target, u64::MAX).unwrap();

        assert_eq!(new_target, Compact::from(config.target_limit()));
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_block_time_test(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = create_unittest_pos_config();
        let upgrades = vec![(
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: pos_config.clone(),
            }),
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .net_upgrades(net_upgrades)
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
            &chain_config,
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(1)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 10);

        let average_block_time = calculate_average_block_time(
            &chain_config,
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(2)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 10);

        let average_block_time = calculate_average_block_time(
            &chain_config,
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(5)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 20);

        let average_block_time = calculate_average_block_time(
            &chain_config,
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(8)).unwrap(),
            get_ancestor,
        )
        .unwrap();
        assert_eq!(average_block_time, 8);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_block_time_no_ancestor(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let pos_config = create_unittest_pos_config();
        let upgrades = vec![(
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: Uint256::MAX.into(),
                config: pos_config.clone(),
            }),
        )];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain().net_upgrades(net_upgrades).build();

        let block_index_handle = TestBlockIndexHandle::new(&chain_config);
        let timestamp = BlockTimestamp::from_int_seconds(100);
        let random_block_id = Id::<Block>::new(H256::random_using(&mut rng));
        let random_block = make_block(&mut rng, random_block_id.into(), timestamp);
        let random_block_index = BlockIndex::new(
            &random_block,
            Uint256::ZERO,
            random_block_id.into(),
            BlockHeight::new(1),
            timestamp,
        );

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        let res = calculate_average_block_time(
            &chain_config,
            &pos_config,
            &random_block_index,
            get_ancestor,
        )
        .unwrap_err();
        assert_eq!(
            res,
            ConsensusPoSError::PropertyQueryError(PropertyQueryError::GetAncestorError(
                GetAncestorError::PrevBlockIndexNotFound(random_block.get_id().into())
            ))
        );
    }

    fn get_pos_status(chain_config: &ChainConfig, height: BlockHeight) -> PoSStatus {
        match chain_config.net_upgrade().consensus_status(height) {
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
        let pos_config_1 = PoSChainConfig::new(target_limit_1, 10, 1.into(), 1.into(), 2).unwrap();
        let pos_config_2 = PoSChainConfig::new(target_limit_2, 20, 1.into(), 1.into(), 5).unwrap();
        let upgrades = vec![
            (
                BlockHeight::new(0),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                    initial_difficulty: Compact::from(target_limit_1),
                    config: pos_config_1,
                }),
            ),
            (
                BlockHeight::new(3),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                    initial_difficulty: Compact::from(target_limit_2),
                    config: pos_config_2,
                }),
            ),
        ];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .net_upgrades(net_upgrades)
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

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

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
                get_ancestor,
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
                get_ancestor,
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
                get_ancestor,
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
                get_ancestor,
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
        let pos_config = create_unittest_pos_config();
        let upgrades = vec![
            (
                BlockHeight::new(0),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
            ),
            (
                BlockHeight::new(1),
                UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                    initial_difficulty: Uint256::MAX.into(),
                    config: pos_config.clone(),
                }),
            ),
        ];
        let net_upgrades = NetUpgrades::initialize(upgrades).expect("valid net-upgrades");
        let chain_config = ConfigBuilder::test_chain()
            .net_upgrades(net_upgrades)
            .genesis_custom(Genesis::new(
                "msg".to_owned(),
                BlockTimestamp::from_int_seconds(0),
                vec![],
            ))
            .build();

        let block_index_handle =
            TestBlockIndexHandle::new_with_blocks(&mut rng, &chain_config, &[30, 20, 10]);

        let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
            block_index_handle.get_ancestor(block_index, ancestor_height)
        };

        let res = calculate_average_block_time(
            &chain_config,
            &pos_config,
            block_index_handle.get_block_index_by_height(BlockHeight::new(3)).unwrap(),
            get_ancestor,
        )
        .unwrap_err();
        assert_eq!(res, ConsensusPoSError::InvariantBrokenNotMonotonicBlockTime);
    }
}
