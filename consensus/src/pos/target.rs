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

use chainstate_types::{BlockIndexHandle, BlockIndexHistoryIterator};
use common::{
    chain::{
        block::ConsensusData, Block, ChainConfig, GenBlock, GenBlockId, PoSChainConfig, PoSStatus,
        RequiredConsensus,
    },
    primitives::{BlockHeight, Compact, Id},
    Uint256,
};
use itertools::Itertools;
use utils::ensure;

use crate::pos::error::ConsensusPoSError;

fn calculate_average_block_time(
    chain_config: &ChainConfig,
    pos_config: &PoSChainConfig,
    block_id: Id<Block>,
    block_height: BlockHeight,
    block_index_handle: &impl BlockIndexHandle,
) -> Result<u64, ConsensusPoSError> {
    let history_iter = BlockIndexHistoryIterator::new(block_id.into(), block_index_handle);

    // Determine net upgrade version that current block belongs to.
    // Across versions config parameters might change so it's invalid to mix versions for target calculations
    let (_, net_version) = chain_config
        .net_upgrade()
        .version_at_height(block_height)
        .expect("NetUpgrade must've been initialized");
    let net_version_range = chain_config
        .net_upgrade()
        .height_range(net_version)
        .expect("NetUpgrade must've been initialized");

    // Get timestamps from the history but make sure they belong to the same consensus version.
    // Then calculate differences of adjacent elements.
    let block_diffs = history_iter
        .take(pos_config.block_count_to_average_for_blocktime())
        .filter(|block_index| net_version_range.contains(&block_index.block_height()))
        .map(|block_index| block_index.block_timestamp().as_int_seconds())
        .tuple_windows::<(u64, u64)>()
        .map(|t| t.0 - t.1);

    let (sum, count) = block_diffs.fold((0u64, 0u64), |(sum, count), curr| (sum + curr, count + 1));

    ensure!(count > 0, ConsensusPoSError::NotEnoughTimestampsToAverage);

    let average = sum / count;

    Ok(average)
}

fn calculate_new_target(
    pos_config: &PoSChainConfig,
    prev_target: &Uint256,
    average_block_time: u64,
) -> Result<Compact, ConsensusPoSError> {
    let average_block_time = Uint256::from_u64(average_block_time);
    let target_block_time = Uint256::from_u64(pos_config.target_block_time().get());

    // TODO: limiting factor (mintlayer/mintlayer-core#787)
    let new_target = *prev_target / target_block_time * average_block_time;

    if new_target > pos_config.target_limit() {
        Ok(Compact::from(pos_config.target_limit()))
    } else {
        Ok(Compact::from(new_target))
    }
}

pub fn calculate_target_required(
    chain_config: &ChainConfig,
    pos_status: &PoSStatus,
    prev_block_id: Id<GenBlock>,
    block_index_handle: &impl BlockIndexHandle,
) -> Result<Compact, ConsensusPoSError> {
    // check if current block is a net upgrade threshold
    let pos_config = match pos_status {
        PoSStatus::Threshold { initial_difficulty } => return Ok(*initial_difficulty),
        PoSStatus::Ongoing { config } => config,
    };

    let prev_block_id = match prev_block_id.classify(chain_config) {
        GenBlockId::Genesis(_) => return Ok(pos_config.target_limit().into()),
        GenBlockId::Block(id) => id,
    };
    let prev_block_index = block_index_handle
        .get_block_index(&prev_block_id)?
        .ok_or(ConsensusPoSError::PrevBlockIndexNotFound(prev_block_id))?;

    // check if prev block is a net upgrade threshold
    match chain_config.net_upgrade().consensus_status(prev_block_index.block_height()) {
        RequiredConsensus::PoS(status) => match status {
            PoSStatus::Threshold { initial_difficulty } => {
                return Ok(initial_difficulty);
            }
            PoSStatus::Ongoing { config: _config } => { /*do nothing*/ }
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

    let average_block_time = calculate_average_block_time(
        chain_config,
        pos_config,
        *prev_block_index.block_id(),
        prev_block_index.block_height(),
        block_index_handle,
    )?;
    calculate_new_target(pos_config, &prev_target, average_block_time)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
    use common::{
        chain::{
            block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward},
            config::Builder as ConfigBuilder,
            create_unittest_pos_config, ConsensusUpgrade, GenBlock, Genesis, NetUpgrades, PoolId,
            UpgradeVersion,
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
        blocks: Vec<(Id<Block>, BlockIndex)>,
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
                    (block.get_id(), block_index)
                })
                .collect::<Vec<_>>();

            Self {
                blocks,
                chain_config,
            }
        }

        pub fn new_with_single_block(chain_config: &'a ChainConfig, block: &Block) -> Self {
            let block_index = BlockIndex::new(
                block,
                Uint256::ZERO,
                block.prev_block_id(),
                0.into(),
                BlockTimestamp::from_int_seconds(1),
            );

            Self {
                blocks: vec![(block.get_id(), block_index)],
                chain_config,
            }
        }

        pub fn get_block_index_by_height(&self, height: usize) -> Option<&BlockIndex> {
            self.blocks.get(height - 1).map(|(_, block_index)| block_index)
        }
    }

    impl<'a> BlockIndexHandle for TestBlockIndexHandle<'a> {
        fn get_block_index(
            &self,
            block_id: &Id<Block>,
        ) -> Result<Option<BlockIndex>, PropertyQueryError> {
            Ok(self.blocks.iter().find(|(id, _)| id == block_id).map(|(_, b)| b.clone()))
        }

        fn get_gen_block_index(
            &self,
            block_id: &Id<GenBlock>,
        ) -> Result<Option<GenBlockIndex>, PropertyQueryError> {
            match block_id.classify(self.chain_config) {
                GenBlockId::Genesis(_) => Ok(Some(GenBlockIndex::Genesis(Arc::clone(
                    self.chain_config.genesis_block(),
                )))),
                GenBlockId::Block(id) => Ok(self
                    .blocks
                    .iter()
                    .find(|(current_id, _)| *current_id == id)
                    .map(|(_, b)| b.clone().into_gen_block_index())),
            }
        }

        fn get_ancestor(
            &self,
            _block_index: &BlockIndex,
            _ancestor_height: common::primitives::BlockHeight,
        ) -> Result<GenBlockIndex, PropertyQueryError> {
            unimplemented!()
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
        let config = PoSChainConfig::new(Uint256::ZERO, 1, 1.into(), 2).unwrap();
        let prev_target = H256::random_using(&mut rng).into();
        let new_target =
            calculate_new_target(&config, &prev_target, config.target_block_time().get()).unwrap();

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

        let block_index_handle =
            TestBlockIndexHandle::new_with_blocks(&mut rng, &chain_config, &[1, 2, 6, 8, 10]);

        let average_block_time = calculate_average_block_time(
            &chain_config,
            &pos_config,
            *block_index_handle.get_block_index_by_height(1).unwrap().block_id(),
            BlockHeight::new(1),
            &block_index_handle,
        )
        .unwrap();
        assert_eq!(average_block_time, 1);

        let average_block_time = calculate_average_block_time(
            &chain_config,
            &pos_config,
            *block_index_handle.get_block_index_by_height(2).unwrap().block_id(),
            BlockHeight::new(2),
            &block_index_handle,
        )
        .unwrap();
        assert_eq!(average_block_time, 1);

        let average_block_time = calculate_average_block_time(
            &chain_config,
            &pos_config,
            *block_index_handle.get_block_index_by_height(5).unwrap().block_id(),
            BlockHeight::new(5),
            &block_index_handle,
        )
        .unwrap();
        assert_eq!(average_block_time, 2);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn calculate_average_block_time_less_than_2_test(#[case] seed: Seed) {
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

        {
            // check that having zero timestamps is not enough to calculate average
            let block_index_handle = TestBlockIndexHandle::new(&chain_config);
            let random_block_id = Id::<Block>::new(H256::random_using(&mut rng));
            assert_eq!(
                0,
                BlockIndexHistoryIterator::new(random_block_id.into(), &block_index_handle).count()
            );

            let res = calculate_average_block_time(
                &chain_config,
                &pos_config,
                random_block_id,
                BlockHeight::new(0),
                &block_index_handle,
            )
            .unwrap_err();
            assert_eq!(res, ConsensusPoSError::NotEnoughTimestampsToAverage);
        }

        {
            // check that having a single timestamp is not enough to calculate average
            let prev_block_id = Id::<Block>::new(H256::random_using(&mut rng));
            let block = make_block(
                &mut rng,
                prev_block_id.into(),
                BlockTimestamp::from_int_seconds(1),
            );
            let block_index_handle =
                TestBlockIndexHandle::new_with_single_block(&chain_config, &block);
            assert_eq!(
                1,
                BlockIndexHistoryIterator::new(block.get_id().into(), &block_index_handle).count()
            );

            let res = calculate_average_block_time(
                &chain_config,
                &pos_config,
                *block_index_handle.get_block_index_by_height(1).unwrap().block_id(),
                BlockHeight::new(0),
                &block_index_handle,
            )
            .unwrap_err();
            assert_eq!(res, ConsensusPoSError::NotEnoughTimestampsToAverage);
        }
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
        let pos_config_1 = PoSChainConfig::new(target_limit_1, 10, 1.into(), 2).unwrap();
        let pos_config_2 = PoSChainConfig::new(target_limit_2, 20, 1.into(), 5).unwrap();
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

        {
            // check with prev genesis
            let pos_status = get_pos_status(&chain_config, BlockHeight::new(1));
            let block_header =
                block_index_handle.get_block_index_by_height(1).unwrap().block_header();
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
            let block_header =
                block_index_handle.get_block_index_by_height(2).unwrap().block_header();
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
            let block_header =
                block_index_handle.get_block_index_by_height(3).unwrap().block_header();
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
            let block_header =
                block_index_handle.get_block_index_by_height(7).unwrap().block_header();
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
}
