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

use std::{borrow::Cow, collections::BTreeMap};

use utils::ensure;

use crate::{
    chain::{GenBlock, Genesis},
    primitives::{BlockHeight, Id},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Checkpoints {
    checkpoints: Cow<'static, BTreeMap<BlockHeight, Id<GenBlock>>>,
}

impl Checkpoints {
    pub fn new(
        mut checkpoints: BTreeMap<BlockHeight, Id<GenBlock>>,
        genesis_id: Id<Genesis>,
    ) -> Result<Self, CheckpointsError> {
        use std::collections::btree_map::Entry;

        let genesis_id: Id<GenBlock> = genesis_id.into();

        match checkpoints.entry(0.into()) {
            Entry::Vacant(entry) => {
                entry.insert(genesis_id);
            }
            Entry::Occupied(entry) => ensure!(
                entry.get() == &genesis_id,
                CheckpointsError::GenesisMismatch {
                    expected: genesis_id,
                    actual: *entry.get()
                }
            ),
        }

        Ok(Self {
            checkpoints: Cow::Owned(checkpoints),
        })
    }

    pub fn new_static(
        checkpoints: &'static BTreeMap<BlockHeight, Id<GenBlock>>,
        expected_genesis_id: &Id<Genesis>,
    ) -> Result<Self, CheckpointsError> {
        let expected_genesis_id: &Id<GenBlock> = expected_genesis_id.into();
        let actual_genesis_id =
            checkpoints.get(&BlockHeight::new(0)).ok_or(CheckpointsError::GenesisMissing)?;
        ensure!(
            actual_genesis_id == expected_genesis_id,
            CheckpointsError::GenesisMismatch {
                expected: *expected_genesis_id,
                actual: *actual_genesis_id
            }
        );

        Ok(Self {
            checkpoints: Cow::Borrowed(checkpoints),
        })
    }

    pub fn checkpoint_at_height(&self, height: &BlockHeight) -> Option<&Id<GenBlock>> {
        self.checkpoints.get(height)
    }

    pub fn parent_checkpoint_to_height(&self, height: BlockHeight) -> (BlockHeight, Id<GenBlock>) {
        let cp = self
            .checkpoints
            .range(..=height)
            .next_back()
            .expect("Genesis must be there, at least");
        (*cp.0, *cp.1)
    }

    pub fn last_checkpoint(&self) -> (BlockHeight, Id<GenBlock>) {
        let (height, cp) =
            self.checkpoints.last_key_value().expect("Genesis must be there, at least");
        (*height, *cp)
    }

    #[cfg(test)]
    pub fn checkpoints_map(&self) -> &BTreeMap<BlockHeight, Id<GenBlock>> {
        &self.checkpoints
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum CheckpointsError {
    #[error("Genesis missing")]
    GenesisMissing,

    #[error("Genesis mismatch, expected: {expected:x}, actual: {actual:x}")]
    GenesisMismatch {
        expected: Id<GenBlock>,
        actual: Id<GenBlock>,
    },
}

#[cfg(test)]
mod tests {
    use once_cell::sync::OnceCell;

    use rstest::rstest;

    use test_utils::{
        assert_matches,
        random::{make_seedable_rng, Rng, Seed},
    };

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_creation(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let genesis1_id = Id::random_using(&mut rng);
        let genesis1_gen_block_id: Id<GenBlock> = genesis1_id.into();
        let genesis2_id: Id<Genesis> = Id::random_using(&mut rng);

        // new
        {
            let checkpoints = Checkpoints::new(BTreeMap::new(), genesis1_id).unwrap();
            assert_eq!(
                checkpoints.checkpoint_at_height(&BlockHeight::zero()).unwrap(),
                &genesis1_gen_block_id
            );

            let error = Checkpoints::new(
                BTreeMap::from([(BlockHeight::zero(), genesis2_id.into())]),
                genesis1_id,
            )
            .unwrap_err();
            assert_matches!(error, CheckpointsError::GenesisMismatch { .. });
        }

        // new_static
        {
            static MAP: OnceCell<BTreeMap<BlockHeight, Id<GenBlock>>> = OnceCell::new();
            MAP.get_or_init(|| BTreeMap::from([(BlockHeight::zero(), genesis1_id.into())]));

            let checkpoints = Checkpoints::new_static(MAP.get().unwrap(), &genesis1_id).unwrap();
            assert_eq!(
                checkpoints.checkpoint_at_height(&BlockHeight::zero()).unwrap(),
                &genesis1_gen_block_id
            );

            let error = Checkpoints::new_static(MAP.get().unwrap(), &genesis2_id).unwrap_err();
            assert_matches!(error, CheckpointsError::GenesisMismatch { .. });
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parent_checkpoint_to_height_with_checkpoints(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let genesis_id = Id::random_using(&mut rng);
        let checkpoints_map = {
            let mut checkpoints_map = BTreeMap::new();
            checkpoints_map.insert(BlockHeight::new(0), genesis_id.into());
            checkpoints_map.insert(BlockHeight::new(5), Id::random_using(&mut rng));
            checkpoints_map.insert(BlockHeight::new(10), Id::random_using(&mut rng));
            checkpoints_map.insert(BlockHeight::new(15), Id::random_using(&mut rng));
            checkpoints_map
        };
        let checkpoints = if rng.gen_bool(0.5) {
            Checkpoints::new(checkpoints_map.clone(), genesis_id).unwrap()
        } else {
            static MAP: OnceCell<BTreeMap<BlockHeight, Id<GenBlock>>> = OnceCell::new();
            MAP.get_or_init(|| checkpoints_map.clone());
            Checkpoints::new_static(MAP.get().unwrap(), &genesis_id).unwrap()
        };

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(0)),
            (0.into(), *checkpoints_map.get(&0.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(1)),
            (0.into(), *checkpoints_map.get(&0.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(4)),
            (0.into(), *checkpoints_map.get(&0.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(5)),
            (5.into(), *checkpoints_map.get(&5.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(6)),
            (5.into(), *checkpoints_map.get(&5.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(9)),
            (5.into(), *checkpoints_map.get(&5.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(10)),
            (10.into(), *checkpoints_map.get(&10.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(11)),
            (10.into(), *checkpoints_map.get(&10.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(14)),
            (10.into(), *checkpoints_map.get(&10.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(15)),
            (15.into(), *checkpoints_map.get(&15.into()).unwrap()),
        );

        assert_eq!(
            checkpoints.parent_checkpoint_to_height(BlockHeight::new(16)),
            (15.into(), *checkpoints_map.get(&15.into()).unwrap()),
        );

        // Anything above the last checkpoint should return the last checkpoint
        assert_eq!(
            checkpoints
                .parent_checkpoint_to_height(BlockHeight::new(rng.gen::<u64>().saturating_add(15))),
            (15.into(), *checkpoints_map.get(&15.into()).unwrap()),
        );

        for i in 15..10000 {
            assert_eq!(
                checkpoints.parent_checkpoint_to_height(BlockHeight::new(i)),
                (15.into(), *checkpoints_map.get(&15.into()).unwrap()),
                "Parent checkpoint to height {} should be 15",
                i
            );
        }
    }
}
