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

use std::collections::BTreeMap;

use crate::{
    chain::GenBlock,
    primitives::{BlockHeight, Id},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Checkpoints {
    checkpoints: BTreeMap<BlockHeight, Id<GenBlock>>,
}

impl From<BTreeMap<BlockHeight, Id<GenBlock>>> for Checkpoints {
    fn from(checkpoints: BTreeMap<BlockHeight, Id<GenBlock>>) -> Self {
        Self::new(checkpoints)
    }
}

impl Checkpoints {
    pub fn new(checkpoints: BTreeMap<BlockHeight, Id<GenBlock>>) -> Self {
        checkpoints
            .get(&BlockHeight::new(0))
            .expect("Checkpoints must have genesis id at height 0");

        Self { checkpoints }
    }

    pub fn checkpoint_at_height(&self, height: &BlockHeight) -> Option<&Id<GenBlock>> {
        self.checkpoints.get(height)
    }

    pub fn parent_checkpoint_to_height(&self, height: BlockHeight) -> (BlockHeight, Id<GenBlock>) {
        // If an exact match is found at height, return it
        let exact_cp = self.checkpoints.get(&height);
        if let Some(&cp) = exact_cp {
            return (height, cp);
        }

        // Otherwise, find the closest checkpoint before the given height
        let cp_before = self
            .checkpoints
            .range(..height)
            .next_back()
            .expect("Genesis must be there, at least.");
        (*cp_before.0, (*cp_before.1))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Rng, Seed};

    use crate::primitives::H256;

    use super::*;

    #[test]
    #[should_panic = "Checkpoints must have genesis id at height 0"]
    fn test_empty_checkpoints() {
        let checkpoints_map = BTreeMap::new();
        let _checkpoints = Checkpoints::new(checkpoints_map);
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn test_parent_checkpoint_to_height_with_checkpoints(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let mut checkpoints_map = BTreeMap::new();
        checkpoints_map.insert(BlockHeight::new(0), H256::random_using(&mut rng).into());
        checkpoints_map.insert(BlockHeight::new(5), H256::random_using(&mut rng).into());
        checkpoints_map.insert(BlockHeight::new(10), H256::random_using(&mut rng).into());
        checkpoints_map.insert(BlockHeight::new(15), H256::random_using(&mut rng).into());
        let checkpoints = Checkpoints::new(checkpoints_map.clone());

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
