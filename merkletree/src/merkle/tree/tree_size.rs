// Copyright (c) 2021-2023 RBB S.r.l
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

use std::{
    fmt::{Display, Formatter},
    num::NonZeroU32,
};

use itertools::Itertools;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreeSize(u32);

const MAX_TREE_SIZE: u32 = 1 << 31;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TreeSizeError {
    #[error("Zero is invalid size for tree")]
    ZeroSize,
    #[error("Tree size must be power of two minus one; this value was found: {0}")]
    InvalidSize(u32),
    #[error("Tree with this huge size is not supported: {0}")]
    HugeTreeUnsupported(u64),
}

impl TreeSize {
    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn leaf_count(&self) -> NonZeroU32 {
        ((self.0 + 1) / 2).try_into().expect("Guaranteed by construction")
    }

    pub fn level_count(&self) -> NonZeroU32 {
        self.0.count_ones().try_into().expect("Guaranteed by construction")
    }

    pub fn from_u32(value: u32) -> Result<Self, TreeSizeError> {
        Self::try_from(value)
    }

    pub fn from_usize(value: usize) -> Result<Self, TreeSizeError> {
        Self::try_from(value)
    }

    pub fn from_leaf_count(leaf_count: u32) -> Result<Self, TreeSizeError> {
        if leaf_count == 0 {
            return Err(TreeSizeError::ZeroSize);
        }
        Self::try_from(leaf_count * 2 - 1)
    }

    /// The absolute index, at which the first node at level `level_from_bottom` starts.
    pub fn level_start(&self, level_from_bottom: u32) -> Option<u32> {
        let level_count = self.level_count().get();
        if level_from_bottom >= level_count {
            return None;
        }

        // To help in seeing how these formulas were derived, see this table that represents values in the case tree.len() == 31 == 0b11111:
        //  level     level_start  level_start in binary    index_in_level_size
        //  0         0            00000                    16
        //  1         16           10000                    8
        //  2         24           11000                    4
        //  3         28           11100                    2
        //  4         30           11110                    1

        let level_from_top = level_count - level_from_bottom;
        // to get leading ones, we shift the tree size, right then left, by the level we need (see the table above)
        let level_start = (self.0 >> level_from_top) << level_from_top;
        Some(level_start)
    }

    /// Creates an iterator that returns the indices of the nodes of the tree, from left to right, as pairs.
    /// Root isn't included in this iterator
    pub fn iter_pairs_indices(&self) -> impl Iterator<Item = (u32, u32)> {
        (0..self.get() - 1).tuple_windows::<(u32, u32)>().step_by(2)
    }
}

impl TryFrom<u32> for TreeSize {
    type Error = TreeSizeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(TreeSizeError::ZeroSize)
        } else if !(value + 1).is_power_of_two() {
            Err(TreeSizeError::InvalidSize(value))
        } else if value > MAX_TREE_SIZE {
            Err(TreeSizeError::HugeTreeUnsupported(value as u64))
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<usize> for TreeSize {
    type Error = TreeSizeError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value > MAX_TREE_SIZE as usize {
            return Err(TreeSizeError::HugeTreeUnsupported(value as u64));
        }
        let size: u32 = value.try_into().expect("Must fit because of last MAX_TREE_SIZE check");
        Self::try_from(size)
    }
}

impl From<TreeSize> for u32 {
    fn from(tree_size: TreeSize) -> Self {
        tree_size.0
    }
}

impl AsRef<u32> for TreeSize {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl Display for TreeSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::rand_tools::{make_seedable_rng, Seed};
    use rand::Rng;
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn construction_from_tree_size(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        // select simple values
        assert_eq!(TreeSize::from_u32(0), Err(TreeSizeError::ZeroSize));
        assert_eq!(TreeSize::from_u32(1), Ok(TreeSize(1)));
        assert_eq!(TreeSize::from_u32(2), Err(TreeSizeError::InvalidSize(2)));
        assert_eq!(TreeSize::from_u32(3), Ok(TreeSize(3)));
        assert_eq!(TreeSize::from_u32(4), Err(TreeSizeError::InvalidSize(4)));
        assert_eq!(TreeSize::from_u32(5), Err(TreeSizeError::InvalidSize(5)));
        assert_eq!(TreeSize::from_u32(6), Err(TreeSizeError::InvalidSize(6)));
        assert_eq!(TreeSize::from_u32(7), Ok(TreeSize(7)));
        assert_eq!(TreeSize::from_u32(8), Err(TreeSizeError::InvalidSize(8)));
        assert_eq!(TreeSize::from_u32(9), Err(TreeSizeError::InvalidSize(9)));
        assert_eq!(TreeSize::from_u32(10), Err(TreeSizeError::InvalidSize(10)));
        assert_eq!(TreeSize::from_u32(11), Err(TreeSizeError::InvalidSize(11)));
        assert_eq!(TreeSize::from_u32(12), Err(TreeSizeError::InvalidSize(12)));
        assert_eq!(TreeSize::from_u32(13), Err(TreeSizeError::InvalidSize(13)));
        assert_eq!(TreeSize::from_u32(14), Err(TreeSizeError::InvalidSize(14)));
        assert_eq!(TreeSize::from_u32(15), Ok(TreeSize(15)));
        assert_eq!(TreeSize::from_u32(16), Err(TreeSizeError::InvalidSize(16)));

        // exhaustive valid
        for i in 1..MAX_TREE_SIZE.ilog2() {
            assert_eq!(TreeSize::from_u32((1 << i) - 1), Ok(TreeSize((1 << i) - 1)));
        }

        // random invalid
        let attempts_count: u32 = 1000;
        for _ in 0..attempts_count {
            let sz = rng.gen_range(1..MAX_TREE_SIZE);
            if (sz + 1).is_power_of_two() {
                assert_eq!(TreeSize::try_from(sz), Ok(TreeSize(sz)));
                assert_eq!(TreeSize::from_u32(sz), Ok(TreeSize(sz)));
            } else {
                assert_eq!(TreeSize::try_from(sz), Err(TreeSizeError::InvalidSize(sz)));
                assert_eq!(TreeSize::from_u32(sz), Err(TreeSizeError::InvalidSize(sz)));
            }
        }
    }

    #[test]
    fn construction_from_leaf_count() {
        assert_eq!(TreeSize::from_leaf_count(0), Err(TreeSizeError::ZeroSize));
        assert_eq!(TreeSize::from_leaf_count(1), Ok(TreeSize(1)));
        assert_eq!(TreeSize::from_leaf_count(2), Ok(TreeSize(3)));
        assert_eq!(TreeSize::from_leaf_count(3), Err(TreeSizeError::InvalidSize(5)));
        assert_eq!(TreeSize::from_leaf_count(4), Ok(TreeSize(7)));
        assert_eq!(TreeSize::from_leaf_count(5), Err(TreeSizeError::InvalidSize(9)));
        assert_eq!(TreeSize::from_leaf_count(6), Err(TreeSizeError::InvalidSize(11)));
        assert_eq!(TreeSize::from_leaf_count(7), Err(TreeSizeError::InvalidSize(13)));
        assert_eq!(TreeSize::from_leaf_count(8), Ok(TreeSize(15)));
        assert_eq!(TreeSize::from_leaf_count(9), Err(TreeSizeError::InvalidSize(17)));
        assert_eq!(TreeSize::from_leaf_count(10), Err(TreeSizeError::InvalidSize(19)));
        assert_eq!(TreeSize::from_leaf_count(11), Err(TreeSizeError::InvalidSize(21)));
        assert_eq!(TreeSize::from_leaf_count(12), Err(TreeSizeError::InvalidSize(23)));
        assert_eq!(TreeSize::from_leaf_count(13), Err(TreeSizeError::InvalidSize(25)));
        assert_eq!(TreeSize::from_leaf_count(14), Err(TreeSizeError::InvalidSize(27)));
        assert_eq!(TreeSize::from_leaf_count(15), Err(TreeSizeError::InvalidSize(29)));
        assert_eq!(TreeSize::from_leaf_count(16), Ok(TreeSize(31)));
        assert_eq!(TreeSize::from_leaf_count(17), Err(TreeSizeError::InvalidSize(33)));
    }

    #[test]
    fn calculations() {
        let t1 = TreeSize::from_u32(1).unwrap();
        assert_eq!(t1.get(), 1);
        assert_eq!(t1.leaf_count().get(), 1);
        assert_eq!(t1.level_count().get(), 1);
        assert_eq!(t1.level_start(0).unwrap(), 0);
        for i in 1..1000u32 {
            assert_eq!(t1.level_start(i), None);
        }

        let t3 = TreeSize::from_u32(3).unwrap();
        assert_eq!(t3.get(), 3);
        assert_eq!(t3.leaf_count().get(), 2);
        assert_eq!(t3.level_count().get(), 2);
        for i in 2..1000u32 {
            assert_eq!(t3.level_start(i), None);
        }

        let t7 = TreeSize::from_u32(7).unwrap();
        assert_eq!(t7.get(), 7);
        assert_eq!(t7.leaf_count().get(), 4);
        assert_eq!(t7.level_count().get(), 3);
        assert_eq!(t7.level_start(0).unwrap(), 0);
        assert_eq!(t7.level_start(1).unwrap(), 4);
        assert_eq!(t7.level_start(2).unwrap(), 6);
        for i in 3..1000u32 {
            assert_eq!(t7.level_start(i), None);
        }

        let t15 = TreeSize::from_u32(15).unwrap();
        assert_eq!(t15.get(), 15);
        assert_eq!(t15.leaf_count().get(), 8);
        assert_eq!(t15.level_count().get(), 4);
        assert_eq!(t15.level_start(0).unwrap(), 0);
        assert_eq!(t15.level_start(1).unwrap(), 8);
        assert_eq!(t15.level_start(2).unwrap(), 12);
        assert_eq!(t15.level_start(3).unwrap(), 14);
        for i in 4..1000u32 {
            assert_eq!(t15.level_start(i), None);
        }

        let t31 = TreeSize::from_u32(31).unwrap();
        assert_eq!(t31.get(), 31);
        assert_eq!(t31.leaf_count().get(), 16);
        assert_eq!(t31.level_count().get(), 5);
        assert_eq!(t31.level_start(0).unwrap(), 0);
        assert_eq!(t31.level_start(1).unwrap(), 16);
        assert_eq!(t31.level_start(2).unwrap(), 24);
        assert_eq!(t31.level_start(3).unwrap(), 28);
        assert_eq!(t31.level_start(4).unwrap(), 30);
        for i in 5..1000u32 {
            assert_eq!(t31.level_start(i), None);
        }

        let t63 = TreeSize::from_u32(63).unwrap();
        assert_eq!(t63.get(), 63);
        assert_eq!(t63.leaf_count().get(), 32);
        assert_eq!(t63.level_count().get(), 6);
        assert_eq!(t63.level_start(0).unwrap(), 0);
        assert_eq!(t63.level_start(1).unwrap(), 32);
        assert_eq!(t63.level_start(2).unwrap(), 48);
        assert_eq!(t63.level_start(3).unwrap(), 56);
        assert_eq!(t63.level_start(4).unwrap(), 60);
        assert_eq!(t63.level_start(5).unwrap(), 62);
        for i in 6..1000u32 {
            assert_eq!(t63.level_start(i), None);
        }

        let t127 = TreeSize::from_u32(127).unwrap();
        assert_eq!(t127.get(), 127);
        assert_eq!(t127.leaf_count().get(), 64);
        assert_eq!(t127.level_count().get(), 7);
        assert_eq!(t127.level_start(0).unwrap(), 0);
        assert_eq!(t127.level_start(1).unwrap(), 64);
        assert_eq!(t127.level_start(2).unwrap(), 96);
        assert_eq!(t127.level_start(3).unwrap(), 112);
        assert_eq!(t127.level_start(4).unwrap(), 120);
        assert_eq!(t127.level_start(5).unwrap(), 124);
        assert_eq!(t127.level_start(6).unwrap(), 126);
        for i in 7..1000u32 {
            assert_eq!(t127.level_start(i), None);
        }

        let t255 = TreeSize::from_u32(255).unwrap();
        assert_eq!(t255.get(), 255);
        assert_eq!(t255.leaf_count().get(), 128);
        assert_eq!(t255.level_count().get(), 8);
        assert_eq!(t255.level_start(0).unwrap(), 0);
        assert_eq!(t255.level_start(1).unwrap(), 128);
        assert_eq!(t255.level_start(2).unwrap(), 192);
        assert_eq!(t255.level_start(3).unwrap(), 224);
        assert_eq!(t255.level_start(4).unwrap(), 240);
        assert_eq!(t255.level_start(5).unwrap(), 248);
        assert_eq!(t255.level_start(6).unwrap(), 252);
        assert_eq!(t255.level_start(7).unwrap(), 254);
        for i in 8..1000u32 {
            assert_eq!(t255.level_start(i), None);
        }
    }

    #[test]
    fn huge_tree_sizes() {
        assert!(TreeSize::try_from(MAX_TREE_SIZE - 1).is_ok());
        // ensure it'll fit in a 32-bit integer, since MAX_TREE_SIZE*2 can overflow in 32-bit systems, depending on its value
        let huge_tree_size = (((MAX_TREE_SIZE as u64) << 1) - 1) as usize;
        assert_eq!(
            TreeSize::try_from(huge_tree_size).unwrap_err(),
            TreeSizeError::HugeTreeUnsupported(huge_tree_size as u64)
        );
    }

    #[test]
    fn iter_non_root_indices() {
        let t1 = TreeSize::from_u32(1).unwrap();
        assert_eq!(t1.iter_pairs_indices().count(), 0);

        let t3 = TreeSize::from_u32(3).unwrap();
        assert_eq!(t3.iter_pairs_indices().collect::<Vec<_>>(), vec![(0, 1)]);

        let t7 = TreeSize::from_u32(7).unwrap();
        assert_eq!(t7.iter_pairs_indices().collect::<Vec<_>>(), vec![(0, 1), (2, 3), (4, 5)]);

        let t15 = TreeSize::from_u32(15).unwrap();
        assert_eq!(
            t15.iter_pairs_indices().collect::<Vec<_>>(),
            vec![(0, 1), (2, 3), (4, 5), (6, 7), (8, 9), (10, 11), (12, 13)]
        );

        let t31 = TreeSize::from_u32(31).unwrap();
        assert_eq!(
            t31.iter_pairs_indices().collect::<Vec<_>>(),
            vec![
                (0, 1),
                (2, 3),
                (4, 5),
                (6, 7),
                (8, 9),
                (10, 11),
                (12, 13),
                (14, 15),
                (16, 17),
                (18, 19),
                (20, 21),
                (22, 23),
                (24, 25),
                (26, 27),
                (28, 29),
            ]
        );

        // Exhaustive... without this taking way too long
        for i in 1..10_u32 {
            let tree_size = TreeSize::from_u32((1 << i) - 1).unwrap();
            assert_eq!(TreeSize::from_u32((1 << i) - 1), Ok(TreeSize((1 << i) - 1)));
            assert_eq!(tree_size.iter_pairs_indices().count() as u32, tree_size.get() / 2);
            assert_eq!(
                tree_size.iter_pairs_indices().collect::<Vec<_>>(),
                (0..tree_size.get() / 2).map(|i| (i * 2, i * 2 + 1)).collect::<Vec<_>>()
            );
        }
    }
}
