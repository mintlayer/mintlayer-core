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

use std::collections::BTreeSet;

use chainstate_types::BlockStatus;
use common::{
    chain::Block,
    primitives::{BlockHeight, Id},
    Uint256,
};

use super::best_chain_candidates::BestChainCandidates;

fn assert_bcc_eq(bcc: &BestChainCandidates, candidates: &[Id<Block>]) {
    let actual_set = BTreeSet::from_iter(bcc.elements().map(|e| e.block_id()));
    let expected_set = BTreeSet::from_iter(candidates);
    assert_eq!(actual_set, expected_set);
}

fn good_status() -> BlockStatus {
    BlockStatus::new()
}

fn bad_status() -> BlockStatus {
    let mut bs = BlockStatus::new();
    bs.set_validation_failed();
    bs
}

// The block tree is ('!' denotes blocks with bad status):
//      /------a0-----a1----a2----a3
//      |      /------b0---!b1---!b2
//      |      |------c0----c1---!c2
//      |      |------d0----d1----d2
//      |      |      /-----e0----e1----e2
// G----m0-----m1-----m2----m3----m4----m5----m6
#[test]
fn the_test() {
    use test_framework::{make_block_id, TestChainstate};

    let mut tc = TestChainstate::new(BlockHeight::zero());
    let m0 = tc.add_block(make_block_id(0), good_status(), true);
    let m1 = tc.add_block(m0, good_status(), true);
    let m2 = tc.add_block(m1, good_status(), true);
    let m3 = tc.add_block(m2, good_status(), true);
    let m4 = tc.add_block(m3, good_status(), true);
    let m5 = tc.add_block(m4, good_status(), true);
    let m6 = tc.add_block(m5, good_status(), true);

    let a0 = tc.add_block(m0, good_status(), false);
    let a1 = tc.add_block(a0, good_status(), false);
    let a2 = tc.add_block(a1, good_status(), false);
    let a3 = tc.add_block(a2, good_status(), false);

    let b0 = tc.add_block(m1, good_status(), false);
    let b1 = tc.add_block(b0, bad_status(), false);
    let _b2 = tc.add_block(b1, bad_status(), false);

    let c0 = tc.add_block(m1, good_status(), false);
    let c1 = tc.add_block(c0, good_status(), false);
    let _c2 = tc.add_block(c1, bad_status(), false);

    let d0 = tc.add_block(m1, good_status(), false);
    let d1 = tc.add_block(d0, good_status(), false);
    let d2 = tc.add_block(d1, good_status(), false);

    let e0 = tc.add_block(m2, good_status(), false);
    let e1 = tc.add_block(e0, good_status(), false);
    let e2 = tc.add_block(e1, good_status(), false);

    // Here min_height_with_allowed_reorg is 0
    {
        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(0)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(1)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(2)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(3)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(4)).unwrap();
        assert_bcc_eq(&bcc, &[a3, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(5)).unwrap();
        assert_bcc_eq(&bcc, &[a3, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(6)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(7)).unwrap();
        assert_bcc_eq(&bcc, &[m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(8)).unwrap();
        assert_bcc_eq(&bcc, &[]);
    }

    // With min_height_with_allowed_reorg=1 the expectations stay the same.
    tc.set_min_height_with_allowed_reorg(BlockHeight::new(1));
    {
        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(0)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(1)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(2)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(3)).unwrap();
        assert_bcc_eq(&bcc, &[a3, b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(4)).unwrap();
        assert_bcc_eq(&bcc, &[a3, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(5)).unwrap();
        assert_bcc_eq(&bcc, &[a3, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(6)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(7)).unwrap();
        assert_bcc_eq(&bcc, &[m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(8)).unwrap();
        assert_bcc_eq(&bcc, &[]);
    }

    // With min_height_with_allowed_reorg=2 the "a" branch is no longer considered.
    tc.set_min_height_with_allowed_reorg(BlockHeight::new(2));
    {
        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(0)).unwrap();
        assert_bcc_eq(&bcc, &[b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(1)).unwrap();
        assert_bcc_eq(&bcc, &[b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(2)).unwrap();
        assert_bcc_eq(&bcc, &[b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(3)).unwrap();
        assert_bcc_eq(&bcc, &[b0, c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(4)).unwrap();
        assert_bcc_eq(&bcc, &[c1, d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(5)).unwrap();
        assert_bcc_eq(&bcc, &[d2, e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(6)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(7)).unwrap();
        assert_bcc_eq(&bcc, &[m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(8)).unwrap();
        assert_bcc_eq(&bcc, &[]);
    }

    // With min_height_with_allowed_reorg=3 the "b", "c" and "d" branches are
    // no longer considered.
    tc.set_min_height_with_allowed_reorg(BlockHeight::new(3));
    {
        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(0)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(1)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(2)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(3)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(4)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(5)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(6)).unwrap();
        assert_bcc_eq(&bcc, &[e2, m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(7)).unwrap();
        assert_bcc_eq(&bcc, &[m6]);

        let bcc = BestChainCandidates::new(&tc, Uint256::from_u64(8)).unwrap();
        assert_bcc_eq(&bcc, &[]);
    }
}

mod test_framework {
    use std::collections::BTreeMap;

    use chainstate_types::{BlockStatus, PropertyQueryError};
    use common::chain::{Block, GenBlock};

    use crate::detail::block_invalidation::best_chain_candidates::{
        BlockInfo, ChainstateAccessor, GenBlockInfo,
    };

    use super::*;

    #[derive(Clone)]
    pub struct TestBlockInfo {
        id: Id<Block>,
        parent_id: Id<Block>,
        height: BlockHeight,
        chain_trust: Uint256,
        status: BlockStatus,
    }

    impl BlockInfo for TestBlockInfo {
        fn id(&self) -> Id<Block> {
            self.id
        }

        fn parent_id(&self) -> Id<GenBlock> {
            self.parent_id.into()
        }

        fn height(&self) -> BlockHeight {
            self.height
        }

        fn chain_trust(&self) -> Uint256 {
            self.chain_trust
        }

        fn status(&self) -> BlockStatus {
            self.status
        }
    }

    impl GenBlockInfo for TestBlockInfo {
        fn height(&self) -> BlockHeight {
            self.height
        }
    }

    pub fn make_block_id(id: usize) -> Id<Block> {
        Id::new(Uint256::from_u64(id as u64).into())
    }

    struct TestChainstateNode {
        status: BlockStatus,
        parent_id: Option<Id<Block>>,
        children_ids: Vec<Id<Block>>,
        height: BlockHeight,
        is_mainchain: bool,
    }

    pub struct TestChainstate {
        min_height_with_allowed_reorg: BlockHeight,
        nodes: BTreeMap<Id<Block>, TestChainstateNode>,
        next_block_id: usize,
    }

    impl TestChainstate {
        pub fn new(min_height_with_allowed_reorg: BlockHeight) -> TestChainstate {
            TestChainstate {
                min_height_with_allowed_reorg,
                nodes: BTreeMap::from([(
                    make_block_id(0),
                    TestChainstateNode {
                        status: BlockStatus::new_fully_checked(),
                        parent_id: None,
                        children_ids: Vec::new(),
                        height: BlockHeight::zero(),
                        is_mainchain: true,
                    },
                )]),
                next_block_id: 1,
            }
        }

        pub fn set_min_height_with_allowed_reorg(
            &mut self,
            min_height_with_allowed_reorg: BlockHeight,
        ) {
            self.min_height_with_allowed_reorg = min_height_with_allowed_reorg
        }

        // Note: block's chain trust will be equal to its height.
        pub fn add_block(
            &mut self,
            parent_id: Id<Block>,
            status: BlockStatus,
            is_mainchain: bool,
        ) -> Id<Block> {
            let id = make_block_id(self.next_block_id);
            self.next_block_id += 1;

            let parent_node = self.nodes.get(&parent_id).unwrap();
            if is_mainchain {
                // The parent should be in the main chain, but siblings should be not
                assert!(parent_node.is_mainchain);
                for sibling_id in parent_node.children_ids.iter() {
                    let sibling = self.nodes.get(sibling_id).unwrap();
                    assert!(!sibling.is_mainchain);
                }
            }

            let new_node = TestChainstateNode {
                status,
                parent_id: Some(parent_id),
                children_ids: Vec::new(),
                height: parent_node.height.next_height(),
                is_mainchain,
            };

            self.nodes.insert(id, new_node);
            self.nodes.get_mut(&parent_id).unwrap().children_ids.push(id);

            id
        }

        fn make_block_info(id: &Id<Block>, node: &TestChainstateNode) -> TestBlockInfo {
            TestBlockInfo {
                id: *id,
                // Note: we don't expect the 0th block to ever be reached in these tests.
                parent_id: node.parent_id.unwrap(),
                height: node.height,
                chain_trust: Uint256::from_u64(node.height.into_int()),
                status: node.status,
            }
        }
    }

    impl ChainstateAccessor for TestChainstate {
        type BlockInfo = TestBlockInfo;
        type GenBlockInfo = TestBlockInfo;

        fn min_height_with_allowed_reorg(&self) -> Result<BlockHeight, PropertyQueryError> {
            Ok(self.min_height_with_allowed_reorg)
        }

        fn get_higher_block_ids_sorted_by_height(
            &self,
            start_from: BlockHeight,
        ) -> Result<impl DoubleEndedIterator<Item = Id<Block>>, PropertyQueryError> {
            let mut ids_heights = self
                .nodes
                .iter()
                .filter_map(|(id, data)| {
                    if data.height > start_from {
                        Some((*id, data.height))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            ids_heights.sort_by(|(_, height1), (_, height2)| height1.cmp(height2));
            Ok(ids_heights.into_iter().map(|(id, _)| id))
        }

        fn get_block_info(
            &self,
            block_id: &Id<Block>,
        ) -> Result<TestBlockInfo, PropertyQueryError> {
            let node = self.nodes.get(block_id).unwrap();
            Ok(Self::make_block_info(block_id, node))
        }

        fn last_common_ancestor_in_main_chain(
            &self,
            block_info: &Self::GenBlockInfo,
        ) -> Result<Self::GenBlockInfo, PropertyQueryError> {
            let mut cur_block_id = block_info.id;
            loop {
                let node = self.nodes.get(&cur_block_id).unwrap();
                if node.is_mainchain {
                    return Ok(Self::make_block_info(&cur_block_id, node));
                }
                cur_block_id = node.parent_id.unwrap();
            }
        }

        fn block_info_to_gen(bi: Self::BlockInfo) -> Self::GenBlockInfo {
            bi
        }

        fn gen_block_id_to_normal(&self, id: &Id<GenBlock>) -> Option<Id<Block>> {
            if *id == make_block_id(0) {
                None
            } else {
                Some(Id::new(id.to_hash()))
            }
        }
    }
}
