// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

use common::chain::block::Block;
use common::primitives::{Idable, H256};
use rand::prelude::ThreadRng;
use rand::seq::SliceRandom;
use std::collections::BTreeMap;
use std::rc::Rc;

pub const DEFAULT_MAX_ORPHAN_BLOCKS: usize = 512;

pub struct OrphanBlocksPool {
    orphan_ids: Vec<H256>,
    orphan_by_id: BTreeMap<H256, Rc<Block>>,
    orphan_by_prev_id: BTreeMap<H256, Vec<Rc<Block>>>,
    max_orphans: usize,
    rng: ThreadRng,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrphanAddError {
    BlockAlreadyInOrphanList(Block),
}

impl OrphanBlocksPool {
    #[allow(dead_code)]
    pub fn new_default() -> Self {
        OrphanBlocksPool {
            orphan_ids: Vec::new(),
            orphan_by_id: BTreeMap::new(),
            orphan_by_prev_id: BTreeMap::new(),
            max_orphans: DEFAULT_MAX_ORPHAN_BLOCKS,
            rng: rand::thread_rng(),
        }
    }

    #[allow(dead_code)]
    pub fn new_custom(max_orphans: usize) -> Self {
        OrphanBlocksPool {
            orphan_ids: Vec::new(),
            orphan_by_id: BTreeMap::new(),
            orphan_by_prev_id: BTreeMap::new(),
            max_orphans,
            rng: rand::thread_rng(),
        }
    }

    #[allow(dead_code)]
    fn drop_block(&mut self, block_id: &H256) {
        let block = self
            .orphan_by_id
            .get(block_id)
            .expect("Entry was found before calling this")
            .clone();

        // remove from the map
        self.orphan_by_id.remove(block_id).expect("Entry was found before calling this");

        {
            // remove from the vector
            let index = self
                .orphan_ids
                .iter()
                .position(|id| *id == *block_id)
                .expect("Must be there since we inserted it");
            self.orphan_ids.remove(index);
        }

        // remove from the prevs
        let prevs = self
            .orphan_by_prev_id
            .get_mut(&block.get_prev_block_id().get())
            .expect("This should always be there since it was added with the other map");
        assert!(!prevs.is_empty());
        if prevs.len() == 1 {
            // if this is the only element left, we remove the whole vector
            self.orphan_by_prev_id
                .remove(&block.get_prev_block_id().get())
                .expect("Was already found before");
        } else {
            // we find the element that matches the block id
            let index = prevs
                .iter()
                .position(|blk| blk.get_id().get() == *block_id)
                .expect("Must be there since we inserted it");
            prevs.remove(index);
        }
    }

    // keep digging in the orphans tree until we find a block that has no children, then delete that
    #[allow(dead_code)]
    fn del_one_deepest_child(&mut self, block_id: &H256) {
        let next_block = self
            .orphan_by_prev_id
            .get(block_id)
            .map(|v| v.get(0).expect("This list should never be empty as we always delete empty vectors from the map"))
            .cloned();
        match next_block {
            Some(block) => self.del_one_deepest_child(&block.get_id().get()),
            None => {
                self.drop_block(block_id);
            }
        }
    }

    #[allow(dead_code)]
    fn prune(&mut self) {
        if self.orphan_by_id.len() < self.max_orphans {
            return;
        }
        let id = self.orphan_ids.choose(&mut self.rng);
        let id = *id.expect("As orphans can never be empty, this should always return");

        self.del_one_deepest_child(&id);
    }

    #[allow(dead_code)]
    pub fn add_block(&mut self, block: Block) -> Result<(), OrphanAddError> {
        self.prune();
        let block_id = block.get_id();
        if self.orphan_by_id.contains_key(&block_id.get()) {
            return Err(OrphanAddError::BlockAlreadyInOrphanList(block));
        }

        let rc_block = Rc::new(block);
        self.orphan_by_id.insert(block_id.get(), rc_block.clone());
        self.orphan_ids.push(block_id.get());
        self.orphan_by_prev_id
            .entry(rc_block.get_prev_block_id().get())
            .or_default()
            .push(rc_block.clone());
        Ok(())
    }

    #[allow(dead_code)]
    pub fn is_already_an_orphan(&self, block_id: &H256) -> bool {
        self.orphan_by_id.contains_key(block_id)
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.orphan_by_id.clear();
        self.orphan_ids.clear();
        self.orphan_by_prev_id.clear();
    }

    /// take all the blocks that share the same parent
    /// this is useful when a new tip is set, and we want to connect all its unorphaned children
    #[allow(dead_code)]
    pub fn take_all_children_of(&mut self, block_id: &H256) -> Vec<Block> {
        let res = self.orphan_by_prev_id.get_mut(block_id);
        let mut res = match res {
            None => {
                return Vec::new();
            }
            Some(v) => v.clone(),
        };
        // after we get all the blocks that have the same prev, we drop them from the pool
        res.iter().for_each(|blk| self.drop_block(&blk.get_id().get()));
        // after dropping everything, this is expected to be the only Rc left
        let res = res
            .drain(..)
            .map(|blk| {
                Rc::try_unwrap(blk)
                    .expect("There cannot be more than one copy of the Rc. This is unexpected.")
            })
            .collect();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use checkers::*;
    use common::chain::block::Block;
    use common::primitives::Id;
    use helpers::*;
    use rand::seq::SliceRandom;

    mod helpers {
        use super::*;
        use common::chain::transaction::Transaction;
        use rand::Rng;

        pub fn gen_random_blocks(count: u32) -> Vec<Block> {
            (0..count).into_iter().map(|_| gen_random_block()).collect::<Vec<_>>()
        }

        pub fn gen_random_block() -> Block {
            gen_block_from_id(None)
        }

        pub fn gen_block_from_id(prev_block_id: Option<H256>) -> Block {
            let mut rng = rand::thread_rng();

            let tx = Transaction::new(0, Vec::new(), Vec::new(), 0).unwrap();

            Block::new(
                vec![tx],
                Id::new(&prev_block_id.unwrap_or(H256::from_low_u64_be(rng.gen()))),
                rng.gen(),
                Vec::new(),
            )
            .unwrap()
        }

        pub fn gen_blocks_chain(count: u32) -> Vec<Block> {
            gen_blocks_chain_starting_from_id(count, None)
        }

        pub fn gen_blocks_chain_starting_from_id(
            count: u32,
            prev_block_id: Option<H256>,
        ) -> Vec<Block> {
            let mut blocks = vec![gen_block_from_id(prev_block_id)];

            (1..count).into_iter().for_each(|_| {
                let prev_block_id = blocks.last().map(|block| block.get_id().get());
                blocks.push(gen_block_from_id(prev_block_id));
            });

            blocks
        }

        pub fn gen_blocks_with_common_parent(count: u32) -> Vec<Block> {
            gen_blocks_with_common_parent_id(count, None)
        }

        pub fn gen_blocks_with_common_parent_id(
            count: u32,
            prev_block_id: Option<H256>,
        ) -> Vec<Block> {
            let mut rng = rand::thread_rng();

            let prev_block_id = prev_block_id.unwrap_or(H256::from_low_u64_be(rng.gen()));

            (0..count).into_iter().map(|_| gen_block_from_id(Some(prev_block_id))).collect()
        }
    }

    mod checkers {
        use super::*;

        // checks whether each vecs in the orphan pool has a length that matches with the expected length.
        pub fn check_pool_length(orphans_pool: &OrphanBlocksPool, expected_length: usize) {
            assert_eq!(orphans_pool.orphan_ids.len(), expected_length);
            assert_eq!(orphans_pool.orphan_by_id.len(), expected_length);

            let len = orphans_pool.orphan_by_prev_id.values().flatten().count();
            assert_eq!(len, expected_length);
        }

        pub fn check_empty_pool(orphans_pool: &OrphanBlocksPool) {
            check_pool_length(orphans_pool, 0);
        }

        pub fn check_block_existence(orphans_pool: &OrphanBlocksPool, block: &Block) {
            assert!(orphans_pool.orphan_ids.contains(&block.get_id().get()));
            assert!(orphans_pool.is_already_an_orphan(&block.get_id().get()));

            if let Some(blocks) =
                orphans_pool.orphan_by_prev_id.get(&block.get_prev_block_id().get())
            {
                assert!(blocks.contains(&Rc::new(block.clone())))
            } else {
                panic!(
                    "the block {:#?} is not in `orphan_by_prev_id` field.",
                    block
                );
            }
        }

        pub fn check_block_existence_and_pool_length(
            orphans_pool: &OrphanBlocksPool,
            block: &Block,
            expected_length: usize,
        ) {
            check_block_existence(orphans_pool, block);
            check_pool_length(orphans_pool, expected_length);
        }
    }

    #[test]
    fn test_pool_default() {
        let orphans_pool = OrphanBlocksPool::new_default();
        assert_eq!(orphans_pool.max_orphans, DEFAULT_MAX_ORPHAN_BLOCKS);
        check_empty_pool(&orphans_pool);
    }

    #[test]
    fn test_pool_custom() {
        let max_orphans = 3;
        let orphans_pool = OrphanBlocksPool::new_custom(max_orphans);
        assert_eq!(orphans_pool.max_orphans, max_orphans);
        check_empty_pool(&orphans_pool);
    }

    #[test]
    fn test_add_one_block_and_clear() {
        let mut orphans_pool = OrphanBlocksPool::new_default();

        // add a random block
        let block = gen_random_block();
        assert!(orphans_pool.add_block(block.clone()).is_ok());

        // check if block was really inserted
        check_block_existence(&orphans_pool, &block);

        // check if orphans pool is empty after clearing.
        orphans_pool.clear();
        check_empty_pool(&orphans_pool);
    }

    #[test]
    fn test_add_blocks_and_clear() {
        let mut orphans_pool = OrphanBlocksPool::new_default();

        // add a random block
        let block = gen_random_block();
        assert!(orphans_pool.add_block(block.clone()).is_ok());

        check_block_existence_and_pool_length(&orphans_pool, &block, 1);

        // add another block that connects to the first one
        let conn_block = gen_block_from_id(Some(block.get_id().get()));
        assert!(orphans_pool.add_block(conn_block.clone()).is_ok());
        check_block_existence_and_pool_length(&orphans_pool, &conn_block, 2);

        // check that there is only 2 key-value pair in `orphans_by_prev_id`
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 2);

        // add another block with the parent id of any of the 2 blocks above
        let rand_block = {
            let rand_id = orphans_pool
                .orphan_ids
                .choose(&mut rand::thread_rng())
                .expect("it should return any id of the 2 blocks above");
            orphans_pool
                .orphan_by_id
                .get(rand_id)
                .expect("it should return the block specified by `rand_id`")
        };

        let sim_block = gen_block_from_id(Some(rand_block.get_prev_block_id().get()));
        assert!(orphans_pool.add_block(sim_block.clone()).is_ok());
        check_block_existence_and_pool_length(&orphans_pool, &sim_block, 3);

        // check that there is STILL only 2 key-value pair in `orphans_by_prev_id`
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 2);

        // check if orphans pool is empty after clearing.
        orphans_pool.clear();
        check_empty_pool(&orphans_pool);
    }

    #[test]
    fn test_add_block_exceeds_max() {
        let max_orphans = 3;
        let mut orphans_pool = OrphanBlocksPool::new_custom(max_orphans);
        let blocks = gen_random_blocks(max_orphans as u32 + 2);

        blocks.into_iter().for_each(|block| {
            assert!(orphans_pool.add_block(block).is_ok());
        });

        check_pool_length(&orphans_pool, max_orphans);
    }

    #[test]
    fn test_add_block_repeated() {
        let mut orphans_pool = OrphanBlocksPool::new_default();
        let blocks = gen_random_blocks(50);

        blocks.iter().for_each(|block| {
            assert!(orphans_pool.add_block(block.clone()).is_ok());
        });

        let rand_block =
            blocks.choose(&mut rand::thread_rng()).expect("this should return any block");

        assert_eq!(
            orphans_pool.add_block(rand_block.clone()).unwrap_err(),
            OrphanAddError::BlockAlreadyInOrphanList(rand_block.clone())
        );
    }

    #[test]
    fn test_pool_drop_block() {
        let mut orphans_pool = OrphanBlocksPool::new_default();
        let blocks = gen_random_blocks(5);

        blocks.iter().for_each(|block| {
            assert!(orphans_pool.add_block(block.clone()).is_ok());
        });
        check_pool_length(&orphans_pool, blocks.len());

        let rand_block =
            blocks.choose(&mut rand::thread_rng()).expect("this should return any block");

        // dropping the rand_block
        orphans_pool.drop_block(&rand_block.get_id().get());

        assert!(!orphans_pool.orphan_by_id.contains_key(&rand_block.get_id().get()));
        assert!(!orphans_pool.orphan_ids.contains(&rand_block.get_id().get()));
        assert!(!orphans_pool
            .orphan_by_prev_id
            .contains_key(&rand_block.get_prev_block_id().get()));
    }

    #[test]
    fn test_deepest_child_in_chain() {
        let mut orphans_pool = OrphanBlocksPool::new_default();

        // In `orphans_by_prev_id`:
        // [
        //  ( a, b ),
        //  ( b, c ),
        //  ( c, d ),
        //  ( d, e ),
        // ]
        let blocks = gen_blocks_chain(4);

        blocks.iter().for_each(|block| {
            assert!(orphans_pool.add_block(block.clone()).is_ok());
            assert!(orphans_pool.is_already_an_orphan(&block.get_id().get()));

            // check that relationship of the prev_id and the block is 1-to-1.
            if let Some(blocks) =
                orphans_pool.orphan_by_prev_id.get(&block.get_prev_block_id().get())
            {
                assert_eq!(blocks.len(), 1);
            } else {
                panic!(
                    "block {:?} not found for key {:?}",
                    block,
                    block.get_prev_block_id().get()
                );
            }
        });
        check_pool_length(&orphans_pool, blocks.len());

        let first_block = blocks.first().expect("list should not be empty");
        let last_block = blocks.last().expect("list should not be empty");

        // block e should be removed:
        // [
        //  ( a, b ),
        //  ( b, c ),
        //  ( c, d ),
        // ]
        orphans_pool.del_one_deepest_child(&first_block.get_id().get());

        // the last block should be deleted.
        assert!(!orphans_pool.orphan_by_id.contains_key(&last_block.get_id().get()));
        assert!(!orphans_pool
            .orphan_by_prev_id
            .contains_key(&last_block.get_prev_block_id().get()));
        check_pool_length(&orphans_pool, blocks.len() - 1);

        // the first block should still exist.
        check_block_existence(&orphans_pool, first_block);
    }

    #[test]
    fn test_deepest_child_common_parent() {
        let mut orphans_pool = OrphanBlocksPool::new_default();
        // In `orphans_by_prev_id`:
        // [
        //  ( a, (b,c,d,e,f) ),
        // ]
        let blocks = gen_blocks_with_common_parent(5);

        blocks.iter().enumerate().for_each(|(idx, b)| {
            let block_id = b.get_id();
            assert!(orphans_pool.add_block(b.clone()).is_ok());
            assert!(orphans_pool.is_already_an_orphan(&block_id.get()));

            // check that the number of blocks for the same key, increases too.
            if let Some(blocks) = orphans_pool.orphan_by_prev_id.get(&b.get_prev_block_id().get()) {
                assert_eq!(blocks.len(), idx + 1);

                let block_id = &blocks[idx].get_id();
                assert_eq!(&b.get_id(), block_id);
            } else {
                panic!("no blocks found for key {:?}", b.get_prev_block_id().get());
            }
        });

        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 1);
        assert_eq!(orphans_pool.orphan_ids.len(), blocks.len());

        // delete a random block
        let random_block = blocks.choose(&mut rand::thread_rng()).expect("returns any block");
        orphans_pool.del_one_deepest_child(&random_block.get_id().get());

        // make sure that the same random_block is deleted.
        assert!(!orphans_pool.orphan_by_id.contains_key(&random_block.get_id().get()));
        assert!(!orphans_pool.orphan_ids.contains(&random_block.get_id().get()));

        if let Some(in_blocks) =
            orphans_pool.orphan_by_prev_id.get(&random_block.get_prev_block_id().get())
        {
            assert_eq!(in_blocks.len(), blocks.len() - 1);
        } else {
            panic!(
                "there should still be {:?} elements in id: {:#?}",
                (blocks.len() - 1),
                random_block.get_prev_block_id().get()
            );
        }
    }

    #[test]
    fn test_prune() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(12);
        // in `orphans_by_prev_id`:
        // [
        //  ( a, (b,c,d,e) )
        // ]
        let sim_blocks = gen_blocks_with_common_parent(4);

        // [
        //  ( f, g ),
        //  ( g, h ),
        //  ( h, i ),
        // ]
        let conn_blocks = gen_blocks_chain(3);

        // generate a chain using one of sim's blocks.
        let sim_block_id = sim_blocks.last().expect("it should return the last element").get_id();
        // [
        //  ( e, j ),
        //  ( j, k )
        // ]
        let extra_sim_blocks = gen_blocks_chain_starting_from_id(2, Some(sim_block_id.get()));

        // generate blocks with conn's block id as parent
        let conn_block_id = conn_blocks.last().expect("it should return last element").get_id();
        // [
        //  ( i, (l,m,n) )
        // ]
        let extra_conn_blocks = gen_blocks_with_common_parent_id(3, Some(conn_block_id.get()));

        //[
        //  ( a, (b,c,d,e) ),
        //  ( f, g ),
        //  ( g, h ),
        //  ( h, i ),
        //  ( e, j ),
        //  ( j, k ),
        //  ( i, (l,m,n) ),
        //]
        let blocks = [sim_blocks, conn_blocks, extra_conn_blocks, extra_sim_blocks].concat();

        blocks.iter().for_each(|block| {
            orphans_pool.add_block(block.clone()).expect("should not fail");
        });

        check_pool_length(&orphans_pool, blocks.len());
        // there should only be 7 key-value pairs.
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 7);

        // 1 block is removed; size is 1 less than the set max_orphans
        orphans_pool.prune();
        check_pool_length(&orphans_pool, orphans_pool.max_orphans - 1);

        // for the 2nd prune, nothing should happen.
        orphans_pool.prune();
        check_pool_length(&orphans_pool, orphans_pool.max_orphans - 1);

        // add a random block
        let random_block = gen_random_block();
        assert!(orphans_pool.add_block(random_block.clone()).is_ok());
        check_block_existence_and_pool_length(
            &orphans_pool,
            &random_block,
            orphans_pool.max_orphans,
        );

        // this will trigger pruning
        orphans_pool.prune();
        check_pool_length(&orphans_pool, orphans_pool.max_orphans - 1);
    }

    #[test]
    fn test_simple_take_all_children_of() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(20);

        let count = 9;
        // in `orphans_by_prev_id`:
        // [
        //  ( a, (b,c,d,e,f,g,h,i,j) )
        // ]
        let sim_blocks = gen_blocks_with_common_parent(count);

        // in `orphans_by_prev_id`:
        // [
        //  (k,l), (l,m), (m,n), (n,o), (o,p), (p,q), (q,r), (r,s), (s,t))
        // ]
        let conn_blocks = gen_blocks_chain(count);
        let conn_blocks_len = conn_blocks.len();

        // alternate adding of blocks
        for (sim_block, conn_block) in sim_blocks.iter().zip(conn_blocks) {
            orphans_pool.add_block(sim_block.clone()).expect("should not fail");
            orphans_pool.add_block(conn_block).expect("should not fail");
        }

        // collect all children of sim_blocks's prev_id
        let sim_parent_id = sim_blocks
            .first()
            .expect("this should return the first element")
            .get_prev_block_id()
            .get();
        let children = orphans_pool.take_all_children_of(&sim_parent_id);
        assert_eq!(children.len(), sim_blocks.len());

        // all blocks in sim_blocks should appear in the children list
        sim_blocks.into_iter().for_each(|child| {
            assert!(children.contains(&Rc::new(child)));
        });

        // the remaining blocks in the pool should all belong to conn_blocks
        check_pool_length(&orphans_pool, conn_blocks_len);
    }

    #[test]
    fn test_mix_chain_take_all_children_of() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(20);

        let count = 9;
        // in `orphans_by_prev_id`:
        // [
        //  ( a, (b,c,d,e,f,g,h,i,j) )
        // ]
        let sim_blocks = gen_blocks_with_common_parent(count);

        let mut conn_blocks: Vec<Block> = vec![];
        // let's use 2 random blocks of sim_blocks to generate a chain of blocks
        // in `orphans_by_prev_id`:
        // [
        //  ( <random_id_x_from_sim_blocks>, k )
        //  ( k, l ),
        //  ( l, m ),
        //  ( <random_id_y_from_sim_blocks>, n ),
        //  ( n, o ),
        //  ( o, p )
        // ]
        for _ in 0..2 {
            let rand_block_id = sim_blocks
                .choose(&mut rand::thread_rng())
                .expect("should return any block in sim_blocks")
                .get_id();
            // generate a chain of 3 blocks for `rand_block_id` as parent.
            let mut blocks = gen_blocks_chain_starting_from_id(3, Some(rand_block_id.get()));
            conn_blocks.append(&mut blocks);
        }

        // alternate insert. At this point, the `orphans_by_prev_id` will look something like this:
        // in `orphans_by_prev_id`:
        // [
        //  ( a, (b,c,d,e,f,g,h,i,j) ),
        //  ( d, k )
        //  ( k, l ),
        //  ( l, m ),
        //  ( i, n ),
        //  ( n, o ),
        //  ( o, p )
        // ]
        for i in 0..sim_blocks.len() {
            if i < conn_blocks.len() {
                let b = conn_blocks[i].clone();
                orphans_pool.add_block(b).expect("should not fail");
            }

            let b = sim_blocks[i].clone();
            orphans_pool.add_block(b).expect("should not fail");
        }

        // collect all children of sim_blocks's prev_id
        let sim_parent_id = sim_blocks
            .first()
            .expect("this should return the first element")
            .get_prev_block_id()
            .get();
        let children = orphans_pool.take_all_children_of(&sim_parent_id);
        assert_eq!(children.len(), sim_blocks.len());

        // all blocks in sim_blocks should appear in the children list
        sim_blocks.iter().for_each(|child| {
            assert!(children.contains(child));
        });

        // the remaining blocks in the pool should all belong to conn_blocks;
        // the (d,k) and (i,n) should STILL be in the pool:
        // in `orphans_by_prev_id`:
        // [
        //  ( d, k ), ( k, l ), ( l, m ), ( i, n ), ( n, o ), ( o, p )
        // ]
        conn_blocks.iter().for_each(|block| {
            check_block_existence(&orphans_pool, block);
        })
    }
}
