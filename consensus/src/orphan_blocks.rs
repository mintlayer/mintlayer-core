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
    pub fn new_default() -> Self {
        OrphanBlocksPool {
            orphan_ids: Vec::new(),
            orphan_by_id: BTreeMap::new(),
            orphan_by_prev_id: BTreeMap::new(),
            max_orphans: DEFAULT_MAX_ORPHAN_BLOCKS,
            rng: rand::thread_rng(),
        }
    }

    pub fn new_custom(max_orphans: usize) -> Self {
        OrphanBlocksPool {
            orphan_ids: Vec::new(),
            orphan_by_id: BTreeMap::new(),
            orphan_by_prev_id: BTreeMap::new(),
            max_orphans,
            rng: rand::thread_rng(),
        }
    }

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
            .get_mut(&block.get_prev_block_id())
            .expect("This should always be there since it was added with the other map");
        assert!(!prevs.is_empty());
        if prevs.len() == 1 {
            // if this is the only element left, we remove the whole vector
            self.orphan_by_prev_id
                .remove(&block.get_prev_block_id())
                .expect("Was already found before");
        } else {
            // we find the element that matches the block id
            let index = prevs
                .iter()
                .position(|blk| blk.get_id() == *block_id)
                .expect("Must be there since we inserted it");
            prevs.remove(index);
        }
    }

    // keep digging in the orphans tree until we find a block that has no children, then delete that
    fn del_one_deepest_child(&mut self, block_id: &H256) {
        let next_block = self
            .orphan_by_prev_id
            .get(block_id)
            .map(|v| v.get(0).expect("This list should never be empty as we always delete empty vectors from the map"))
            .cloned();
        match next_block {
            Some(block) => self.del_one_deepest_child(&block.get_id()),
            None => {
                self.drop_block(block_id);
            }
        }
    }

    fn prune(&mut self) {
        if self.orphan_by_id.len() < self.max_orphans {
            return;
        }
        let id = self.orphan_ids.choose(&mut self.rng);
        let id = *id.expect("As orphans can never be empty, this should always return");

        self.del_one_deepest_child(&id);
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), OrphanAddError> {
        self.prune();
        let block_id = block.get_id();
        if self.orphan_by_id.contains_key(&block_id) {
            return Err(OrphanAddError::BlockAlreadyInOrphanList(block));
        }

        let rc_block = Rc::new(block);
        self.orphan_by_id.insert(block_id, rc_block.clone());
        self.orphan_ids.push(block_id);
        self.orphan_by_prev_id
            .entry(rc_block.get_prev_block_id())
            .or_default()
            .push(rc_block.clone());
        Ok(())
    }

    pub fn is_already_an_orphan(&self, block_id: &H256) -> bool {
        self.orphan_by_id.contains_key(block_id)
    }

    pub fn clear(&mut self) {
        self.orphan_by_id.clear();
        self.orphan_ids.clear();
        self.orphan_by_prev_id.clear();
    }

    /// take all the blocks that share the same parent
    /// this is useful when a new tip is set, and we want to connect all its unorphaned children
    pub fn take_all_children_of(&mut self, block_id: &H256) -> Vec<Rc<Block>> {
        let res = self.orphan_by_prev_id.get_mut(block_id);
        let res = match res {
            None => {
                return Vec::new();
            }
            Some(v) => v.clone(),
        };
        // after we get all the blocks that have the same prev, we drop them from the pool
        res.iter().for_each(|blk| self.drop_block(&blk.get_id()));
        // after dropping everything, this is expected to be the only Rc left
        res.iter().for_each(|blk| assert_eq!(Rc::strong_count(blk), 1));
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::block::{Block, BlockHeader};
    use rand::Rng;

    fn gen_blocks(count: u32) -> Vec<Block> {
        (0..count).into_iter().map(|_| gen_random_block()).collect::<Vec<_>>()
    }

    fn gen_random_block() -> Block {
        gen_block(None)
    }

    fn gen_block(prev_block_id: Option<H256>) -> Block {
        let mut rng = rand::thread_rng();

        let header = BlockHeader {
            consensus_data: Vec::new(),
            hash_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: prev_block_id.unwrap_or(H256::from_low_u64_be(rng.gen())),
            time: rng.gen(),
            version: 1,
        };
        Block {
            header,
            transactions: Vec::new(),
        }
    }

    fn gen_connecting_blocks(count: u32) -> Vec<Block> {
        gen_connecting_blocks_from_id(count, None)
    }

    fn gen_connecting_blocks_from_id(count: u32, prev_block_id: Option<H256>) -> Vec<Block> {
        let mut rng = rand::thread_rng();

        let block = gen_block(prev_block_id);

        (1..count).into_iter().fold(vec![block], |mut blocks, _| {
            let prev_block_id = blocks.last().map(|block| block.get_id());

            blocks.push(gen_block(prev_block_id));
            blocks
        })
    }

    fn gen_similar_prev_id_blocks(count: u32) -> Vec<Block> {
        gen_similar_prev_id_blocks_from_id(count, None)
    }

    fn gen_similar_prev_id_blocks_from_id(count: u32, prev_block_id: Option<H256>) -> Vec<Block> {
        let mut rng = rand::thread_rng();

        let prev_block_id = if prev_block_id.is_none() {
            Some(H256::from_low_u64_be(rng.gen()))
        } else {
            prev_block_id
        };

        (0..count).into_iter().fold(vec![], |mut blocks, idx| {
            let block = gen_block(prev_block_id);

            blocks.push(block);
            blocks
        })
    }

    #[test]
    fn test_pool_default() {
        let orphans_pool = OrphanBlocksPool::new_default();
        assert_eq!(orphans_pool.max_orphans, DEFAULT_MAX_ORPHAN_BLOCKS);
        assert_eq!(orphans_pool.orphan_ids.len(), 0);
        assert_eq!(orphans_pool.orphan_by_id.len(), 0);
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 0);
    }

    #[test]
    fn test_pool_custom() {
        let orphans_pool = OrphanBlocksPool::new_custom(3);
        assert_eq!(orphans_pool.max_orphans, 3);
        assert_eq!(orphans_pool.orphan_ids.len(), 0);
        assert_eq!(orphans_pool.orphan_by_id.len(), 0);
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 0);
    }

    #[test]
    fn test_add_block_simple() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(3);

        let block = gen_random_block();
        assert!(orphans_pool.add_block(block.clone()).is_ok());

        let block_2 = gen_block(Some(block.get_id()));
        assert!(orphans_pool.add_block(block_2.clone()).is_ok());

        let block_id = block.get_id();
        let prev_block_id = block.get_prev_block_id();

        assert!(orphans_pool.orphan_ids.contains(&block_id));

        match orphans_pool.orphan_by_id.get(&block_id) {
            None => {
                panic!(
                    "the block id {:?} should be found in orphans_pool `orphan_by_id`.",
                    block_id
                );
            }
            Some(b) => {
                assert_eq!(b.clone(), Rc::from(block.clone()));
            }
        }

        match orphans_pool.orphan_by_prev_id.get(&prev_block_id) {
            None => {
                panic!(
                    "the block id {:?} should be found in orphans_pool `orphan_by_prev_id`.",
                    prev_block_id
                );
            }
            Some(blocks) => {
                if let Some(b) = blocks.last() {
                    assert_eq!(b.clone(), Rc::from(block.clone()));
                } else {
                    panic!(
                        "the block {:?} should be found in orphans_pool `orphan_by_prev_id`.",
                        block
                    );
                }
            }
        }
    }

    #[test]
    fn test_add_block_exceeds_max() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(3);
        let blocks = gen_blocks(5);

        blocks.iter().for_each(|block| {
            assert!(orphans_pool.add_block(block.clone()).is_ok());
        });

        assert_eq!(orphans_pool.max_orphans, 3);
        assert_eq!(orphans_pool.orphan_ids.len(), 3);
        assert_eq!(orphans_pool.orphan_by_id.len(), 3);
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 3);
    }

    #[test]
    fn test_add_block_repeated() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(100);
        let blocks = gen_blocks(50);

        blocks.iter().for_each(|block| {
            assert!(orphans_pool.add_block(block.clone()).is_ok());
        });

        let rand_block = blocks
            .choose(&mut orphans_pool.rng)
            .expect("this should return the first element");
        if let Err(e) = orphans_pool.add_block(rand_block.clone()) {
            assert_eq!(
                e,
                OrphanAddError::BlockAlreadyInOrphanList(rand_block.clone())
            );
        } else {
            panic!("the `add_block` operation should fail,because {:?} already exists, and is being added again.", rand_block.get_id());
        }
    }

    #[test]
    fn test_pool_drop_block() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(10);
        let blocks = gen_blocks(5);

        blocks.iter().for_each(|block| {
            assert!(orphans_pool.add_block(block.clone()).is_ok());
        });

        assert_eq!(orphans_pool.orphan_ids.len(), 5);

        let rand_block = blocks
            .choose(&mut orphans_pool.rng)
            .expect("this should return the first element");
        orphans_pool.drop_block(&rand_block.get_id());

        assert!(!orphans_pool.orphan_by_id.contains_key(&rand_block.get_id()));
        assert!(!orphans_pool.orphan_ids.contains(&rand_block.get_id()));
        assert!(!orphans_pool.orphan_by_prev_id.contains_key(&rand_block.get_prev_block_id()));
    }

    #[test]
    fn test_deepest_child_connecting_blocks() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(5);
        // In `orphan_by_prev_id`:
        // [
        //  ( a, b ),
        //  ( b, c ),
        //  ( c, d ),
        // ]
        let blocks = gen_connecting_blocks(3);

        blocks.iter().enumerate().for_each(|(idx, b)| {
            assert!(orphans_pool.add_block(b.clone()).is_ok());

            let block_id = orphans_pool.orphan_ids[idx];
            assert_eq!(b.get_id(), block_id);

            if let Some(block) = orphans_pool.orphan_by_id.get(&block_id) {
                assert_eq!(block, &Rc::new(b.clone()));
            } else {
                panic!("block {:?} not found for key {:?}", b, block_id);
            }

            if let Some(blocks) = orphans_pool.orphan_by_prev_id.get(&b.get_prev_block_id()) {
                assert_eq!(blocks.len(), 1);

                let only_block = blocks.first().expect("this should not be empty");
                assert_eq!(only_block, &Rc::new(b.clone()));
            } else {
                panic!(
                    "block {:?} not found for key {:?}",
                    b,
                    b.get_prev_block_id()
                );
            }
        });
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 3);
        assert_eq!(orphans_pool.orphan_ids.len(), 3);

        let first_block = blocks.first().expect("list should not be empty");
        let last_block = blocks.last().expect("list should not be empty");

        {
            let x = orphans_pool
                .orphan_by_prev_id
                .get(&last_block.get_prev_block_id())
                .expect("this id should exist");
            assert_eq!(x.len(), 1);
        }

        // block d should be removed:
        // [
        //  ( a, b ),
        //  ( b, c ),
        // ]
        orphans_pool.del_one_deepest_child(&first_block.get_id());

        assert!(!orphans_pool.orphan_by_id.contains_key(&last_block.get_id()));
        assert!(!orphans_pool.orphan_by_prev_id.contains_key(&last_block.get_prev_block_id()));
        assert_eq!(orphans_pool.orphan_ids.len(), 2);
    }

    #[test]
    fn test_deepest_child_similar_prev_ids() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(5);
        // In `orphan_by_prev_id`:
        // [
        //  ( a, (b,c,d) ),
        // ]
        let blocks = gen_similar_prev_id_blocks(3);

        blocks.iter().enumerate().for_each(|(idx, b)| {
            assert!(orphans_pool.add_block(b.clone()).is_ok());

            let block_id = orphans_pool.orphan_ids[idx];
            assert_eq!(b.get_id(), block_id);

            if let Some(block) = orphans_pool.orphan_by_id.get(&block_id) {
                assert_eq!(block, &Rc::new(b.clone()));
            } else {
                panic!("block {:?} not found for key {:?}", b, block_id);
            }

            if let Some(blocks) = orphans_pool.orphan_by_prev_id.get(&b.get_prev_block_id()) {
                assert_eq!(blocks.len(), idx + 1);
                let block_id = &blocks[idx].get_id();
                assert_eq!(&b.get_id(), block_id);
            } else {
                panic!("no blocks found for key {:?}", b.get_prev_block_id());
            }
        });
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 1);
        assert_eq!(orphans_pool.orphan_ids.len(), 3);

        let random_block = blocks.choose(&mut orphans_pool.rng).expect("list should not be empty");
        {
            let x = orphans_pool
                .orphan_by_prev_id
                .get(&random_block.get_prev_block_id())
                .expect("this id should exist");
            assert_eq!(x.len(), 3);
        }

        orphans_pool.del_one_deepest_child(&random_block.get_id());

        assert!(!orphans_pool.orphan_by_id.contains_key(&random_block.get_id()));

        if let Some(blocks) = orphans_pool.orphan_by_prev_id.get(&random_block.get_prev_block_id())
        {
            assert_eq!(blocks.len(), 2);
        } else {
            panic!(
                "there should still be 2 elements in id: {:?}",
                random_block.get_prev_block_id()
            );
        }

        assert_eq!(orphans_pool.orphan_ids.len(), 2);
    }

    fn prune_result(orphans_pool: &mut OrphanBlocksPool) {
        let orphans_len = orphans_pool.max_orphans - 1;
        assert_eq!(orphans_pool.orphan_ids.len(), orphans_len);
        assert_eq!(orphans_pool.orphan_by_id.len(), orphans_len);

        let len = orphans_pool
            .orphan_by_prev_id
            .iter()
            .fold(0usize, |acc, (_, value)| acc + value.len());
        assert_eq!(len, orphans_len);
    }

    #[test]
    fn test_prune() {
        let mut orphans_pool = OrphanBlocksPool::new_custom(12);
        // [
        //  ( a, (b,c,d,e) )
        // ]
        let sim_blocks = gen_similar_prev_id_blocks(4);

        // [
        //  ( f, g ),
        //  ( g, h ),
        //  ( h, i ),
        // ]
        let conn_blocks = gen_connecting_blocks(3);

        // generate connecting block using one of sim's blocks.
        let sim_block_id = sim_blocks.last().expect("it should return first element").get_id();
        // [
        //  ( e, j ),
        //  ( j, k )
        // ]
        let extra_sim_blocks = gen_connecting_blocks_from_id(2, Some(sim_block_id));

        // generate blocks with similar using one of conn's blocks
        let conn_block_id = conn_blocks.last().expect("it should return second element").get_id();
        // [
        //  ( i, (l,m,n) )
        // ]
        let extra_conn_blocks = gen_similar_prev_id_blocks_from_id(3, Some(conn_block_id));

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
            orphans_pool.add_block(block.clone());
        });

        assert_eq!(orphans_pool.orphan_by_id.len(), blocks.len());
        assert_eq!(orphans_pool.orphan_ids.len(), blocks.len());
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 7);

        // 1 block is removed; size is 1 less than the set max_orphans
        orphans_pool.prune();
        prune_result(&mut orphans_pool);

        // for the 2nd prune, nothing should happen.
        orphans_pool.prune();
        prune_result(&mut orphans_pool);

        // add a random block
        let random_block = gen_random_block();
        assert!(orphans_pool.add_block(random_block).is_ok());

        assert_eq!(orphans_pool.orphan_ids.len(), orphans_pool.max_orphans);
        assert_eq!(orphans_pool.orphan_by_id.len(), orphans_pool.max_orphans);
        let len = orphans_pool
            .orphan_by_prev_id
            .iter()
            .fold(0usize, |acc, (_, value)| acc + value.len());
        assert_eq!(len, orphans_pool.max_orphans);

        // this will trigger pruning
        orphans_pool.prune();
        prune_result(&mut orphans_pool);
    }
}
