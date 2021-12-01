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
            rng: rand::thread_rng()
        }
    }

    pub fn new_custom(max_orphans: usize) -> Self {
        OrphanBlocksPool {
            orphan_ids: Vec::new(),
            orphan_by_id: BTreeMap::new(),
            orphan_by_prev_id: BTreeMap::new(),
            max_orphans,
            rng: rand::thread_rng()
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
}

#[cfg(test)]
mod tests {
    use common::chain::block::BlockHeader;
    use rand::Rng;

    use super::*;

    fn gen_random_block() -> Block
    {
        let mut rng = rand::thread_rng();

        let header = BlockHeader {
            consensus_data: Vec::new(),
            hash_merkle_root: H256::from_low_u64_be(rng.gen()),
            hash_prev_block: H256::from_low_u64_be(rng.gen()),
            time: rng.gen(),
            version: 1,
        };
        Block {
            header,
            transactions: Vec::new(),
        }
    }

    fn gen_blocks(count: u32) -> Vec<Block> {
        (0..count).into_iter().map(|_| { gen_random_block() }).collect::<Vec<_>>()
    }

    #[test]
    fn simple_add() {
        let orphans_pool = OrphanBlocksPool::new_custom(3);

        let blocks = gen_blocks(10);
        assert_eq!(blocks.len(), 10);

        assert_eq!(orphans_pool.orphan_ids.len(), 0);
        assert_eq!(orphans_pool.orphan_by_id.len(), 0);
        assert_eq!(orphans_pool.orphan_by_prev_id.len(), 0);



    }
}
