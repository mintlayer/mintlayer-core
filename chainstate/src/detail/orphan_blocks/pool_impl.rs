use std::ops::{Deref, DerefMut};

use common::{
    chain::{Block, GenBlock},
    primitives::{id::WithId, Id},
};

use super::{OrphanAddError, OrphanBlocksMut, OrphanBlocksPool, OrphanBlocksRef};

impl OrphanBlocksRef for &OrphanBlocksPool {
    fn len(&self) -> usize {
        self.deref().len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.deref().is_already_an_orphan(block_id)
    }
}

impl OrphanBlocksRef for &mut OrphanBlocksPool {
    fn len(&self) -> usize {
        self.deref().len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.deref().is_already_an_orphan(block_id)
    }
}

impl OrphanBlocksMut for &mut OrphanBlocksPool {
    fn clear(&mut self) {
        self.deref_mut().clear()
    }

    fn add_block(&mut self, block: WithId<Block>) -> Result<(), Box<OrphanAddError>> {
        self.deref_mut().add_block(block)
    }

    fn take_all_children_of(&mut self, block_id: &Id<GenBlock>) -> Vec<WithId<Block>> {
        self.deref_mut().take_all_children_of(block_id)
    }
}
