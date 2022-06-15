use super::{OrphanAddError, OrphanBlocksPool};
use common::{chain::block::Block, primitives::Id};

pub trait OrphansReadOnly {
    fn len(&self) -> usize;
    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool;
}

pub trait OrphansReadWrite: OrphansReadOnly {
    fn clear(&mut self);
    fn add_block(&mut self, block: Block) -> Result<(), OrphanAddError>;
    fn take_all_children_of(&mut self, block_id: &Id<Block>) -> Vec<Block>;
}

pub struct OrphansReadOnlyRef<'a> {
    inner: &'a OrphanBlocksPool,
}

impl<'a> OrphansReadOnlyRef<'a> {
    pub fn new(inner: &'a OrphanBlocksPool) -> Self {
        Self { inner }
    }
}

impl<'a> OrphansReadOnly for OrphansReadOnlyRef<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.inner.is_already_an_orphan(block_id)
    }
}

pub struct OrphansReadWriteRef<'a> {
    inner: &'a mut OrphanBlocksPool,
}

impl<'a> OrphansReadWriteRef<'a> {
    pub fn new(inner: &'a mut OrphanBlocksPool) -> Self {
        Self { inner }
    }
}

impl<'a> OrphansReadOnly for OrphansReadWriteRef<'a> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_already_an_orphan(&self, block_id: &Id<Block>) -> bool {
        self.inner.is_already_an_orphan(block_id)
    }
}

impl<'a> OrphansReadWrite for OrphansReadWriteRef<'a> {
    fn clear(&mut self) {
        self.inner.clear()
    }

    fn add_block(&mut self, block: Block) -> Result<(), OrphanAddError> {
        self.inner.add_block(block)
    }

    fn take_all_children_of(&mut self, block_id: &Id<Block>) -> Vec<Block> {
        self.inner.take_all_children_of(block_id)
    }
}
