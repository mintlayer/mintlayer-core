use common::{
    chain::{Block, GenBlock},
    primitives::Id,
};

pub trait NodeInterface {
    type Error: std::error::Error;

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error>;
    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error>;
}
