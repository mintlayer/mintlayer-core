use common::{
    chain::{Block, GenBlock},
    primitives::Id,
};

use crate::node_traits::NodeInterface;

use super::{NodeRpcClient, NodeRpcError};

impl NodeInterface for NodeRpcClient {
    type Error = NodeRpcError;

    fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        let block = self.get_block(block_id)?;
        Ok(block)
    }

    fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        let best_block_id = self.get_best_block_id()?;
        Ok(best_block_id)
    }
}
