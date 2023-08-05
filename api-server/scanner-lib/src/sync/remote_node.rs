use chainstate::ChainInfo;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use node_comm::{
    node_traits::NodeInterface,
    rpc_client::{NodeRpcClient, NodeRpcError},
};

/// An abstraction for a node that can be called to retrieve information about the blockchain.
#[async_trait::async_trait]
pub trait RemoteNode {
    type Error: std::error::Error;

    async fn chainstate(&self) -> Result<ChainInfo, Self::Error>;
    async fn last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error>;
    async fn mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error>;
}

#[async_trait::async_trait]
impl RemoteNode for NodeRpcClient {
    type Error = NodeRpcError;

    async fn chainstate(&self) -> Result<ChainInfo, Self::Error> {
        self.chainstate_info().await
    }
    async fn last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        self.get_last_common_ancestor(first_block, second_block).await
    }

    async fn mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        self.get_mainchain_blocks(from, max_count).await
    }
}
