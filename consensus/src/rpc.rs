//! Consensus subsystem RPC handler

use crate::ConsensusError;

use common::primitives::BlockHeight;
use subsystem::subsystem::CallError;

type BlockId = common::primitives::Id<common::chain::block::Block>;

#[rpc::rpc(server, namespace = "consensus")]
trait ConsensusRpc {
    /// Get the best block ID
    #[method(name = "best_block_id")]
    async fn best_block_id(&self) -> rpc::Result<String>;

    /// Get block ID at given height in the mainchain
    #[method(name = "block_id_at_height")]
    async fn block_id_at_height(&self, height: BlockHeight) -> rpc::Result<Option<BlockId>>;
}

#[async_trait::async_trait]
impl ConsensusRpcServer for super::ConsensusHandle {
    async fn best_block_id(&self) -> rpc::Result<String> {
        // TODO better way of converting Id<Foo> to Json
        let res = self
            .call(|this| this.get_best_block_id().map(|x| format!("{:?}", x.get())))
            .await;
        handle_error(res)
    }

    async fn block_id_at_height(&self, height: BlockHeight) -> rpc::Result<Option<BlockId>> {
        // TODO better way of converting Id<Foo> to Json
        let res = self.call(move |this| this.get_block_id_from_height(&height)).await;
        handle_error(res)
    }
}

fn handle_error<T>(e: Result<Result<T, ConsensusError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)
        .and_then(|r| r.map_err(rpc::Error::to_call_error))
}
