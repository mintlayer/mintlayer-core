//! Consensus subsystem RPC handler

use crate::ConsensusError;

use crate::{Block, BlockSource};
use common::primitives::BlockHeight;
use serialization::Decode;
use subsystem::subsystem::CallError;

type BlockId = common::primitives::Id<common::chain::block::Block>;

#[rpc::rpc(server, namespace = "consensus")]
trait ConsensusRpc {
    /// Get the best block ID
    #[method(name = "best_block_id")]
    async fn best_block_id(&self) -> rpc::Result<BlockId>;

    /// Get block ID at given height in the mainchain
    #[method(name = "block_id_at_height")]
    async fn block_id_at_height(&self, height: BlockHeight) -> rpc::Result<Option<BlockId>>;

    /// Submit a block to be included in the chain
    #[method(name = "submit_block")]
    async fn submit_block(&self, block_hex: String) -> rpc::Result<()>;

    /// Get block height in main chain
    #[method(name = "block_height_in_main_chain")]
    async fn block_height_in_main_chain(
        &self,
        block_id: BlockId,
    ) -> rpc::Result<Option<BlockHeight>>;
}

#[async_trait::async_trait]
impl ConsensusRpcServer for super::ConsensusHandle {
    async fn best_block_id(&self) -> rpc::Result<BlockId> {
        handle_error(self.call(|this| this.get_best_block_id()).await)
    }

    async fn block_id_at_height(&self, height: BlockHeight) -> rpc::Result<Option<BlockId>> {
        handle_error(self.call(move |this| this.get_block_id_from_height(&height)).await)
    }

    async fn submit_block(&self, block_hex: String) -> rpc::Result<()> {
        // TODO there should be a generic way of decoding SCALE-encoded hex json strings
        let block_data = hex::decode(block_hex).map_err(rpc::Error::to_call_error)?;
        let block = Block::decode(&mut &block_data[..]).map_err(rpc::Error::to_call_error)?;
        let res = self.call_mut(move |this| this.process_block(block, BlockSource::Local)).await;
        handle_error(res)
    }

    async fn block_height_in_main_chain(
        &self,
        block_id: BlockId,
    ) -> rpc::Result<Option<BlockHeight>> {
        handle_error(self.call(move |this| this.get_block_height_in_main_chain(&block_id)).await)
    }
}

fn handle_error<T>(e: Result<Result<T, ConsensusError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)?.map_err(rpc::Error::to_call_error)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::Value;
    use std::{future::Future, sync::Arc};

    async fn with_consensus<F: 'static + Send + Future<Output = ()>>(
        proc: impl 'static + Send + FnOnce(crate::ConsensusHandle) -> F,
    ) {
        let storage = blockchain_storage::Store::new_empty().unwrap();
        let cfg = Arc::new(common::chain::config::create_unit_test_config());
        let mut man = subsystem::Manager::new("rpctest");
        let handle = man.add_subsystem(
            "consensus",
            crate::make_consensus(cfg, storage, None).unwrap(),
        );
        let _ = man.add_raw_subsystem(
            "test",
            move |_: subsystem::subsystem::CallRequest<()>, _| proc(handle),
        );
        man.main().await;
    }

    #[tokio::test]
    async fn rpc_requests() {
        with_consensus(|handle| async {
            let rpc = handle.into_rpc();

            let res = rpc.call("consensus_best_block_id", [(); 0]).await;
            let genesis_hash = match res {
                Ok(Value::String(hash_str)) => {
                    assert_eq!(hash_str.len(), 64);
                    assert!(hash_str.chars().all(|ch| ch.is_ascii_hexdigit()));
                    hash_str
                }
                _ => panic!("expected a json object"),
            };

            let res: rpc::Result<Value> = rpc.call("consensus_block_id_at_height", [0u32]).await;
            assert!(matches!(res, Ok(Value::String(hash)) if hash == genesis_hash));

            let res: rpc::Result<Value> = rpc.call("consensus_block_id_at_height", [1u32]).await;
            assert!(matches!(res, Ok(Value::Null)));
        })
        .await
    }
}
