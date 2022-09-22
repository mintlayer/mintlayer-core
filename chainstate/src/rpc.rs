// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Chainstate subsystem RPC handler

use std::io::Write;

use crate::{Block, BlockSource, ChainstateError, GenBlock};
use common::{
    chain::tokens::{RPCTokenInfo, TokenId},
    primitives::{BlockHeight, Id},
};
use serialization::{Decode, Encode};
use subsystem::subsystem::CallError;

#[rpc::rpc(server, namespace = "chainstate")]
trait ChainstateRpc {
    /// Get the best block ID
    #[method(name = "best_block_id")]
    async fn best_block_id(&self) -> rpc::Result<Id<GenBlock>>;

    /// Get block ID at given height in the mainchain
    #[method(name = "block_id_at_height")]
    async fn block_id_at_height(&self, height: BlockHeight) -> rpc::Result<Option<Id<GenBlock>>>;

    /// Submit a block to be included in the chain
    #[method(name = "submit_block")]
    async fn submit_block(&self, block_hex: String) -> rpc::Result<()>;

    /// Get block height in main chain
    #[method(name = "block_height_in_main_chain")]
    async fn block_height_in_main_chain(
        &self,
        block_id: Id<GenBlock>,
    ) -> rpc::Result<Option<BlockHeight>>;

    /// Get best block height in main chain
    #[method(name = "best_block_height")]
    async fn best_block_height(&self) -> rpc::Result<BlockHeight>;

    /// Get token information
    #[method(name = "token_info")]
    async fn token_info(&self, token_id: TokenId) -> rpc::Result<Option<RPCTokenInfo>>;

    /// Write blocks to disk
    #[method(name = "export_bootstrap_file")]
    async fn export_bootstrap_file(
        &self,
        file_path: &std::path::Path,
        include_orphans: bool,
    ) -> rpc::Result<()>;
}

#[async_trait::async_trait]
impl ChainstateRpcServer for super::ChainstateHandle {
    async fn best_block_id(&self) -> rpc::Result<Id<GenBlock>> {
        handle_error(self.call(|this| this.get_best_block_id()).await)
    }

    async fn block_id_at_height(&self, height: BlockHeight) -> rpc::Result<Option<Id<GenBlock>>> {
        handle_error(self.call(move |this| this.get_block_id_from_height(&height)).await)
    }

    async fn submit_block(&self, block_hex: String) -> rpc::Result<()> {
        // TODO there should be a generic way of decoding SCALE-encoded hex json strings
        let block_data = hex::decode(block_hex).map_err(rpc::Error::to_call_error)?;
        let block = Block::decode(&mut &block_data[..]).map_err(rpc::Error::to_call_error)?;
        let res = self.call_mut(move |this| this.process_block(block, BlockSource::Local)).await;
        // remove the block index from the return value
        let res = res.map(|v| v.map(|_bi| ()));
        handle_error(res)
    }

    async fn block_height_in_main_chain(
        &self,
        block_id: Id<GenBlock>,
    ) -> rpc::Result<Option<BlockHeight>> {
        handle_error(self.call(move |this| this.get_block_height_in_main_chain(&block_id)).await)
    }

    async fn best_block_height(&self) -> rpc::Result<BlockHeight> {
        handle_error(self.call(move |this| this.get_best_block_height()).await)
    }

    async fn token_info(&self, token_id: TokenId) -> rpc::Result<Option<RPCTokenInfo>> {
        handle_error(self.call(move |this| this.get_token_info_for_rpc(token_id)).await)
    }

    async fn export_bootstrap_file(
        &self,
        file_path: &std::path::Path,
        include_orphans: bool,
    ) -> rpc::Result<()> {
        let blocks_list = if include_orphans {
            handle_error(self.call(move |this| this.get_block_id_tree_as_list()).await)?
        } else {
            handle_error(self.call(move |this| this.get_mainchain_blocks_list()).await)?
        };
        let chain_config = self
            .call(move |this| this.get_chain_config())
            .await
            .map_err(rpc::Error::to_call_error)?;

        let magic_bytes = chain_config.magic_bytes();

        let file_obj = std::fs::File::create(file_path).map_err(rpc::Error::to_call_error)?;
        let mut writer = std::io::BufWriter::new(&file_obj);
        for block_id in blocks_list {
            writer.write(magic_bytes).map_err(rpc::Error::to_call_error)?;
            let block = handle_error(self.call(move |this| this.get_block(block_id)).await)?
                .ok_or(rpc::Error::Custom(
                    "Block not found by id after having being read from chainstate block index"
                        .to_owned(),
                ))?;
            writer.write(&block.encode())?;
        }
        Ok(())
    }
}

fn handle_error<T>(e: Result<Result<T, ChainstateError>, CallError>) -> rpc::Result<T> {
    e.map_err(rpc::Error::to_call_error)?.map_err(rpc::Error::to_call_error)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ChainstateConfig;
    use serde_json::Value;
    use std::{future::Future, sync::Arc};

    async fn with_chainstate<F: 'static + Send + Future<Output = ()>>(
        proc: impl 'static + Send + FnOnce(crate::ChainstateHandle) -> F,
    ) {
        let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let mut man = subsystem::Manager::new("rpctest");
        let handle = man.add_subsystem(
            "chainstate",
            crate::make_chainstate(
                chain_config,
                chainstate_config,
                storage,
                None,
                Default::default(),
            )
            .unwrap(),
        );
        let _ = man.add_raw_subsystem(
            "test",
            move |_: subsystem::subsystem::CallRequest<()>, _| proc(handle),
        );
        man.main().await;
    }

    #[tokio::test]
    async fn rpc_requests() {
        with_chainstate(|handle| async {
            let rpc = handle.into_rpc();

            let res = rpc.call("chainstate_best_block_height", [(); 0]).await;
            let best_height = match res {
                Ok(Value::Number(height)) => height,
                _ => panic!("expected a json value with a number"),
            };
            assert_eq!(best_height, 0.into());

            let res = rpc.call("chainstate_best_block_id", [(); 0]).await;
            let genesis_hash = match res {
                Ok(Value::String(hash_str)) => {
                    assert_eq!(hash_str.len(), 64);
                    assert!(hash_str.chars().all(|ch| ch.is_ascii_hexdigit()));
                    hash_str
                }
                _ => panic!("expected a json value with a string"),
            };

            let res: rpc::Result<Value> = rpc.call("chainstate_block_id_at_height", [0u32]).await;
            assert!(matches!(res, Ok(Value::String(hash)) if hash == genesis_hash));

            let res: rpc::Result<Value> = rpc.call("chainstate_block_id_at_height", [1u32]).await;
            assert!(matches!(res, Ok(Value::Null)));
        })
        .await
    }
}
