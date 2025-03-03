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

mod types;

use std::{
    convert::Infallible,
    io::{Read, Write},
    num::NonZeroUsize,
    sync::Arc,
};

use self::types::{block::RpcBlock, event::RpcEvent};
use crate::{Block, BlockSource, ChainInfo, GenBlock};
use chainstate_types::BlockIndex;
use common::{
    address::{dehexify::to_dehexified_json, Address},
    chain::{
        tokens::{RPCTokenInfo, TokenId},
        ChainConfig, DelegationId, Destination, OrderId, PoolId, RpcOrderInfo, TxOutput,
    },
    primitives::{Amount, BlockHeight, Id},
};
use rpc::{subscription, RpcResult};
use serialization::hex_encoded::HexEncoded;
pub use types::{
    input::RpcUtxoOutpoint,
    output::{RpcOutputValueIn, RpcOutputValueOut, RpcTxOutput},
    signed_transaction::RpcSignedTransaction,
};

#[rpc::describe]
#[rpc::rpc(server, client, namespace = "chainstate")]
trait ChainstateRpc {
    /// Get the best block ID, which is the tip of the blockchain (i.e., longest chain, or mainchain).
    #[method(name = "best_block_id")]
    async fn best_block_id(&self) -> RpcResult<Id<GenBlock>>;

    /// Get block ID at a given height in the mainchain.
    ///
    /// Returns `None` (null) if the block at the given height does not exist.
    #[method(name = "block_id_at_height")]
    async fn block_id_at_height(&self, height: BlockHeight) -> RpcResult<Option<Id<GenBlock>>>;

    /// Returns a hex-encoded serialized block with the given id.
    ///
    /// Returns `None` (null) if a block with the given id is not found.
    /// Note that genesis cannot be retrieved with this function.
    #[method(name = "get_block")]
    async fn get_block(&self, id: Id<Block>) -> RpcResult<Option<HexEncoded<Block>>>;

    /// Same as get_block, but returns the block information in json format.
    #[method(name = "get_block_json")]
    async fn get_block_json(&self, id: Id<Block>) -> RpcResult<Option<serde_json::Value>>;

    /// Returns hex-encoded serialized blocks from the mainchain starting from a given block height.
    ///
    /// The number of returned blocks can be capped using the `max_count` parameter.
    #[method(name = "get_mainchain_blocks")]
    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> RpcResult<Vec<HexEncoded<Block>>>;

    /// Returns mainchain block ids with heights in the range start_height..end_height using
    /// the given step;
    #[method(name = "get_block_ids_as_checkpoints")]
    async fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> RpcResult<Vec<(BlockHeight, Id<GenBlock>)>>;

    /// Returns the TxOutput for a specified UtxoOutPoint.
    /// Returns `None` (null) if the UtxoOutPoint is not found or is already spent.
    #[method(name = "get_utxo")]
    async fn get_utxo(&self, outpoint: RpcUtxoOutpoint) -> RpcResult<Option<TxOutput>>;

    /// Submit a block to be included in the blockchain.
    ///
    /// Note that the submission does not circumvent any validation process.
    /// This function is used by the wallet to submit valid blocks after successful staking.
    #[method(name = "submit_block")]
    async fn submit_block(&self, block_hex: HexEncoded<Block>) -> RpcResult<()>;

    /// Invalidate the specified block and its descendants.
    ///
    /// Use this function with caution, as invalidating a block that the network approves
    /// of can lead to staying behind.
    #[method(name = "invalidate_block")]
    async fn invalidate_block(&self, id: Id<Block>) -> RpcResult<()>;

    /// Reset failure flags for the specified block and its descendants.
    #[method(name = "reset_block_failure_flags")]
    async fn reset_block_failure_flags(&self, id: Id<Block>) -> RpcResult<()>;

    /// Get block height in mainchain, given a block id.
    #[method(name = "block_height_in_main_chain")]
    async fn block_height_in_main_chain(
        &self,
        block_id: Id<GenBlock>,
    ) -> RpcResult<Option<BlockHeight>>;

    /// Get best block height in mainchain.
    #[method(name = "best_block_height")]
    async fn best_block_height(&self) -> RpcResult<BlockHeight>;

    /// Returns last common block id and height of two chains.
    /// Returns None if no blocks are found and therefore the last common ancestor is unknown.
    #[method(name = "last_common_ancestor_by_id")]
    async fn last_common_ancestor_by_id(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> RpcResult<Option<(Id<GenBlock>, BlockHeight)>>;

    /// Returns the balance of the pool associated with the given pool id.
    ///
    /// The balance contains both delegated balance and staker balance.
    /// Returns `None` (null) if the pool is not found.
    #[method(name = "stake_pool_balance")]
    async fn stake_pool_balance(&self, pool_address: String) -> RpcResult<Option<Amount>>;

    /// Returns the balance of the staker (pool owner) of the pool associated with the given pool address.
    ///
    /// This excludes the delegation balances.
    /// Returns `None` (null) if the pool is not found.
    #[method(name = "staker_balance")]
    async fn staker_balance(&self, pool_address: String) -> RpcResult<Option<Amount>>;

    /// Returns the pool's decommission destination associated with the given pool address.
    ///
    /// Returns `None` (null) if the pool is not found.
    #[method(name = "pool_decommission_destination")]
    async fn pool_decommission_destination(
        &self,
        pool_address: String,
    ) -> RpcResult<Option<Destination>>;

    /// Given a pool defined by a pool address, and a delegation address,
    /// returns the amount of coins owned by that delegation in that pool.
    #[method(name = "delegation_share")]
    async fn delegation_share(
        &self,
        pool_address: String,
        delegation_address: String,
    ) -> RpcResult<Option<Amount>>;

    /// Get token information, given a token id, in address form.
    #[method(name = "token_info")]
    async fn token_info(&self, token_id: String) -> RpcResult<Option<RPCTokenInfo>>;

    /// Get order information, given an order id, in address form.
    #[method(name = "order_info")]
    async fn order_info(&self, order_id: String) -> RpcResult<Option<RpcOrderInfo>>;

    /// Exports a "bootstrap file", which contains all blocks
    #[method(name = "export_bootstrap_file")]
    async fn export_bootstrap_file(
        &self,
        file_path: &std::path::Path,
        include_orphans: bool,
    ) -> RpcResult<()>;

    /// Imports a bootstrap file's blocks to this node
    #[method(name = "import_bootstrap_file")]
    async fn import_bootstrap_file(&self, file_path: &std::path::Path) -> RpcResult<()>;

    /// Return generic information about the chain, including the current best block, best block height and more.
    #[method(name = "info")]
    async fn info(&self) -> RpcResult<ChainInfo>;

    /// Subscribe to chainstate events, such as new tip.
    ///
    /// After a successful subscription, the node will message the subscriber with a message on every event.
    #[subscription(name = "subscribe_to_events", item = RpcEvent)]
    async fn subscribe_to_events(&self) -> rpc::subscription::Reply;
}

#[async_trait::async_trait]
impl ChainstateRpcServer for super::ChainstateHandle {
    async fn best_block_id(&self) -> RpcResult<Id<GenBlock>> {
        rpc::handle_result(self.call(|this| this.get_best_block_id()).await)
    }

    async fn block_id_at_height(&self, height: BlockHeight) -> RpcResult<Option<Id<GenBlock>>> {
        rpc::handle_result(self.call(move |this| this.get_block_id_from_height(&height)).await)
    }

    async fn get_block(&self, id: Id<Block>) -> RpcResult<Option<HexEncoded<Block>>> {
        let block: Option<Block> =
            rpc::handle_result(self.call(move |this| this.get_block(id)).await)?;
        Ok(block.map(HexEncoded::new))
    }

    async fn get_block_json(&self, id: Id<Block>) -> RpcResult<Option<serde_json::Value>> {
        let both: Option<(Block, BlockIndex)> = rpc::handle_result(
            self.call(move |this| {
                let block = this.get_block(id);
                let block_index = this.get_block_index_for_persisted_block(&id);
                match (block, block_index) {
                    (Ok(block), Ok(block_index)) => Ok(block.zip(block_index)),
                    (Err(e), _) => Err(e),
                    (_, Err(e)) => Err(e),
                }
            })
            .await,
        )?;

        let chain_config: Arc<ChainConfig> = rpc::handle_result(
            self.call(move |this| {
                let chain_config = Arc::clone(this.get_chain_config());
                Ok::<_, Infallible>(chain_config)
            })
            .await,
        )?;

        let rpc_blk: Option<RpcBlock> = both
            .map(|(block, block_index)| {
                rpc::handle_result(RpcBlock::new(&chain_config, block, block_index))
            })
            .transpose()?;

        let result = rpc_blk.map(|rpc_blk| to_dehexified_json(&chain_config, rpc_blk)).transpose();

        rpc::handle_result(result)
    }

    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> RpcResult<Vec<HexEncoded<Block>>> {
        let blocks: Vec<Block> = rpc::handle_result(
            self.call(move |this| this.get_mainchain_blocks(from, max_count)).await,
        )?;
        Ok(blocks.into_iter().map(HexEncoded::new).collect())
    }

    async fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> RpcResult<Vec<(BlockHeight, Id<GenBlock>)>> {
        rpc::handle_result(
            self.call(move |this| {
                this.get_block_ids_as_checkpoints(start_height, end_height, step)
            })
            .await,
        )
    }

    async fn get_utxo(&self, outpoint: RpcUtxoOutpoint) -> RpcResult<Option<TxOutput>> {
        let outpoint = outpoint.into_outpoint();
        rpc::handle_result(
            self.call_mut(move |this| {
                this.utxo(&outpoint).map(|utxo| utxo.map(|utxo| utxo.take_output()))
            })
            .await,
        )
    }

    async fn submit_block(&self, block: HexEncoded<Block>) -> RpcResult<()> {
        let res = self
            .call_mut(move |this| this.process_block(block.take(), BlockSource::Local))
            .await;
        // remove the block index from the return value
        let res = res.map(|v| v.map(|_bi| ()));
        rpc::handle_result(res)
    }

    async fn invalidate_block(&self, id: Id<Block>) -> RpcResult<()> {
        rpc::handle_result(self.call_mut(move |this| this.invalidate_block(&id)).await)
    }

    async fn reset_block_failure_flags(&self, id: Id<Block>) -> RpcResult<()> {
        rpc::handle_result(self.call_mut(move |this| this.reset_block_failure_flags(&id)).await)
    }

    async fn block_height_in_main_chain(
        &self,
        block_id: Id<GenBlock>,
    ) -> RpcResult<Option<BlockHeight>> {
        rpc::handle_result(
            self.call(move |this| this.get_block_height_in_main_chain(&block_id)).await,
        )
    }

    async fn best_block_height(&self) -> RpcResult<BlockHeight> {
        rpc::handle_result(self.call(move |this| this.get_best_block_height()).await)
    }

    async fn last_common_ancestor_by_id(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> RpcResult<Option<(Id<GenBlock>, BlockHeight)>> {
        rpc::handle_result(
            self.call(move |this| this.last_common_ancestor_by_id(&first_block, &second_block))
                .await,
        )
    }

    async fn stake_pool_balance(&self, pool_address: String) -> RpcResult<Option<Amount>> {
        rpc::handle_result(
            self.call(move |this| {
                let chain_config = this.get_chain_config();
                let id_result = Address::<PoolId>::from_string(chain_config, pool_address);
                id_result.map(|address| this.get_stake_pool_balance(address.into_object()))
            })
            .await,
        )
    }

    async fn staker_balance(&self, pool_address: String) -> RpcResult<Option<Amount>> {
        rpc::handle_result(
            self.call(move |this| {
                let chain_config = this.get_chain_config();
                let result: Result<Option<Amount>, _> =
                    dynamize_err(Address::<PoolId>::from_string(chain_config, pool_address))
                        .map(|address| address.into_object())
                        .and_then(|pool_id| dynamize_err(this.get_stake_pool_data(pool_id)))
                        .and_then(|pool_data| {
                            dynamize_err(pool_data.map(|d| d.staker_balance()).transpose())
                        });

                result
            })
            .await,
        )
    }

    async fn pool_decommission_destination(
        &self,
        pool_address: String,
    ) -> RpcResult<Option<Destination>> {
        rpc::handle_result(
            self.call(move |this| {
                let chain_config = this.get_chain_config();
                let result: Result<Option<Destination>, _> =
                    dynamize_err(Address::<PoolId>::from_string(chain_config, pool_address))
                        .map(|address| address.into_object())
                        .and_then(|pool_id| dynamize_err(this.get_stake_pool_data(pool_id)))
                        .map(|pool_data| pool_data.map(|d| d.decommission_destination().clone()));

                result
            })
            .await,
        )
    }

    async fn delegation_share(
        &self,
        pool_address: String,
        delegation_address: String,
    ) -> RpcResult<Option<Amount>> {
        rpc::handle_result(
            self.call(move |this| {
                let chain_config = this.get_chain_config();

                let pool_id_result =
                    dynamize_err(Address::<PoolId>::from_string(chain_config, &pool_address))
                        .map(|address| address.into_object());

                let delegation_id_result = dynamize_err(Address::<DelegationId>::from_string(
                    chain_config,
                    &delegation_address,
                ))
                .map(|address| address.into_object());

                let ids = pool_id_result.and_then(|x| delegation_id_result.map(|y| (x, y)));

                ids.and_then(|(pool_id, del_id)| {
                    dynamize_err(this.get_stake_pool_delegation_share(pool_id, del_id))
                })
            })
            .await,
        )
    }

    async fn token_info(&self, token_id: String) -> RpcResult<Option<RPCTokenInfo>> {
        rpc::handle_result(
            self.call(move |this| {
                let chain_config = this.get_chain_config();
                let token_info_result: Result<Option<RPCTokenInfo>, _> =
                    dynamize_err(Address::<TokenId>::from_string(chain_config, token_id))
                        .map(|address| address.into_object())
                        .and_then(|token_id| dynamize_err(this.get_token_info_for_rpc(token_id)));

                token_info_result
            })
            .await,
        )
    }

    async fn order_info(&self, order_id: String) -> RpcResult<Option<RpcOrderInfo>> {
        rpc::handle_result(
            self.call(move |this| {
                let chain_config = this.get_chain_config();
                let result: Result<Option<RpcOrderInfo>, _> =
                    dynamize_err(Address::<OrderId>::from_string(chain_config, order_id))
                        .map(|address| address.into_object())
                        .and_then(|order_id| dynamize_err(this.get_order_info_for_rpc(order_id)));

                result
            })
            .await,
        )
    }

    async fn export_bootstrap_file(
        &self,
        file_path: &std::path::Path,
        include_orphans: bool,
    ) -> RpcResult<()> {
        // TODO: test this function in functional tests
        let file_obj: std::fs::File = rpc::handle_result(std::fs::File::create(file_path))?;
        let writer: std::io::BufWriter<Box<dyn Write + Send>> =
            std::io::BufWriter::new(Box::new(file_obj));

        rpc::handle_result(
            self.call(move |this| this.export_bootstrap_stream(writer, include_orphans))
                .await,
        )
    }

    async fn import_bootstrap_file(&self, file_path: &std::path::Path) -> RpcResult<()> {
        // TODO: test this function in functional tests
        let file_obj: std::fs::File = rpc::handle_result(std::fs::File::create(file_path))?;
        let reader: std::io::BufReader<Box<dyn Read + Send>> =
            std::io::BufReader::new(Box::new(file_obj));

        rpc::handle_result(self.call_mut(move |this| this.import_bootstrap_stream(reader)).await)
    }

    async fn info(&self) -> RpcResult<ChainInfo> {
        rpc::handle_result(self.call(move |this| this.info()).await)
    }

    async fn subscribe_to_events(&self, pending: subscription::Pending) -> subscription::Reply {
        let event_rx = self.call_mut(move |this| this.subscribe_to_rpc_events()).await?;
        rpc::subscription::connect_broadcast_map(event_rx, pending, RpcEvent::from_event).await
    }
}

fn dynamize_err<T, E: std::error::Error + Send + Sync>(
    o: Result<T, E>,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
where
    Box<dyn std::error::Error + Send + Sync>: From<E>,
{
    o.map_err(Into::into)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{ChainstateConfig, DefaultTransactionVerificationStrategy};
    use rpc::RpcCallResult;
    use serde_json::Value;
    use std::{future::Future, sync::Arc};

    async fn with_chainstate<F: Send + Future<Output = ()> + 'static>(
        proc: impl Send + FnOnce(crate::ChainstateHandle) -> F + 'static,
    ) {
        let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
        let chain_config = Arc::new(common::chain::config::create_unit_test_config());
        let chainstate_config = ChainstateConfig::new();
        let mut man = subsystem::Manager::new("rpctest");
        let shutdown = man.make_shutdown_trigger();
        let handle = man.add_subsystem(
            "chainstate",
            crate::make_chainstate(
                chain_config,
                chainstate_config,
                storage,
                DefaultTransactionVerificationStrategy::new(),
                None,
                Default::default(),
            )
            .unwrap(),
        );
        let tester = tokio::spawn(async move {
            proc(handle);
            shutdown.initiate();
        });
        let _ = tokio::join!(man.main(), tester);
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

            let res: RpcCallResult<Value> = rpc.call("chainstate_block_id_at_height", [0u32]).await;
            assert!(matches!(res, Ok(Value::String(hash)) if hash == genesis_hash));

            let res: RpcCallResult<Value> = rpc.call("chainstate_block_id_at_height", [1u32]).await;
            assert!(matches!(res, Ok(Value::Null)));
        })
        .await
    }
}
