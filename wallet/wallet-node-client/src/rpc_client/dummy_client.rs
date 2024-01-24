// Copyright (c) 2023 RBB S.r.l
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

use chainstate::ChainInfo;
use common::{
    chain::{
        tokens::{RPCTokenInfo, TokenId},
        Block, DelegationId, GenBlock, PoolId, SignedTransaction, Transaction,
    },
    primitives::{Amount, BlockHeight, Id},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e::EndToEndPublicKey;
use mempool::{tx_accumulator::PackingStrategy, tx_options::TxOptionsOverrides, FeeRate};
use p2p::{
    interface::types::ConnectedPeer,
    types::{bannable_address::BannableAddress, ip_or_socket_address::IpOrSocketAddress, PeerId},
};

use crate::node_traits::NodeInterface;

use super::{MaybeDummyNode, NodeRpcError};

#[async_trait::async_trait]
impl NodeInterface for MaybeDummyNode {
    type Error = NodeRpcError;

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.chainstate_info().await
        } else {
            let genesis = self.chain_config.genesis_block();
            Ok(ChainInfo {
                best_block_id: self.chain_config.genesis_block_id(),
                best_block_height: BlockHeight::zero(),
                best_block_timestamp: genesis.timestamp(),
                median_time: genesis.timestamp(),
                is_initial_block_download: false,
            })
        }
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_block(block_id).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_mainchain_blocks(from, max_count).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_best_block_id().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_best_block_height(&self) -> Result<common::primitives::BlockHeight, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_best_block_height().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_block_id_at_height(height).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_last_common_ancestor(first_block, second_block).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_stake_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_stake_pool_balance(pool_id).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_staker_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_staker_balance(pool_id).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_delegation_share(pool_id, delegation_id).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn get_token_info(&self, token_id: TokenId) -> Result<Option<RPCTokenInfo>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.get_token_info(token_id).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn generate_block_e2e_public_key(&self) -> Result<EndToEndPublicKey, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.generate_block_e2e_public_key().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn generate_block_e2e(
        &self,
        encrypted_input_data: Vec<u8>,
        public_key: EndToEndPublicKey,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client
                .generate_block_e2e(
                    encrypted_input_data,
                    public_key,
                    transactions,
                    transaction_ids,
                    packing_strategy,
                )
                .await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn generate_block(
        &self,
        input_data: GenerateBlockInputData,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client
                .generate_block(input_data, transactions, transaction_ids, packing_strategy)
                .await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn submit_block(&self, block: Block) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.submit_block(block).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn submit_transaction(
        &self,
        tx: SignedTransaction,
        options: TxOptionsOverrides,
    ) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.submit_transaction(tx, options).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.node_shutdown().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn node_version(&self) -> Result<String, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.node_version().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_connect(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_connect(address).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_disconnect(peer_id).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_list_banned(&self) -> Result<Vec<BannableAddress>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_list_banned().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_ban(&self, address: BannableAddress) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_ban(address).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_unban(&self, address: BannableAddress) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_unban(address).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_get_peer_count().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_get_connected_peers().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_add_reserved_node(&self, address: IpOrSocketAddress) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_add_reserved_node(address).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn p2p_remove_reserved_node(
        &self,
        address: IpOrSocketAddress,
    ) -> Result<(), Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.p2p_remove_reserved_node(address).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn mempool_get_fee_rate(&self, in_top_x_mb: usize) -> Result<FeeRate, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.mempool_get_fee_rate(in_top_x_mb).await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }

    async fn mempool_get_fee_rate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        if let Some(client) = self.opt_client.as_ref() {
            client.mempool_get_fee_rate_points().await
        } else {
            Err(NodeRpcError::ResponseError(
                jsonrpsee::core::ClientError::HttpNotImplemented,
            ))
        }
    }
}
