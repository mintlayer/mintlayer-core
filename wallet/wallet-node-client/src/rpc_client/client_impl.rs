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

use chainstate::{rpc::ChainstateRpcClient, ChainInfo};
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use p2p::{interface::types::ConnectedPeer, rpc::P2pRpcClient, types::peer_id::PeerId};
use serialization::hex::HexDecode;

use crate::node_traits::NodeInterface;

use super::{NodeRpcClient, NodeRpcError};

#[async_trait::async_trait]
impl NodeInterface for NodeRpcClient {
    type Error = NodeRpcError;

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        ChainstateRpcClient::info(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        let response = ChainstateRpcClient::get_block(&self.http_client, block_id)
            .await
            .map_err(NodeRpcError::ResponseError)?;
        match response {
            Some(block_hex) => {
                let block = Block::hex_decode_all(block_hex)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        ChainstateRpcClient::best_block_id(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_best_block_height(&self) -> Result<common::primitives::BlockHeight, Self::Error> {
        ChainstateRpcClient::best_block_height(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        ChainstateRpcClient::block_id_at_height(&self.http_client, height)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_last_common_block(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        ChainstateRpcClient::last_common_block(&self.http_client, first_block, second_block)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn submit_block(&self, block_hex: String) -> Result<(), Self::Error> {
        ChainstateRpcClient::submit_block(&self.http_client, block_hex)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn submit_transaction(&self, transaction_hex: String) -> Result<(), Self::Error> {
        P2pRpcClient::submit_transaction(&self.http_client, transaction_hex)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        node_lib::rpc::NodeRpcClient::shutdown(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        node_lib::rpc::NodeRpcClient::version(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn p2p_connect(&self, address: String) -> Result<(), Self::Error> {
        P2pRpcClient::connect(&self.http_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_disconnect(&self, peer_id: PeerId) -> Result<(), Self::Error> {
        P2pRpcClient::disconnect(&self.http_client, peer_id)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        P2pRpcClient::get_peer_count(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        P2pRpcClient::get_connected_peers(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_add_reserved_node(&self, address: String) -> Result<(), Self::Error> {
        P2pRpcClient::add_reserved_node(&self.http_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
    async fn p2p_remove_reserved_node(&self, address: String) -> Result<(), Self::Error> {
        P2pRpcClient::remove_reserved_node(&self.http_client, address)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
}
