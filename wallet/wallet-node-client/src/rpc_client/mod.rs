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

pub mod client_impl;

use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use jsonrpsee::{core::params::ObjectParams, http_client::HttpClient};
use serialization::hex::{HexDecode, HexEncode};

#[derive(thiserror::Error, Debug)]
pub enum NodeRpcError {
    #[error("Initialization error: {0}")]
    InitializationError(Box<NodeRpcError>),
    #[error("Decoding error: {0}")]
    DecodingError(#[from] serialization::hex::HexError),
    #[error("Client creation error: {0}")]
    ClientCreationError(jsonrpsee::core::Error),
    #[error("Response error: {0}")]
    ResponseError(jsonrpsee::core::Error),
}

pub struct NodeRpcClient {
    http_client: HttpClient,
}

impl NodeRpcClient {
    pub async fn new(remote_socket_address: String) -> Result<Self, NodeRpcError> {
        let host = format!("http://{remote_socket_address}");
        let http_client = HttpClientBuilder::default()
            .build(host)
            .map_err(NodeRpcError::ClientCreationError)?;

        let client = Self { http_client };

        client
            .get_best_block_id()
            .await
            .map_err(|e| NodeRpcError::InitializationError(Box::new(e)))?;

        Ok(client)
    }

    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, NodeRpcError> {
        let block_id_hex = block_id.hex_encode();

        let params = {
            let mut params = ObjectParams::new();
            params.insert("id", block_id_hex).expect("Can't fail");
            params
        };

        let response: Option<String> = self
            .http_client
            .request("chainstate_get_block", params)
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

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, NodeRpcError> {
        let response: String = self
            .http_client
            .request("chainstate_best_block_id", rpc_params![])
            .await
            .map_err(NodeRpcError::ResponseError)?;

        let block_id = Id::<GenBlock>::hex_decode_all(response)?;
        Ok(block_id)
    }

    async fn get_best_block_height(&self) -> Result<BlockHeight, NodeRpcError> {
        let response: u64 = self
            .http_client
            .request("chainstate_best_block_height", rpc_params![])
            .await
            .map_err(NodeRpcError::ResponseError)?;

        Ok(response.into())
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, NodeRpcError> {
        let params = {
            let mut params = ObjectParams::new();
            params.insert("height", height).expect("Can't fail");
            params
        };

        let response: Option<Id<GenBlock>> = self
            .http_client
            .request("chainstate_block_id_at_height", params)
            .await
            .map_err(NodeRpcError::ResponseError)?;

        Ok(response)
    }
}
