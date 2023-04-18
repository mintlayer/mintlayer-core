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

use base64::Engine;
use chainstate::rpc::ChainstateRpcClient;
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::http_client::HttpClientBuilder;
use serialization::hex::HexDecode;

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

fn get_headers(username_password: Option<(&str, &str)>) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    if let Some((username, password)) = username_password {
        headers.append(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
            ))
            .expect("Should not fail"),
        );
    }
    headers
}

impl NodeRpcClient {
    pub async fn new(
        remote_socket_address: String,
        username_password: Option<(&str, &str)>,
    ) -> Result<Self, NodeRpcError> {
        let host = format!("http://{remote_socket_address}");
        let http_client = HttpClientBuilder::default()
            .set_headers(get_headers(username_password))
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

    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, NodeRpcError> {
        ChainstateRpcClient::best_block_id(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_best_block_height(&self) -> Result<BlockHeight, NodeRpcError> {
        ChainstateRpcClient::best_block_height(&self.http_client)
            .await
            .map_err(NodeRpcError::ResponseError)
    }

    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, NodeRpcError> {
        ChainstateRpcClient::block_id_at_height(&self.http_client, height)
            .await
            .map_err(NodeRpcError::ResponseError)
    }
}
