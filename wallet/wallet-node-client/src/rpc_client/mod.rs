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

use jsonrpsee::http_client::HttpClient;
use jsonrpsee::http_client::HttpClientBuilder;
use rpc::make_http_header_with_auth;

use crate::node_traits::NodeInterface;

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
    pub async fn new(
        remote_socket_address: String,
        username_password: Option<(&str, &str)>,
    ) -> Result<Self, NodeRpcError> {
        let host = format!("http://{remote_socket_address}");
        let http_client = HttpClientBuilder::default()
            .set_headers(make_http_header_with_auth(username_password))
            .build(host)
            .map_err(NodeRpcError::ClientCreationError)?;

        let client = Self { http_client };

        client
            .get_best_block_id()
            .await
            .map_err(|e| NodeRpcError::InitializationError(Box::new(e)))?;

        Ok(client)
    }
}
