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
pub mod cold_wallet_client;

use std::sync::Arc;

use common::{
    address::AddressError, chain::ChainConfig, primitives::per_thousand::PerThousandParseError,
};
use rpc::{ClientError, RpcAuthData, RpcWsClient, new_ws_client};

use crate::node_traits::{NodeInterface, NodeInterfaceError};

#[derive(thiserror::Error, Debug)]
pub enum NodeRpcError {
    #[error("Initialization error: {0}")]
    InitializationError(Box<NodeRpcError>),
    #[error("Decoding error: {0}")]
    DecodingError(#[from] serialization::hex::HexError),
    #[error("Client creation error: {0}")]
    ClientCreationError(ClientError),
    #[error("Response error: {0}")]
    ResponseError(ClientError),
    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),
    #[error("PerThousand parse error: {0}")]
    PerThousandParseError(#[from] PerThousandParseError),
}

impl NodeInterfaceError for NodeRpcError {
    fn is_recoverable_mempool_error_during_block_production(&self) -> bool {
        match self {
            NodeRpcError::ResponseError(err) => match err {
                rpc::ClientError::Call(err_obj) => {
                    err_obj.message().contains(blockprod::RECOVERABLE_MEMPOOL_ERROR_MSG)
                }
                _ => false,
            },

            NodeRpcError::InitializationError(_)
            | NodeRpcError::DecodingError(_)
            | NodeRpcError::ClientCreationError(_)
            | NodeRpcError::AddressError(_)
            | NodeRpcError::PerThousandParseError(_) => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ColdWalletClient {
    chain_config: Arc<ChainConfig>,
}

impl ColdWalletClient {
    pub fn new(chain_config: Arc<ChainConfig>) -> Self {
        Self { chain_config }
    }
}

#[derive(Clone, Debug)]
pub struct NodeRpcClient {
    rpc_client: Arc<RpcWsClient>,
    chain_config: Arc<ChainConfig>,
}

impl NodeRpcClient {
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        remote_socket_address: String,
        rpc_auth: RpcAuthData,
    ) -> Result<Self, NodeRpcError> {
        let host = format!("ws://{remote_socket_address}");

        let rpc_client =
            new_ws_client(host, rpc_auth).await.map_err(NodeRpcError::ClientCreationError)?;

        let client = Self {
            rpc_client: Arc::new(rpc_client),
            chain_config,
        };

        client
            .get_best_block_id()
            .await
            .map_err(|e| NodeRpcError::InitializationError(Box::new(e)))?;

        Ok(client)
    }
}
