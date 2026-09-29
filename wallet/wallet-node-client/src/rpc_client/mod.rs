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
use rpc::{ClientError, ClientErrorExt as _, RpcAuthData, RpcWsClient, new_ws_client};

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

impl NodeRpcError {
    /// Returns `true` if the error is caused by a connection-level problem between this client
    /// and the node, i.e. the connection is broken or cannot be established, as opposed to an
    /// application-level error reported by the node.
    ///
    /// Such errors are recoverable by dropping the client and establishing a new connection.
    ///
    /// Caution: connection-level does not mean that the failed request was not processed. A
    /// timeout or a lost response in particular leaves the outcome of the request unknown, so
    /// callers retrying non-idempotent node calls must account for that instead of blindly
    /// resending. (The scanner's sync and the mempool subscription are both idempotent: they
    /// resume from local state.)
    pub fn is_connection_error(&self) -> bool {
        match self {
            // The client could not be created or the call did not reach the node (or its
            // response was lost) because of a broken connection.
            NodeRpcError::ClientCreationError(err) | NodeRpcError::ResponseError(err) => {
                err.is_connection_error()
            }
            // The initial connection check failed; the cause is either a connection problem or
            // an application-level error, both classified by the wrapped error.
            NodeRpcError::InitializationError(err) => err.is_connection_error(),
            NodeRpcError::DecodingError(_)
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

    /// Direct access to the underlying WebSocket RPC client, e.g. for subscriptions.
    pub fn ws_client(&self) -> &rpc::RpcWsClient {
        &self.rpc_client
    }
}

#[cfg(test)]
mod connection_error_tests {
    use super::*;
    use jsonrpsee::types::ErrorObjectOwned;

    /// The "background task closed ...; restart required" error reported by a WS client whose
    /// connection was closed by the node; this is the error seen by the scanner in production
    /// when the node drops the WebSocket connection.
    fn background_task_closed_error() -> ClientError {
        ClientError::RestartNeeded(Arc::new(ClientError::Transport(
            "Connection was closed".into(),
        )))
    }

    #[test]
    fn broken_connection_is_a_connection_error() {
        assert!(NodeRpcError::ResponseError(background_task_closed_error()).is_connection_error());
        assert!(
            NodeRpcError::ResponseError(ClientError::Transport("connection reset by peer".into()))
                .is_connection_error()
        );
        assert!(NodeRpcError::ResponseError(ClientError::RequestTimeout).is_connection_error());

        // A client that cannot be created at all (e.g. the node is simply down) is also a
        // connection-level failure.
        assert!(
            NodeRpcError::ClientCreationError(ClientError::Transport("Connection refused".into()))
                .is_connection_error()
        );

        // The initial connection check wraps the cause; the classification is inherited.
        assert!(
            NodeRpcError::InitializationError(Box::new(NodeRpcError::ResponseError(
                background_task_closed_error()
            )))
            .is_connection_error()
        );
    }

    #[test]
    fn node_reported_errors_are_not_connection_errors() {
        // A definitive application-level answer from the node must not trigger a reconnection.
        let call_error = ClientError::Call(ErrorObjectOwned::owned(
            jsonrpsee::types::error::CALL_EXECUTION_FAILED_CODE,
            "No such block",
            None::<serde_json::Value>,
        ));
        assert!(!NodeRpcError::ResponseError(call_error).is_connection_error());

        assert!(
            !NodeRpcError::DecodingError(serialization::hex::HexError::ScaleDecodeError(
                "decoding failed".into()
            ))
            .is_connection_error()
        );
    }
}
