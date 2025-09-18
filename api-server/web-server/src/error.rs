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

use api_server_common::storage::storage_api::ApiServerStorageError;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

#[derive(thiserror::Error, Debug)]
pub enum ApiServerWebServerInitError {
    #[error("RPC error: {0}")]
    RpcError(node_comm::rpc_client::NodeRpcError),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Postgres connection error: {0}")]
    PostgresConnectionError(ApiServerStorageError),
}

#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerError {
    #[error("Client error: {0}")]
    ClientError(#[from] ApiServerWebServerClientError),
    #[error("Not found error: {0}")]
    NotFound(#[from] ApiServerWebServerNotFoundError),
    #[error("{0}")]
    Forbidden(#[from] ApiServerWebServerForbiddenError),
    #[error("Server error: {0}")]
    ServerError(#[from] ApiServerWebServerServerError),
}

#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerNotFoundError {
    #[error("Address not found")]
    AddressNotFound,
    #[error("Block not found")]
    BlockNotFound,
    #[error("No block found at supplied height")]
    NoBlockAtHeight,
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Transaction not part of any block")]
    TransactionNotPartOfBlock,
    #[error("Transaction output not found")]
    TransactionOutputNotFound,
    #[error("Stake pool not found")]
    PoolNotFound,
    #[error("Delegation not found")]
    DelegationNotFound,
    #[error("Token not found")]
    TokenNotFound,
    #[error("NFT not found")]
    NftNotFound,
    #[error("Order not found")]
    OrderNotFound,
}

#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerForbiddenError {
    #[error("Forbidden endpoint")]
    Forbidden,
}

#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerClientError {
    #[error("Bad request")]
    BadRequest,
    #[error("Invalid block height")]
    InvalidBlockHeight,
    #[error("Invalid block Id")]
    InvalidBlockId,
    #[error("Invalid address")]
    InvalidAddress,
    #[error("Invalid transaction Id")]
    InvalidTransactionId,
    #[error("Invalid pool Id")]
    InvalidPoolId,
    #[error("Invalid offset")]
    InvalidOffset,
    #[error("Invalid offset mode")]
    InvalidOffsetMode,
    #[error("Invalid number of items")]
    InvalidNumItems,
    #[error("Invalid pools sort order")]
    InvalidPoolsSortOrder,
    #[error("Invalid signed transaction")]
    InvalidSignedTransaction,
    #[error("Invalid token Id")]
    InvalidTokenId,
    #[error("Invalid NFT Id")]
    InvalidNftId,
    #[error("Invalid in top X MB query parameter")]
    InvalidInTopX,
    #[error("Invalid order Id")]
    InvalidOrderId,
    #[error("Invalid order trading pair")]
    InvalidOrderTradingPair,
}

#[allow(dead_code)]
#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerServerError {
    #[error("Cannot find transaction in block")]
    CannotFindTransactionInBlock,
    #[error("Error calculating merkle path")]
    ErrorCalculatingMerklePath,
    #[error("Error calculating merkle tree")]
    ErrorCalculatingMerkleTree,
    #[error("Internal server error")]
    InternalServerError,
    #[error("Transaction index overflowed")]
    TransactionIndexOverflow,
    #[error("RPC error: {0}")]
    RpcError(String),
}

impl IntoResponse for ApiServerWebServerError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiServerWebServerError::ClientError(error) => {
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            ApiServerWebServerError::NotFound(error) => (StatusCode::NOT_FOUND, error.to_string()),
            ApiServerWebServerError::Forbidden(error) => (StatusCode::FORBIDDEN, error.to_string()),
            ApiServerWebServerError::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
