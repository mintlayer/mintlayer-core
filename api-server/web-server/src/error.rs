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

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerError {
    #[error("Client error: {0}")]
    ClientError(#[from] ApiServerWebServerClientError),
    #[error("Server error: {0}")]
    ServerError(#[from] ApiServerWebServerServerError),
}

#[allow(dead_code)]
#[derive(Debug, Error, Serialize)]
pub enum ApiServerWebServerClientError {
    #[error("Bad request")]
    BadRequest,
    #[error("Block not found")]
    BlockNotFound,
    #[error("Invalid block height")]
    InvalidBlockHeight,
    #[error("Invalid block Id")]
    InvalidBlockId,
    #[error("Invalid transaction Id")]
    InvalidTransactionId,
    #[error("No block found at supplied height")]
    NoBlockAtHeight,
    #[error("Transaction not found")]
    TransactionNotFound,
    #[error("Transaction not part of any block")]
    TransactionNotPartOfBlock,
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
}

impl IntoResponse for ApiServerWebServerError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiServerWebServerError::ClientError(error) => {
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            ApiServerWebServerError::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
