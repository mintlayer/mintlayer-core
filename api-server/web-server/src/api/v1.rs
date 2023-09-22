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

use api_server_common::storage::storage_api::{ApiServerStorage, ApiServerStorageRead};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use common::{
    chain::{Block, Transaction, TxOutput},
    primitives::{BlockHeight, Id, Idable, H256},
};
use crypto::random::{make_true_rng, Rng};
use serde_json::json;
use std::{str::FromStr, sync::Arc};
use web_server::{
    error::{
        APIServerWebServerClientError, APIServerWebServerError, APIServerWebServerServerError,
    },
    APIServerWebServerState,
};

pub const API_VERSION: &str = "1.0.0";

pub fn routes<T: ApiServerStorage + Send + Sync + 'static>(
) -> Router<APIServerWebServerState<Arc<T>>> {
    let router = Router::new();

    let router = router
        .route("/chain/genesis", get(chain_genesis))
        .route("/chain/tip", get(chain_tip))
        .route("/chain/:height", get(chain_at_height));

    let router = router
        .route("/block/:id", get(block))
        .route("/block/:id/header", get(block_header))
        .route("/block/:id/reward", get(block_reward))
        .route("/block/:id/transaction-ids", get(block_transaction_ids));

    let router = router
        .route("/transaction/:id", get(transaction))
        .route("/transaction/:id/merkle-path", get(transaction_merkle_path));

    let router = router
        .route(
            "/destination/address/:public_key_hash",
            get(destination_address),
        )
        .route(
            "/destination/public-key/:public_key",
            get(destination_public_key),
        )
        .route(
            "/destination/script-hash/:script_id",
            get(destination_script_hash),
        )
        .route(
            "/destination/multisig/:public_key",
            get(destination_multisig),
        );

    router.route("/pool/:id", get(pool))
}

//
// block/
//

#[allow(clippy::unused_async)]
pub async fn block<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = {
        let block_id: Id<Block> = H256::from_str(&block_id)
            .map_err(|_| {
                APIServerWebServerError::ClientError(APIServerWebServerClientError::BadRequest)
            })?
            .into();

        state
            .db
            .transaction_ro()
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
            .get_block(block_id)
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
    };

    match block {
        Some(block) => {
            //: TODO expand this with a usable JSON response
            let transactions: Vec<Transaction> = vec![];

            Ok(Json(json!({
            "previous_block_id": block.prev_block_id(),
            "timestamp": block.timestamp(),
            "merkle_root": block.merkle_root(),
            "transactions": transactions,
            })))
        }
        None => Err(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BadRequest,
        )),
    }
}

#[allow(clippy::unused_async)]
pub async fn block_header<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = {
        let block_id: Id<Block> = H256::from_str(&block_id)
            .map_err(|_| {
                APIServerWebServerError::ClientError(APIServerWebServerClientError::BadRequest)
            })?
            .into();

        state
            .db
            .transaction_ro()
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
            .get_block(block_id)
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
    };

    match block {
        Some(block) => Ok(Json(json!({
            "previous_block_id": block.prev_block_id(),
            "timestamp": block.timestamp(),
            "merkle_root": block.merkle_root(),
        }))),
        None => Err(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BadRequest,
        )),
    }
}

#[allow(clippy::unused_async)]
pub async fn block_reward<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = {
        let block_id: Id<Block> = H256::from_str(&block_id)
            .map_err(|_| {
                APIServerWebServerError::ClientError(APIServerWebServerClientError::BadRequest)
            })?
            .into();

        state
            .db
            .transaction_ro()
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
            .get_block(block_id)
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
    };

    match block {
        Some(_block) => Ok(Json(json!({
            // TODO: expand this with a usable JSON response
        }))),
        None => Err(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BadRequest,
        )),
    }
}

#[allow(clippy::unused_async)]
pub async fn block_transaction_ids<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = {
        let block_id: Id<Block> = H256::from_str(&block_id)
            .map_err(|_| {
                APIServerWebServerError::ClientError(APIServerWebServerClientError::BadRequest)
            })?
            .into();

        state
            .db
            .transaction_ro()
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
            .get_block(block_id)
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
    };

    match block {
        Some(block) => {
            let transaction_ids = block
                .transactions()
                .iter()
                .map(|tx| tx.transaction().get_id())
                .collect::<Vec<_>>();

            Ok(Json(json!({
                "transaction_ids": transaction_ids,
            })))
        }
        None => Err(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BadRequest,
        )),
    }
}

//
// chain/
//

#[allow(clippy::unused_async)]
pub async fn chain_genesis<T: ApiServerStorage>(
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let genesis = state.chain_config.genesis_block();

    // TODO: expand this with a usable JSON response
    let utxos: Vec<TxOutput> = vec![];

    Ok(Json(json!({
        "block_id": genesis.get_id(),
        "fun_message": genesis.fun_message(),
        "timestamp": genesis.timestamp(),
        "utxos": utxos,
    })))
}

#[allow(clippy::unused_async)]
pub async fn chain_at_height<T: ApiServerStorage>(
    Path(block_height): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block_height = block_height.parse::<BlockHeight>().map_err(|_| {
        APIServerWebServerError::ClientError(APIServerWebServerClientError::BadRequest)
    })?;

    let block_id = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?
        .get_main_chain_block_id(block_height)
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?;

    match block_id {
        Some(block_id) => Ok(Json(block_id)),
        None => Err(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BadRequest,
        )),
    }
}

#[allow(clippy::unused_async)]
pub async fn chain_tip<T: ApiServerStorage>(
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let best_block = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?
        .get_best_block()
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?;

    Ok(Json(json!({
      "block_height": best_block.0,
      "block_id": best_block.1,
    })))
}

//
// transaction/
//

#[allow(clippy::unused_async)]
pub async fn transaction<T: ApiServerStorage>(
    Path(transaction_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let transaction = {
        let transaction_id: Id<Transaction> = H256::from_str(&transaction_id)
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
            .into();

        state
            .db
            .transaction_ro()
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
            .get_transaction(transaction_id)
            .await
            .map_err(|_| {
                APIServerWebServerError::ServerError(
                    APIServerWebServerServerError::InternalServerError,
                )
            })?
    };

    match transaction {
        Some((block_id, transaction)) => {
            let transaction = transaction.transaction();

            Ok(Json(json!({
            "block_id": if let Some(block_id) = block_id { block_id.to_string() } else { "".into() },
            "version_byte": transaction.version_byte(),
            "is_replaceable": transaction.is_replaceable(),
            "flags": transaction.flags(),
            "inputs": transaction.inputs(),
            "outputs": transaction.outputs(),
                })))
        }
        None => Err(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BadRequest,
        )),
    }
}

#[allow(clippy::unused_async)]
pub async fn transaction_merkle_path(
    Path(_transaction_id): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!([(0..rng.gen_range(1..10))
        .map(|_| H256::random_using(&mut rng))
        .collect::<Vec<_>>()])))
}

//
// destination/
//

#[allow(clippy::unused_async)]
pub async fn destination_address(
    Path(_public_key_hash): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "balance": rng.gen_range(1..100_000_000),
        "tokens": {
            "BTC": rng.gen_range(1..1000),
            "ETH": rng.gen_range(1..1000),
            "USDT": rng.gen_range(1..1000),
            "USDC": rng.gen_range(1..1000),
        },
        "history": (0..rng.gen_range(1..20)).map(|_| { json!({
            "block_id": Id::<Block>::new(H256::random_using(&mut rng)),
            "transaction_id": Id::<Transaction>::new(H256::random_using(&mut rng)),
        })}).collect::<Vec<_>>(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn destination_multisig(
    Path(_public_key): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "balance": rng.gen_range(1..100_000_000),
        "tokens": {
            "BTC": rng.gen_range(1..1000),
            "ETH": rng.gen_range(1..1000),
            "USDT": rng.gen_range(1..1000),
            "USDC": rng.gen_range(1..1000),
        },
        "history": (0..rng.gen_range(1..20)).map(|_| { json!({
            "block_id": Id::<Block>::new(H256::random_using(&mut rng)),
            "transaction_id": Id::<Transaction>::new(H256::random_using(&mut rng)),
        })}).collect::<Vec<_>>(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn destination_public_key(
    Path(_public_key): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "balance": rng.gen_range(1..100_000_000),
        "tokens": {
            "BTC": rng.gen_range(1..1000),
            "ETH": rng.gen_range(1..1000),
            "USDT": rng.gen_range(1..1000),
            "USDC": rng.gen_range(1..1000),
        },
        "history": (0..rng.gen_range(1..20)).map(|_| { json!({
            "block_id": Id::<Block>::new(H256::random_using(&mut rng)),
            "transaction_id": Id::<Transaction>::new(H256::random_using(&mut rng)),
        })}).collect::<Vec<_>>(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn destination_script_hash(
    Path(_script_hash): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "balance": rng.gen_range(1..100_000_000),
        "tokens": {
            "BTC": rng.gen_range(1..1000),
            "ETH": rng.gen_range(1..1000),
            "USDT": rng.gen_range(1..1000),
            "USDC": rng.gen_range(1..1000),
        },
        "history": (0..rng.gen_range(1..20)).map(|_| { json!({
            "block_id": Id::<Block>::new(H256::random_using(&mut rng)),
            "transaction_id": Id::<Transaction>::new(H256::random_using(&mut rng)),
        })}).collect::<Vec<_>>(),
    })))
}

//
// pool/
//

#[allow(clippy::unused_async)]
pub async fn pool(
    Path(_pool_id): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "decommission_destination": H256::random_using(&mut rng),
        "pledged": rng.gen_range(1..100_000_000),
        "balance": rng.gen_range(1..100_000_000),
        "delegates": [
            (0..rng.gen_range(1..20)).map(|_| { json!({
                "destination": H256::random_using(&mut rng),
                "pledged": rng.gen_range(1..100_000_000),
            })}).collect::<Vec<_>>(),
        ],
        "history": (0..rng.gen_range(1..20)).map(|_| {
            H256::random_using(&mut rng)
        }).collect::<Vec<_>>(),
    })))
}
