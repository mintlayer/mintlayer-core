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

use crate::error::{
    APIServerWebServerClientError, APIServerWebServerError, APIServerWebServerServerError,
};
use api_server_common::storage::storage_api::{ApiServerStorage, ApiServerStorageRead};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use common::{
    chain::{Block, SignedTransaction, Transaction, TxOutput},
    primitives::{BlockHeight, Id, Idable, H256},
};
use crypto::random::{make_true_rng, Rng};
use hex::ToHex;
use serde_json::json;
use std::{str::FromStr, sync::Arc};

use crate::APIServerWebServerState;

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

async fn get_block(
    block_id: &str,
    state: &APIServerWebServerState<Arc<impl ApiServerStorage>>,
) -> Result<Block, APIServerWebServerError> {
    let block_id: Id<Block> = H256::from_str(block_id)
        .map_err(|_| {
            APIServerWebServerError::ClientError(APIServerWebServerClientError::InvalidBlockId)
        })?
        .into();

    state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?
        .get_block(block_id)
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?
        .ok_or(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::BlockNotFound,
        ))
}

#[allow(clippy::unused_async)]
pub async fn block<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    Ok(Json(json!({
    "previous_block_id": block.prev_block_id(),
    "timestamp": block.timestamp(),
    "merkle_root": block.merkle_root(),
    "transactions": block.transactions(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_header<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    Ok(Json(json!({
        "previous_block_id": block.prev_block_id(),
        "timestamp": block.timestamp(),
        "merkle_root": block.merkle_root(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_reward<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let _block = get_block(&block_id, &state).await?;

    Ok(Json(json!({
        // TODO: expand this with a usable JSON response
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_transaction_ids<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    let transaction_ids = block
        .transactions()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "transaction_ids": transaction_ids,
    })))
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
        APIServerWebServerError::ClientError(APIServerWebServerClientError::InvalidBlockHeight)
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
            APIServerWebServerClientError::NoBlockAtHeight,
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

async fn get_transaction(
    transaction_id: &str,
    state: &APIServerWebServerState<Arc<impl ApiServerStorage>>,
) -> Result<(Option<Id<Block>>, SignedTransaction), APIServerWebServerError> {
    let transaction_id: Id<Transaction> = H256::from_str(transaction_id)
        .map_err(|_| {
            APIServerWebServerError::ClientError(
                APIServerWebServerClientError::InvalidTransactionId,
            )
        })?
        .into();

    state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?
        .get_transaction(transaction_id)
        .await
        .map_err(|_| {
            APIServerWebServerError::ServerError(APIServerWebServerServerError::InternalServerError)
        })?
        .ok_or(APIServerWebServerError::ClientError(
            APIServerWebServerClientError::TransactionNotFound,
        ))
}

#[allow(clippy::unused_async)]
pub async fn transaction<T: ApiServerStorage>(
    Path(transaction_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let (block_id, transaction) = get_transaction(&transaction_id, &state).await?;

    Ok(Json(json!({
    "block_id": block_id.map_or("".to_string(), |b| b.to_hash().encode_hex::<String>()),
    "version_byte": transaction.version_byte(),
    "is_replaceable": transaction.is_replaceable(),
    "flags": transaction.flags(),
    "inputs": transaction.inputs(),
    "outputs": transaction.outputs(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn transaction_merkle_path<T: ApiServerStorage>(
    Path(transaction_id): Path<String>,
    State(state): State<APIServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    let (block, transaction) = match get_transaction(&transaction_id, &state).await? {
        (Some(block_id), transaction) => {
            let block = get_block(&block_id.to_hash().encode_hex::<String>(), &state).await?;
            (block, transaction.transaction().clone())
        }
        (None, _) => {
            return Err(APIServerWebServerError::ClientError(
                APIServerWebServerClientError::TransactionNotPartOfBlock,
            ))
        }
    };

    let transaction_index: u32 = block
        .transactions()
        .iter()
        .position(|t| t.transaction().get_id() == transaction.get_id())
        .ok_or(APIServerWebServerError::ServerError(
            APIServerWebServerServerError::CannotFindTransactionInBlock,
        ))?
        .try_into()
        .map_err(|_| {
            APIServerWebServerError::ServerError(
                APIServerWebServerServerError::TransactionIndexOverflow,
            )
        })?;

    let merkle_tree = block
        .body()
        .merkle_tree_proxy()
        .map_err(|_| {
            APIServerWebServerError::ServerError(
                APIServerWebServerServerError::ErrorCalculatingMerkleTree,
            )
        })?
        .merkle_tree()
        .transaction_inclusion_proof(transaction_index)
        .map_err(|_| {
            APIServerWebServerError::ServerError(
                APIServerWebServerServerError::ErrorCalculatingMerklePath,
            )
        })?
        .into_hashes()
        .into_iter()
        .map(|h| h.encode_hex::<String>())
        .collect::<Vec<_>>();

    Ok(Json(json!({
    "block_id": block.get_id(),
    "merkle_root": block.merkle_root().encode_hex::<String>(),
    "transaction_index": transaction_index,
    "merkle_path": merkle_tree,
    })))
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
