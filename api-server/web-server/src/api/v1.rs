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

use crate::{
    api::json_helpers::{amount_to_json, tx_to_json},
    error::{
        ApiServerWebServerClientError, ApiServerWebServerError, ApiServerWebServerNotFoundError,
        ApiServerWebServerServerError,
    },
};
use api_server_common::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageRead,
};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use common::{
    address::Address,
    chain::{Block, Destination, SignedTransaction, Transaction},
    primitives::{Amount, BlockHeight, Id, Idable, H256},
};
use hex::ToHex;
use serde_json::json;
use std::{ops::Sub, str::FromStr, sync::Arc};

use crate::ApiServerWebServerState;

use super::json_helpers::txoutput_to_json;

pub const API_VERSION: &str = "1.0.0";

pub fn routes<T: ApiServerStorage + Send + Sync + 'static>(
) -> Router<ApiServerWebServerState<Arc<T>>> {
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

    let router = router.route("/address/:address", get(address));

    let router = router
        .route("/pool/:id", get(pool))
        .route("/pool/:id/delegations", get(pool_delegations));

    router.route("/delegation/:id", get(delegation))
}

//
// block/
//

async fn get_block(
    block_id: &str,
    state: &ApiServerWebServerState<Arc<impl ApiServerStorage>>,
) -> Result<Block, ApiServerWebServerError> {
    let block_id: Id<Block> = H256::from_str(block_id)
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidBlockId)
        })?
        .into();

    state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_block(block_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::BlockNotFound,
        ))
}

#[allow(clippy::unused_async)]
pub async fn block<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    Ok(Json(json!({
    "header": {
        "previous_block_id": block.prev_block_id(),
    "timestamp": block.timestamp(),
        "merkle_root": block.merkle_root(),
        "witness_merkle_root": block.witness_merkle_root(),
    },
    "body": {
        "reward": block.block_reward()
            .outputs()
            .iter()
            .map(|out| txoutput_to_json(out, &state.chain_config))
            .collect::<Vec<_>>(),
        "transactions": block.transactions()
                            .iter()
                            .map(|tx| tx_to_json(tx.transaction(), &state.chain_config))
                            .collect::<Vec<_>>(),
    },
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_header<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    Ok(Json(json!({
        "previous_block_id": block.prev_block_id(),
        "timestamp": block.timestamp(),
        "merkle_root": block.merkle_root(),
        "witness_merkle_root": block.witness_merkle_root(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_reward<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    Ok(Json(json!(block
        .block_reward()
        .outputs()
        .iter()
        .map(|out| txoutput_to_json(out, &state.chain_config))
        .collect::<Vec<_>>())))
}

#[allow(clippy::unused_async)]
pub async fn block_transaction_ids<T: ApiServerStorage>(
    Path(block_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let block = get_block(&block_id, &state).await?;

    let transaction_ids = block
        .transactions()
        .iter()
        .map(|tx| tx.transaction().get_id())
        .collect::<Vec<_>>();

    Ok(Json(json!(transaction_ids)))
}

//
// chain/
//

#[allow(clippy::unused_async)]
pub async fn chain_genesis<T: ApiServerStorage>(
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let genesis = state.chain_config.genesis_block();

    Ok(Json(json!({
        "block_id": genesis.get_id(),
        "fun_message": genesis.fun_message(),
        "timestamp": genesis.timestamp(),
        "utxos": genesis.utxos()
                 .iter()
                 .map(|out| txoutput_to_json(out, &state.chain_config))
                 .collect::<Vec<_>>(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn chain_at_height<T: ApiServerStorage>(
    Path(block_height): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let block_height = block_height.parse::<BlockHeight>().map_err(|_| {
        ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidBlockHeight)
    })?;

    let block_id = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_main_chain_block_id(block_height)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?;

    match block_id {
        Some(block_id) => Ok(Json(block_id)),
        None => Err(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::NoBlockAtHeight,
        )),
    }
}

#[allow(clippy::unused_async)]
pub async fn chain_tip<T: ApiServerStorage>(
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let best_block = best_block(&state).await?;

    Ok(Json(json!({
      "block_height": best_block.0,
      "block_id": best_block.1,
    })))
}

async fn best_block<T: ApiServerStorage>(
    state: &ApiServerWebServerState<Arc<T>>,
) -> Result<(BlockHeight, Id<common::chain::GenBlock>), ApiServerWebServerError> {
    state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_best_block()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })
}

//
// transaction/
//

async fn get_transaction(
    transaction_id: &str,
    state: &ApiServerWebServerState<Arc<impl ApiServerStorage>>,
) -> Result<(Option<BlockAuxData>, SignedTransaction), ApiServerWebServerError> {
    let transaction_id: Id<Transaction> = H256::from_str(transaction_id)
        .map_err(|_| {
            ApiServerWebServerError::ClientError(
                ApiServerWebServerClientError::InvalidTransactionId,
            )
        })?
        .into();

    state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_transaction_with_block(transaction_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::TransactionNotFound,
        ))
}

#[allow(clippy::unused_async)]
pub async fn transaction<T: ApiServerStorage>(
    Path(transaction_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let (block, transaction) = get_transaction(&transaction_id, &state).await?;

    let confirmations = if let Some(block) = &block {
        let (tip_height, _) = best_block(&state).await?;
        tip_height.sub(block.block_height())
    } else {
        None
    };

    Ok(Json(json!({
    "block_id": block.as_ref().map_or("".to_string(), |b| b.block_id().to_hash().encode_hex::<String>()),
    "timestamp": block.as_ref().map_or("".to_string(), |b| b.block_timestamp().to_string()),
    "confirmations": confirmations.map_or("".to_string(), |c| c.to_string()),
    "version_byte": transaction.version_byte(),
    "is_replaceable": transaction.is_replaceable(),
    "flags": transaction.flags(),
    // TODO: add fee
    "fee": amount_to_json(Amount::ZERO),
    "inputs": transaction.inputs(),
    "outputs": transaction.outputs()
            .iter()
            .map(|out| txoutput_to_json(out, &state.chain_config))
            .collect::<Vec<_>>()
    })))
}

pub async fn transaction_merkle_path<T: ApiServerStorage>(
    Path(transaction_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let (block, transaction) = match get_transaction(&transaction_id, &state).await? {
        (Some(block_data), transaction) => {
            let block = get_block(
                &block_data.block_id().to_hash().encode_hex::<String>(),
                &state,
            )
            .await?;
            (block, transaction.transaction().clone())
        }
        (None, _) => {
            return Err(ApiServerWebServerError::NotFound(
                ApiServerWebServerNotFoundError::TransactionNotPartOfBlock,
            ))
        }
    };

    let transaction_index: u32 = block
        .transactions()
        .iter()
        .position(|t| t.transaction().get_id() == transaction.get_id())
        .ok_or(ApiServerWebServerError::ServerError(
            ApiServerWebServerServerError::CannotFindTransactionInBlock,
        ))?
        .try_into()
        .map_err(|_| {
            ApiServerWebServerError::ServerError(
                ApiServerWebServerServerError::TransactionIndexOverflow,
            )
        })?;

    let merkle_tree = block
        .body()
        .merkle_tree_proxy()
        .map_err(|_| {
            ApiServerWebServerError::ServerError(
                ApiServerWebServerServerError::ErrorCalculatingMerkleTree,
            )
        })?
        .merkle_tree()
        .transaction_inclusion_proof(transaction_index)
        .map_err(|_| {
            ApiServerWebServerError::ServerError(
                ApiServerWebServerServerError::ErrorCalculatingMerklePath,
            )
        })?
        .into_hashes()
        .into_iter()
        .map(|h| h.encode_hex::<String>())
        .collect::<Vec<_>>();

    Ok(Json(json!({
    "block_id": block.get_id(),
    "transaction_index": transaction_index,
    "merkle_root": block.merkle_root().encode_hex::<String>(),
    "merkle_path": merkle_tree,
    })))
}

//
// address/
//

#[allow(clippy::unused_async)]
pub async fn address<T: ApiServerStorage>(
    Path(address): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let address =
        Address::<Destination>::from_str(&state.chain_config, &address).map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidAddress)
        })?;

    let coin_balance = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_address_balance(&address.to_string())
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::AddressNotFound,
        ))?;

    let transaction_history = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_address_transactions(&address.to_string())
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?;

    Ok(Json(json!({
    "coin_balance": coin_balance.into_atoms(),
    "transaction_history": transaction_history
    //TODO "token_balances": destination_summary.token_balances(),
    })))

    // Ok(Json(json!({
    //     "balance": rng.gen_range(1..100_000_000),
    //     "tokens": {
    //         "BTC": rng.gen_range(1..1000),
    //         "ETH": rng.gen_range(1..1000),
    //         "USDT": rng.gen_range(1..1000),
    //         "USDC": rng.gen_range(1..1000),
    //     },
    //     "history": (0..rng.gen_range(1..20)).map(|_| { json!({
    //         "block_id": Id::<Block>::new(H256::random_using(&mut rng)),
    //         "transaction_id": Id::<Transaction>::new(H256::random_using(&mut rng)),
    //     })}).collect::<Vec<_>>(),
    // })))
}

//
// pool/
//

pub async fn pool<T: ApiServerStorage>(
    Path(pool_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let pool_id = Address::from_str(&state.chain_config, &pool_id)
        .and_then(|address| address.decode_object(&state.chain_config))
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidPoolId)
        })?;

    let pool_data = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_pool_data(pool_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::PoolNotFound,
        ))?;

    let decommission_destination =
        Address::new(&state.chain_config, pool_data.decommission_destination())
            .expect("no error in encoding");
    Ok(Json(json!({
        "decommission_destination": decommission_destination.get(),
        "balance": pool_data.pledge_amount(),
        "margin_ratio_per_thousand": pool_data.margin_ratio_per_thousand(),
        "cost_per_block": pool_data.cost_per_block(),
        "vrf_public_key": pool_data.vrf_public_key(),
    })))
}

pub async fn pool_delegations<T: ApiServerStorage>(
    Path(pool_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let pool_id = Address::from_str(&state.chain_config, &pool_id)
        .and_then(|address| address.decode_object(&state.chain_config))
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidPoolId)
        })?;

    let delegations = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_pool_delegations(pool_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?;

    Ok(Json(
        delegations.into_iter().map(|(delegation_id, delegation)|
            json!({
            "delegation_id": Address::new(&state.chain_config, &delegation_id).expect(
                "no error in encoding"
            ).get(),
            "spend_destination": Address::new(&state.chain_config, delegation.spend_destination()).expect(
                "no error in encoding"
            ).get(),
            "balance": delegation.balance(),
        })
        ).collect::<Vec<_>>(),
    ))
}

pub async fn delegation<T: ApiServerStorage>(
    Path(delegation_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let delegation_id = Address::from_str(&state.chain_config, &delegation_id)
        .and_then(|address| address.decode_object(&state.chain_config))
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidPoolId)
        })?;

    let delegation = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_delegation(delegation_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::DelegationNotFound,
        ))?;

    Ok(Json(json!({
        "spend_destination": Address::new(&state.chain_config, delegation.spend_destination()).expect(
            "no error in encoding"
        ).get(),
        "balance": delegation.balance(),
        "pool_id": Address::new(&state.chain_config, &delegation.pool_id()).expect(
            "no error in encoding"
        ).get(),
    })))
}
