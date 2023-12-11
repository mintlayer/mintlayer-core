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
        ApiServerWebServerClientError, ApiServerWebServerError, ApiServerWebServerForbiddenError,
        ApiServerWebServerNotFoundError, ApiServerWebServerServerError,
    },
    TxSubmitClient,
};
use api_server_common::storage::storage_api::{
    block_aux_data::BlockAuxData, ApiServerStorage, ApiServerStorageRead, CoinOrTokenId,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use common::{
    address::Address,
    chain::{tokens::NftIssuance, Block, Destination, SignedTransaction, Transaction},
    primitives::{Amount, BlockHeight, Id, Idable, H256},
};
use hex::ToHex;
use serde_json::json;
use serialization::hex_encoded::HexEncoded;
use std::{collections::BTreeMap, ops::Sub, str::FromStr, sync::Arc};

use crate::ApiServerWebServerState;

use super::json_helpers::txoutput_to_json;

pub const API_VERSION: &str = "1.0.0";

const TX_BODY_LIMIT: usize = 10240;

pub fn routes<
    T: ApiServerStorage + Send + Sync + 'static,
    R: TxSubmitClient + Send + Sync + 'static,
>(
    enable_post_routes: bool,
) -> Router<ApiServerWebServerState<Arc<T>, Option<Arc<R>>>> {
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

    let router = if enable_post_routes {
        router.route(
            "/transaction",
            post(submit_transaction).layer(DefaultBodyLimit::max(TX_BODY_LIMIT)),
        )
    } else {
        router.route("/transaction", post(forbidden_request))
    };

    let router = router
        .route("/transaction/:id", get(transaction))
        .route("/transaction/:id/merkle-path", get(transaction_merkle_path));

    let router = router
        .route("/address/:address", get(address))
        .route("/address/:address/available-utxos", get(address_utxos))
        .route("/address/:address/delegations", get(address_delegations));

    let router = router
        .route("/pool", get(pools))
        .route("/pool/:id", get(pool))
        .route("/pool/:id/delegations", get(pool_delegations));

    let router = router.route("/delegation/:id", get(delegation));

    router.route("/token/:id", get(token)).route("/nft/:id", get(nft))
}

async fn forbidden_request() -> Result<(), ApiServerWebServerError> {
    Err(ApiServerWebServerForbiddenError::Forbidden)?
}

//
// block/
//

async fn get_block(
    block_id: &str,
    state: &ApiServerWebServerState<Arc<impl ApiServerStorage>, Option<Arc<impl TxSubmitClient>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let best_block = best_block(&state).await?;

    Ok(Json(json!({
      "block_height": best_block.0,
      "block_id": best_block.1,
    })))
}

async fn best_block<T: ApiServerStorage>(
    state: &ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>,
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
    state: &ApiServerWebServerState<Arc<impl ApiServerStorage>, Option<Arc<impl TxSubmitClient>>>,
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

pub async fn submit_transaction<T: ApiServerStorage>(
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
    body: String,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let tx = HexEncoded::<SignedTransaction>::from_str(&body)
        .map_err(|_| {
            ApiServerWebServerError::ClientError(
                ApiServerWebServerClientError::InvalidSignedTransaction,
            )
        })?
        .take();

    state
        .rpc
        .expect("must be present if route is enabled")
        .submit_tx(tx)
        .await
        .map_err(|e| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::RpcError(
                e.to_string(),
            ))
        })?;

    Ok(())
}

pub async fn transaction<T: ApiServerStorage>(
    Path(transaction_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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

pub async fn address<T: ApiServerStorage>(
    Path(address): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
        .get_address_balance(&address.to_string(), CoinOrTokenId::Coin)
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

pub async fn address_utxos<T: ApiServerStorage>(
    Path(address): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let address =
        Address::<Destination>::from_str(&state.chain_config, &address).map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidAddress)
        })?;

    let utxos = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_address_available_utxos(&address.to_string())
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?;

    Ok(Json(
        utxos
            .into_iter()
            .map(|utxo| {
                json!({
                "outpoint": utxo.0,
                "utxo": txoutput_to_json(&utxo.1, &state.chain_config)})
            })
            .collect::<Vec<_>>(),
    ))
}

pub async fn address_delegations<T: ApiServerStorage>(
    Path(address): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let address =
        Address::<Destination>::from_str(&state.chain_config, &address).map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidAddress)
        })?;

    let delegations = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_delegations_from_address(
            &address.decode_object(&state.chain_config).expect("already checked"),
        )
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
            "next_nonce": delegation.next_nonce(),
            "spend_destination": Address::new(&state.chain_config, delegation.spend_destination()).expect(
                "no error in encoding"
            ).get(),
            "balance": delegation.balance(),
        })
        ).collect::<Vec<_>>(),
    ))
}

//
// pool/
//

enum PoolSorting {
    ByHeight,
    ByPledge,
}

impl FromStr for PoolSorting {
    type Err = ApiServerWebServerClientError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "by_height" => Ok(Self::ByHeight),
            "by_pledge" => Ok(Self::ByPledge),
            _ => Err(ApiServerWebServerClientError::InvalidPoolsSortOrder),
        }
    }
}

pub async fn pools<T: ApiServerStorage>(
    Query(params): Query<BTreeMap<String, String>>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    const OFFSET: &str = "offset";
    const ITEMS: &str = "items";
    const DEFAULT_NUM_ITEMS: u32 = 10;
    const SORT: &str = "sort";

    let offset = params
        .get(OFFSET)
        .map(|offset| u32::from_str(offset))
        .transpose()
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidOffset)
        })?
        .unwrap_or_default();

    let items = params
        .get(ITEMS)
        .map(|items| u32::from_str(items))
        .transpose()
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidNumItems)
        })?
        .unwrap_or(DEFAULT_NUM_ITEMS);

    let sort = params
        .get(SORT)
        .map(|offset| PoolSorting::from_str(offset))
        .transpose()?
        .unwrap_or(PoolSorting::ByHeight);

    let db_tx = state.db.transaction_ro().await.map_err(|_| {
        ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
    })?;

    let pools = match sort {
        PoolSorting::ByHeight => db_tx.get_latest_pool_data(items, offset).await.map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?,
        PoolSorting::ByPledge => {
            db_tx.get_pool_data_with_largest_pledge(items, offset).await.map_err(|_| {
                ApiServerWebServerError::ServerError(
                    ApiServerWebServerServerError::InternalServerError,
                )
            })?
        }
    };

    let pools = pools.into_iter().map(|(pool_id, pool_data)| {
        let decommission_destination =
            Address::new(&state.chain_config, pool_data.decommission_destination())
                .expect("no error in encoding");
        let pool_id = Address::new(&state.chain_config, &pool_id).expect("no error in encoding");
        json!({
            "pool_id": pool_id.get(),
            "decommission_destination": decommission_destination.get(),
            "pledge": pool_data.pledge_amount(),
            "margin_ratio_per_thousand": pool_data.margin_ratio_per_thousand(),
            "cost_per_block": pool_data.cost_per_block(),
            "vrf_public_key": pool_data.vrf_public_key(),
        })
    });

    Ok(Json(pools.collect::<Vec<_>>()))
}

pub async fn pool<T: ApiServerStorage>(
    Path(pool_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
        "pledge": pool_data.pledge_amount(),
        "margin_ratio_per_thousand": pool_data.margin_ratio_per_thousand(),
        "cost_per_block": pool_data.cost_per_block(),
        "vrf_public_key": pool_data.vrf_public_key(),
    })))
}

pub async fn pool_delegations<T: ApiServerStorage>(
    Path(pool_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
            "next_nonce": delegation.next_nonce(),
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
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
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
        "next_nonce": delegation.next_nonce(),
        "pool_id": Address::new(&state.chain_config, &delegation.pool_id()).expect(
            "no error in encoding"
        ).get(),
    })))
}

pub async fn token<T: ApiServerStorage>(
    Path(token_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let token_id = Address::from_str(&state.chain_config, &token_id)
        .and_then(|address| address.decode_object(&state.chain_config))
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidPoolId)
        })?;

    let token = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_fungible_token_issuance(token_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::TokenNotFound,
        ))?;

    Ok(Json(json!({
        "authority": Address::new(&state.chain_config, &token.authority).expect(
            "no error in encoding"
        ).get(),
        "is_locked": token.is_locked,
        "circulating_supply": amount_to_json(token.circulating_supply),
        "metadata_uri": token.metadata_uri,
        "number_of_decimals": token.number_of_decimals,
        "total_supply": token.total_supply,
        "frozen": token.frozen,
    })))
}

pub async fn nft<T: ApiServerStorage>(
    Path(nft_id): Path<String>,
    State(state): State<ApiServerWebServerState<Arc<T>, Option<Arc<impl TxSubmitClient>>>>,
) -> Result<impl IntoResponse, ApiServerWebServerError> {
    let nft_id = Address::from_str(&state.chain_config, &nft_id)
        .and_then(|address| address.decode_object(&state.chain_config))
        .map_err(|_| {
            ApiServerWebServerError::ClientError(ApiServerWebServerClientError::InvalidPoolId)
        })?;

    let nft = state
        .db
        .transaction_ro()
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .get_nft_token_issuance(nft_id)
        .await
        .map_err(|_| {
            ApiServerWebServerError::ServerError(ApiServerWebServerServerError::InternalServerError)
        })?
        .ok_or(ApiServerWebServerError::NotFound(
            ApiServerWebServerNotFoundError::NftNotFound,
        ))?;

    match nft {
        NftIssuance::V0(nft) => Ok(Json(json!({
            "authority": nft.metadata.creator
                .map(|creator| Address::new(&state.chain_config, &Destination::PublicKey(creator.public_key))
                .expect("no error in encoding")
                .get().to_owned()
            ),
            "name": nft.metadata.name,
            "description": nft.metadata.description,
            "ticker": nft.metadata.ticker,
            "icon_uri": nft.metadata.icon_uri,
            "additional_metadata_uri": nft.metadata.additional_metadata_uri,
            "media_uri": nft.metadata.media_uri,
            "media_hash": nft.metadata.media_hash,
        }))),
    }
}
