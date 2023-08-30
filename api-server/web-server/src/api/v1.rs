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

use web_server::{error::APIServerWebServerError, APIServerWebServerState};
use axum::{extract::Path, response::IntoResponse, routing::get, Json, Router};
use common::{
    chain::{Block, Genesis, Transaction},
    primitives::{BlockHeight, Id, H256},
};
use crypto::random::{make_true_rng, Rng};
use serde_json::json;

pub const API_VERSION: &str = "1.0.0";

pub fn routes() -> Router<APIServerWebServerState> {
    let mut router = Router::new();

    router = router
        .route("/chain/genesis", get(chain_genesis))
        .route("/chain/tip", get(chain_tip))
        .route("/chain/:height", get(chain_at_height));

    router = router
        .route("/block/:id", get(block))
        .route("/block/:id/header", get(block_header))
        .route("/block/:id/reward", get(block_reward))
        .route("/block/:id/transaction-ids", get(block_transaction_ids));

    router = router
        .route("/transaction/:id", get(transaction))
        .route("/transaction/:id/merkle-path", get(transaction_merkle_path));

    router = router
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

    router = router.route("/pool/:id", get(pool));

    router
}

//
// block/
//

#[allow(clippy::unused_async)]
pub async fn block(
    Path(_block_id): Path<Id<String>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "previous_block_id": Id::<Block>::new(H256::random_using(&mut rng)),
        "height": BlockHeight::from(rng.gen_range(1..1_000_000)),
        "timestamp": rng.gen_range(1..1_000_000_000),
        "merkle_root": H256::random_using(&mut rng),
        "reward": (0..rng.gen_range(1..5)).map(|_| { json!({
                "destination": H256::random_using(&mut rng),
                "amount": rng.gen_range(1..100_000_000),
            })
        }).collect::<Vec<_>>(),
        "transaction_ids": (0..rng.gen_range(1..100)).map(|_| {
            Id::<Transaction>::new(H256::random_using(&mut rng)
        )}).collect::<Vec<_>>(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_header(
    Path(_block_id): Path<Id<String>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "previous_block_id": Id::<Block>::new(H256::random_using(&mut rng)),
        "height": BlockHeight::from(rng.gen_range(1..1_000_000)),
        "timestamp": rng.gen_range(1..1_000_000_000),
        "merkle_root": H256::random_using(&mut rng),
    })))
}

#[allow(clippy::unused_async)]
pub async fn block_reward(
    Path(_block_id): Path<Id<String>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!([(0..rng.gen_range(1..5))
        .map(|_| {
            json!({
                "destination": H256::random_using(&mut rng),
                "amount": rng.gen_range(1..100_000_000),
            })
        })
        .collect::<Vec<_>>()])))
}

#[allow(clippy::unused_async)]
pub async fn block_transaction_ids(
    Path(_block_id): Path<Id<String>>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!([(0..rng.gen_range(1..100))
        .map(|_| Id::<Transaction>::new(H256::random_using(&mut rng)))
        .collect::<Vec<_>>()])))
}

//
// chain/
//

#[allow(clippy::unused_async)]
pub async fn chain_genesis() -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "block_id": Id::<Genesis>::new(H256::random_using(&mut rng)),
        "merkle_root": H256::random_using(&mut rng),
        "transaction_ids": (0..rng.gen_range(1..100)).map(|_| {
            Id::<Transaction>::new(H256::random_using(&mut rng)
        )}).collect::<Vec<_>>(),
    })))
}

#[allow(clippy::unused_async)]
pub async fn chain_at_height(
    Path(_block_height): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!(Id::<Block>::new(H256::random_using(&mut rng)))))
}

#[allow(clippy::unused_async)]
pub async fn chain_tip() -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "block_id": Id::<Block>::new(H256::random_using(&mut rng)),
        "block_height": BlockHeight::from(rng.gen_range(1..1_000_000)),
    })))
}

//
// transaction/
//

#[allow(clippy::unused_async)]
pub async fn transaction(
    Path(_transaction_id): Path<String>,
) -> Result<impl IntoResponse, APIServerWebServerError> {
    // TODO replace mock with database calls

    let mut rng = make_true_rng();

    Ok(Json(json!({
        "timestamp": rng.gen_range(1..1_000_000_000),
        "inputs":  (0..rng.gen_range(1..20)).map(|_| { json!({
            "transaction_id": Id::<Transaction>::new(H256::random_using(&mut rng)),
            "index": rng.gen_range(1..100),
        })}).collect::<Vec<_>>(),
        "outputs": (0..rng.gen_range(1..20)).map(|_| { json!({
            "destination": H256::random_using(&mut rng),
            "amount": rng.gen_range(1..100_000_000),
        })}).collect::<Vec<_>>(),
    })))
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
pub async fn pool(Path(_pool_id): Path<String>) -> Result<impl IntoResponse, APIServerWebServerError> {
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
