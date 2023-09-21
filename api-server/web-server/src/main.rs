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

mod api;
mod config;
mod error;

use api_server_common::storage::impls::in_memory::transactional::TransactionalApiServerInMemoryStorage;
use axum::{response::IntoResponse, routing::get, Json, Router};
use clap::Parser;
use common::chain::config::create_unit_test_config;
use config::ApiServerWebServerConfig;
use logging::log;
use serde_json::json;
use std::sync::Arc;
use web_server::{
    error::APIServerWebServerClientError, APIServerWebServerError, APIServerWebServerState,
};

#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    logging::init_logging();

    let args = ApiServerWebServerConfig::parse();
    log::info!("Command line options: {args:?}");

    // TODO: generalize network configuration
    let chain_config = Arc::new(create_unit_test_config());

    // TODO: point database to PostgreSQL from command line arguments
    let state = APIServerWebServerState {
        db: Arc::new(TransactionalApiServerInMemoryStorage::new(&chain_config)),
        chain_config,
    };

    let routes = Router::new()
        .route("/", get(server_status))
        .nest("/api/v1", api::v1::routes())
        .fallback(bad_request)
        .with_state(state);

    axum::Server::bind(&args.address.unwrap_or_default())
        .serve(routes.into_make_service())
        .await
        .expect("API Server Web Server failed")
}

#[allow(clippy::unused_async)]
async fn server_status() -> Result<impl IntoResponse, APIServerWebServerError> {
    Ok(Json(json!({
        "versions": [api::v1::API_VERSION]
        //"network": "testnet",
    })))
}

#[allow(clippy::unused_async)]
pub async fn bad_request() -> Result<(), APIServerWebServerError> {
    Err(APIServerWebServerClientError::BadRequest)?
}
