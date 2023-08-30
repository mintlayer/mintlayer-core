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

use api_server_daemon::{error::APIServerDaemonClientError, APIServerDaemonError, APIServerState};
use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use clap::Parser;
use config::ApiServerDaemonConfig;
use logging::{init_logging, log::info};
use serde_json::json;

#[tokio::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    init_logging::<&std::path::Path>(None);

    let args = ApiServerDaemonConfig::parse();
    info!("Command line options: {args:?}");

    let state = APIServerState {
        example_shared_value: "test value".to_string(),
    };

    let routes = Router::new()
        .route("/", get(server_status))
        .nest("/api/v1", api::v1::routes())
        .fallback(bad_request)
        .with_state(state);

    axum::Server::bind(&args.address.unwrap_or_default())
        .serve(routes.into_make_service())
        .await
        .expect("API Server Daemon failed")
}

#[allow(clippy::unused_async)]
async fn server_status(
    State(_state): State<APIServerState>,
) -> Result<impl IntoResponse, APIServerDaemonError> {
    Ok(Json(json!({
        "versions": [api::v1::API_VERSION]
        //"network": "testnet",
    })))
}

#[allow(clippy::unused_async)]
pub async fn bad_request() -> Result<(), APIServerDaemonError> {
    Err(APIServerDaemonClientError::BadRequest)?
}
