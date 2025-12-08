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

pub mod json_helpers;
pub mod v2;

use std::sync::Arc;

use axum::{http::Method, response::IntoResponse, routing::get, Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::{AllowMethods, Any, CorsLayer};

use api_server_common::storage::storage_api::ApiServerStorage;

use crate::{
    api,
    error::{ApiServerWebServerClientError, ApiServerWebServerError},
    ApiServerWebServerState, TxSubmitClient,
};

#[allow(clippy::unused_async)]
async fn bad_request() -> Result<(), ApiServerWebServerError> {
    Err(ApiServerWebServerClientError::BadRequest)?
}

#[allow(clippy::unused_async)]
async fn server_status() -> Result<impl IntoResponse, ApiServerWebServerError> {
    Ok(Json(json!({
        "versions": [api::v2::API_VERSION]
        //"network": "testnet",
    })))
}

#[allow(dead_code)]
pub fn web_server<
    T: ApiServerStorage + Send + Sync + 'static,
    R: TxSubmitClient + Send + Sync + 'static,
>(
    socket: TcpListener,
    state: ApiServerWebServerState<Arc<T>, Arc<R>>,
    enable_post_endpoints: bool,
) -> axum::serve::Serve<Router, Router> {
    let cors_layer = CorsLayer::new()
        .allow_methods(AllowMethods::list([Method::GET, Method::POST]))
        .allow_headers(Any)
        .allow_origin(Any);

    let routes = Router::new()
        .route("/", get(server_status))
        .nest("/api/v2", api::v2::routes(enable_post_endpoints))
        .fallback(bad_request)
        .with_state(state)
        .layer(cors_layer);

    axum::serve(socket, routes)
}
