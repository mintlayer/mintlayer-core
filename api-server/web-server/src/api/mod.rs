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

pub mod v1;

use crate::{
    api,
    error::{APIServerWebServerClientError, APIServerWebServerError},
    APIServerWebServerState,
};

use api_server_common::storage::storage_api::ApiServerStorage;
use axum::{
    response::IntoResponse,
    routing::{get, IntoMakeService},
    Json, Router, Server,
};
use serde_json::json;
use std::{net::TcpListener, sync::Arc};

#[allow(clippy::unused_async)]
async fn bad_request() -> Result<(), APIServerWebServerError> {
    Err(APIServerWebServerClientError::BadRequest)?
}

#[allow(clippy::unused_async)]
async fn server_status() -> Result<impl IntoResponse, APIServerWebServerError> {
    Ok(Json(json!({
        "versions": [api::v1::API_VERSION]
        //"network": "testnet",
    })))
}

#[allow(dead_code)]
pub fn web_server<T: ApiServerStorage + Send + Sync + 'static>(
    socket: TcpListener,
    state: APIServerWebServerState<Arc<T>>,
) -> Server<hyper::server::conn::AddrIncoming, IntoMakeService<Router>> {
    let routes = Router::new()
        .route("/", get(server_status))
        .nest("/api/v1", api::v1::routes())
        .fallback(bad_request)
        .with_state(state);

    axum::Server::from_tcp(socket).unwrap().serve(routes.into_make_service())
}
