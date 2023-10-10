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

use api_server_common::storage::impls::postgres::TransactionalApiServerPostgresStorage;
use api_web_server::{api::web_server, config::ApiServerWebServerConfig, ApiServerWebServerState};
use clap::Parser;
use common::chain::config::create_unit_test_config;
use logging::log;
use std::sync::Arc;

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

    let storage = TransactionalApiServerPostgresStorage::new(
        &args.postgres_config.postgres_host,
        args.postgres_config.postgres_port,
        &args.postgres_config.postgres_user,
        args.postgres_config.postgres_password.as_deref(),
        args.postgres_config.postgres_database.as_deref(),
        args.postgres_config.postgres_max_connections,
        &chain_config,
    )
    .await
    .unwrap_or_else(|e| {
        log::error!("Error creating Postgres storage: {}", e);
        std::process::exit(1);
    });

    let state = ApiServerWebServerState {
        db: Arc::new(storage),
        chain_config,
    };

    web_server(args.address.unwrap_or_default().tcp_listener(), state)
        .await
        .expect("API Server Web Server failed");
}
