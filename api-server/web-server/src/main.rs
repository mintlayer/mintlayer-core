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
use api_web_server::{
    api::web_server, config::ApiServerWebServerConfig, ApiServerWebServerState, CachedValues,
    TxSubmitClient,
};
use clap::Parser;
use common::{
    chain::config::{Builder, ChainType},
    primitives::time::Time,
};
use logging::log;
use node_comm::make_rpc_client;
use node_lib::default_rpc_config;
use rpc::RpcAuthData;
use std::sync::{Arc, RwLock};
use utils::{cookie::COOKIE_FILENAME, default_data_dir::default_data_dir_for_chain};

use crate::error::ApiServerWebServerInitError;

#[tokio::main]
async fn main() -> Result<(), ApiServerWebServerInitError> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    logging::init_logging();

    let args = ApiServerWebServerConfig::parse();
    log::info!("Command line options: {args:?}");

    let chain_type: ChainType = args.network.into();
    let chain_config = Arc::new(Builder::new(chain_type).build());

    let storage = TransactionalApiServerPostgresStorage::new(
        &args.postgres_config.postgres_host,
        args.postgres_config.postgres_port,
        &args.postgres_config.postgres_user,
        args.postgres_config.postgres_password.as_deref(),
        args.postgres_config.postgres_database.as_deref(),
        args.postgres_config.postgres_max_connections,
        chain_config.clone(),
    )
    .await
    .map_err(ApiServerWebServerInitError::PostgresConnectionError)?;

    let rpc_client = {
        let rpc_auth = match (args.rpc_cookie_file, args.rpc_username, args.rpc_password) {
            (None, None, None) => {
                let cookie_file_path =
                    default_data_dir_for_chain(chain_type.name()).join(COOKIE_FILENAME);
                RpcAuthData::Cookie { cookie_file_path }
            }
            (Some(cookie_file_path), None, None) => RpcAuthData::Cookie {
                cookie_file_path: cookie_file_path.into(),
            },
            (None, Some(username), Some(password)) => RpcAuthData::Basic { username, password },
            _ => {
                return Err(ApiServerWebServerInitError::InvalidConfig(
                    "Invalid RPC cookie/username/password combination".to_owned(),
                ))
            }
        };
        let default_rpc_bind_address =
            || default_rpc_config(&chain_config).bind_address.expect("Can't fail").into();

        let rpc_address = args.rpc_address.unwrap_or_else(default_rpc_bind_address);

        make_rpc_client(rpc_address.to_string(), rpc_auth)
            .await
            .map_err(ApiServerWebServerInitError::RpcError)?
    };

    let state = ApiServerWebServerState {
        db: Arc::new(storage),
        chain_config,
        rpc: Arc::new(rpc_client),
        cached_values: Arc::new(CachedValues {
            feerate_points: RwLock::new((Time::from_secs_since_epoch(0), vec![])),
        }),
        time_getter: Default::default(),
    };

    web_server(
        args.address.unwrap_or_default().tcp_listener(),
        state,
        args.enable_post_routes,
    )
    .await
    .expect("API Server Web Server failed");

    Ok(())
}
