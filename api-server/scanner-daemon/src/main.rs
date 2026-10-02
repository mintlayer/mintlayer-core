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

use std::sync::Arc;

use api_blockchain_scanner_daemon::{ApiServerScannerError, make_postgres_storage, run};
use clap::Parser;
use common::chain::config::ChainType;
use config::ApiServerScannerArgs;
use rpc::RpcAuthData;
use utils::{cookie::COOKIE_FILENAME, default_data_dir::default_data_dir_for_chain};

mod config;

utils::enable_rust_backtrace!();

#[tokio::main]
async fn main() -> Result<(), ApiServerScannerError> {
    let args = ApiServerScannerArgs::parse();

    logging::init_logging();
    logging::log::info!("Command line options: {args:?}");

    let ApiServerScannerArgs {
        network,
        node_rpc_address,
        node_rpc_cookie_file,
        node_rpc_username,
        node_rpc_password,
        postgres_config,
    } = args;

    let chain_type: ChainType = network.into();
    let chain_config = Arc::new(common::chain::config::Builder::new(chain_type).build());

    let node_rpc_auth = match (node_rpc_cookie_file, node_rpc_username, node_rpc_password) {
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
            return Err(ApiServerScannerError::InvalidConfig(
                "Invalid RPC cookie/username/password combination".to_owned(),
            ));
        }
    };

    let default_node_rpc_bind_address = || {
        node_lib::default_rpc_config(&chain_config)
            .bind_address
            .expect("Can't fail")
            .into()
    };

    let node_rpc_address = node_rpc_address.unwrap_or_else(default_node_rpc_bind_address);

    // Note: the node does not have to be reachable at this point; the scanner establishes the
    // connection (and re-establishes it after every connection-level failure) in its
    // supervision loop, see `run`.
    let storage = make_postgres_storage(
        postgres_config.postgres_host,
        postgres_config.postgres_port,
        postgres_config.postgres_user,
        postgres_config.postgres_password,
        postgres_config.postgres_database,
        postgres_config.postgres_max_connections,
        chain_config.clone(),
    )
    .await?;

    run(
        &chain_config,
        node_rpc_address.to_string(),
        node_rpc_auth,
        storage,
    )
    .await?;

    Ok(())
}
