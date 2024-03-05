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

use api_blockchain_scanner_lib::blockchain_state::BlockchainState;
use api_server_common::storage::{
    impls::{postgres::TransactionalApiServerPostgresStorage, CURRENT_STORAGE_VERSION},
    storage_api::{
        ApiServerStorage, ApiServerStorageError, ApiServerStorageRead, ApiServerStorageWrite,
        ApiServerTransactionRw,
    },
};
use clap::Parser;
use common::chain::{config::ChainType, ChainConfig};
use config::ApiServerScannerArgs;
use node_comm::{make_rpc_client, rpc_client::NodeRpcClient};
use node_lib::default_rpc_config;
use rpc::RpcAuthData;
use utils::{cookie::COOKIE_FILENAME, default_data_dir::default_data_dir_for_chain};
mod config;

pub async fn make_postgres_storage(
    postgres_host: String,
    postgres_port: u16,
    postgres_user: String,
    postgres_password: Option<String>,
    postgres_database: Option<String>,
    postgres_max_connections: u32,
    chain_config: Arc<ChainConfig>,
) -> Result<TransactionalApiServerPostgresStorage, ApiServerScannerError> {
    TransactionalApiServerPostgresStorage::new(
        &postgres_host,
        postgres_port,
        &postgres_user,
        postgres_password.as_deref(),
        postgres_database.as_deref(),
        postgres_max_connections,
        chain_config,
    )
    .await
    .map_err(ApiServerScannerError::PostgresConnectionError)
}

pub async fn run<S: ApiServerStorage>(
    chain_config: &Arc<ChainConfig>,
    rpc_client: &NodeRpcClient,
    mut storage: S,
) -> Result<(), ApiServerScannerError> {
    // TODO: move this storage initialization into a separate function... the trait bounds are gonna be painful

    let mut local_block = {
        let mut db_tx = storage
            .transaction_rw()
            .await
            .unwrap_or_else(|e| panic!("Initial transaction for initialization failed {}", e));
        if !db_tx
            .is_initialized()
            .await
            .unwrap_or_else(|e| panic!("Storage initialization checking failed {}", e))
        {
            db_tx
                .initialize_storage(chain_config)
                .await
                .unwrap_or_else(|e| panic!("Storage initialization failed {}", e));

            db_tx
                .commit()
                .await
                .unwrap_or_else(|e| panic!("Storage initialization commit failed {}", e));

            let mut local_block = BlockchainState::new(Arc::clone(chain_config), storage);
            local_block
                .scan_genesis(chain_config.genesis_block().as_ref())
                .await
                .expect("Can't scan genesis");
            local_block
        } else {
            let storage_version = db_tx
                .get_storage_version()
                .await
                .unwrap_or_else(|e| panic!("Storage version read failed {}", e))
                .expect("cannot be empty");

            if storage_version != CURRENT_STORAGE_VERSION {
                db_tx
                    .reinitialize_storage(chain_config)
                    .await
                    .unwrap_or_else(|e| panic!("Storage re-initialization failed {}", e));
            }

            db_tx
                .commit()
                .await
                .unwrap_or_else(|e| panic!("Storage initialization commit failed {}", e));
            BlockchainState::new(Arc::clone(chain_config), storage)
        }
    };

    loop {
        let sync_result =
            api_blockchain_scanner_lib::sync::sync_once(chain_config, rpc_client, &mut local_block)
                .await;

        match sync_result {
            Ok(_) => (),
            Err(err) => logging::log::error!("Scanner sync error: {}", err),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ApiServerScannerError {
    #[error("RPC error: {0}")]
    RpcError(node_comm::rpc_client::NodeRpcError),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
    #[error("Postgres connection error: {0}")]
    PostgresConnectionError(ApiServerStorageError),
}

#[tokio::main]
async fn main() -> Result<(), ApiServerScannerError> {
    utils::rust_backtrace::enable();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    let args = ApiServerScannerArgs::parse();

    logging::init_logging();
    logging::log::info!("Command line options: {args:?}");

    let ApiServerScannerArgs {
        network,
        rpc_address,
        rpc_cookie_file,
        rpc_username,
        rpc_password,
        postgres_config,
    } = args;

    let chain_type: ChainType = network.into();
    let chain_config = Arc::new(common::chain::config::Builder::new(chain_type).build());

    let rpc_auth = match (rpc_cookie_file, rpc_username, rpc_password) {
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
            ))
        }
    };

    let default_rpc_bind_address =
        || default_rpc_config(&chain_config).bind_address.expect("Can't fail").into();

    let rpc_address = rpc_address.unwrap_or_else(default_rpc_bind_address);

    let rpc_client = make_rpc_client(chain_config.clone(), rpc_address.to_string(), rpc_auth)
        .await
        .map_err(ApiServerScannerError::RpcError)?;

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

    run(&chain_config, &rpc_client, storage).await?;

    Ok(())
}
