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

//! Wallet RPC testing utilities

use std::{sync::Arc, time::Duration};

use common::primitives::BlockHeight;
use test_utils::{test_dir::TestRoot, test_root};
use wallet_rpc_lib::{
    config::WalletServiceConfig, types::AccountIndexArg, WalletHandle, WalletService,
};
use wallet_test_node::{RPC_PASSWORD, RPC_USERNAME};

pub use crypto::random::Rng;
pub use jsonrpsee::{core::client::ClientT, core::JsonValue};
pub use test_utils::random::{make_seedable_rng, Seed};

pub const ACCOUNT0_ARG: AccountIndexArg = AccountIndexArg { account: 0 };
pub const ACCOUNT1_ARG: AccountIndexArg = AccountIndexArg { account: 1 };

pub struct TestFramework {
    pub wallet_service: WalletService,
    pub shutdown_trigger: subsystem::ShutdownTrigger,
    pub node_manager_task: subsystem::ManagerJoinHandle,
    pub test_root: TestRoot,
    pub rpc_server: rpc::Rpc,
}

impl TestFramework {
    /// Start node, initialize a wallet, start wallet service
    pub async fn start(rng: &mut impl Rng) -> Self {
        logging::init_logging();

        let chain_config = {
            let opts = wallet_test_node::default_chain_config_options();
            Arc::new(wallet_test_node::create_chain_config(rng, &opts))
        };
        let chain_type = *chain_config.chain_type();

        let test_root = test_root!("wallet_rpc").expect("test root creation");

        // Create the wallet database
        let wallet_path = {
            let wallet_path = test_root.fresh_test_dir("wallet").as_ref().join("wallet.sqlite");
            let db = wallet::wallet::open_or_create_wallet_file(&wallet_path).unwrap();

            let _wallet = wallet::Wallet::create_new_wallet(
                Arc::clone(&chain_config),
                db,
                wallet_test_node::MNEMONIC,
                None,
                wallet_types::seed_phrase::StoreSeedPhrase::DoNotStore,
                BlockHeight::new(0),
                chain_config.genesis_block_id(),
            )
            .unwrap();

            wallet_path
        };

        // Start the node
        let (manager, node_rpc_addr) =
            wallet_test_node::start_node(Arc::clone(&chain_config)).await;
        let shutdown_trigger = manager.make_shutdown_trigger();
        let node_manager_task = manager.main_in_task();

        // Start the wallet service
        let (wallet_service, rpc_server) = {
            let ws_config = WalletServiceConfig::new(chain_type, wallet_path)
                .with_custom_chain_config(chain_config)
                .with_node_rpc_address(node_rpc_addr.to_string())
                .with_username_and_password(RPC_USERNAME.to_string(), RPC_PASSWORD.to_string());
            let bind_addr = "127.0.0.1:0".parse().unwrap();
            let rpc_config = wallet_rpc_lib::config::WalletRpcConfig {
                bind_addr,
                auth_credentials: None,
            };

            wallet_rpc_lib::start_services(ws_config, rpc_config).await.unwrap()
        };

        TestFramework {
            wallet_service,
            shutdown_trigger,
            node_manager_task,
            test_root,
            rpc_server,
        }
    }

    pub fn rpc_client(&self) -> rpc::RpcHttpClient {
        let rpc_addr = format!("http://{}", self.rpc_addr());
        let rpc_auth = rpc::RpcAuthData::None;
        rpc::new_http_client(rpc_addr, rpc_auth).unwrap()
    }

    pub fn handle(&self) -> WalletHandle {
        self.wallet_service.handle()
    }

    pub fn rpc_addr(&self) -> &std::net::SocketAddr {
        self.rpc_server.http_address()
    }

    pub async fn stop(self) {
        let TestFramework {
            wallet_service,
            shutdown_trigger,
            node_manager_task,
            test_root,
            rpc_server,
        } = self;

        let wallet_handle = wallet_service.handle();

        let shutdown_sequence = async {
            wallet_handle.stop().unwrap();
            wallet_rpc_lib::wait_for_shutdown(wallet_service, rpc_server).await;

            shutdown_trigger.initiate();
            node_manager_task.join().await;
        };

        tokio::time::timeout(Duration::from_secs(10), shutdown_sequence).await.unwrap();

        test_root.delete();
    }
}