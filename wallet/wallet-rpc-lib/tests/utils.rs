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

use common::{
    chain::config::{
        regtest::GenesisStakingSettings, regtest_options::ChainConfigOptions, ChainConfig,
    },
    primitives::BlockHeight,
};
use rpc::RpcAuthData;
use test_utils::{test_dir::TestRoot, test_root};
use wallet::signer::software_signer::SoftwareSignerProvider;
use wallet_controller::NodeRpcClient;
use wallet_rpc_lib::{config::WalletServiceConfig, types::AccountArg, WalletHandle, WalletService};
use wallet_test_node::{RPC_PASSWORD, RPC_USERNAME};

pub use randomness::Rng;
pub use rpc::test_support::{ClientT, Subscription, SubscriptionClientT};
pub use serde_json::Value as JsonValue;
pub use test_utils::random::{make_seedable_rng, Seed};
use wallet_types::{seed_phrase::StoreSeedPhrase, wallet_type::WalletType};

pub const ACCOUNT0_ARG: AccountArg = AccountArg(0);
pub const ACCOUNT1_ARG: AccountArg = AccountArg(1);

pub struct TestFramework {
    pub wallet_service: WalletService<NodeRpcClient>,
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
                (BlockHeight::new(0), chain_config.genesis_block_id()),
                WalletType::Hot,
                |db_tx| {
                    Ok(SoftwareSignerProvider::new_from_mnemonic(
                        chain_config.clone(),
                        db_tx,
                        wallet_test_node::MNEMONIC,
                        None,
                        StoreSeedPhrase::DoNotStore,
                    )?)
                },
            )
            .unwrap();

            wallet_path
        };

        // Start the node
        let (manager, node_rpc_addr) =
            wallet_test_node::start_node(Arc::clone(&chain_config)).await;
        let shutdown_trigger = manager.make_shutdown_trigger();
        let node_manager_task = manager.main_in_task();

        let chain_config_options = ChainConfigOptions {
            software_version: None,
            chain_magic_bytes: None,
            chain_coin_decimals: None,
            chain_pos_netupgrades: None,
            chain_emission_schedule: None,
            chain_initial_difficulty: None,
            chain_target_block_spacing: None,
            chain_max_block_header_size: None,
            chain_genesis_block_timestamp: None,
            chain_pos_netupgrades_v0_to_v1: None,
            chain_genesis_staking_settings: GenesisStakingSettings::default(),
            chain_max_future_block_time_offset: None,
            chain_max_block_size_with_standard_txs: None,
            chain_max_block_size_with_smart_contracts: None,
        };

        // Start the wallet service
        let (wallet_service, rpc_server) = {
            let ws_config =
                WalletServiceConfig::new(chain_type, Some(wallet_path), false, vec![], None)
                    .with_regtest_options(chain_config_options)
                    .unwrap()
                    .with_custom_chain_config(chain_config.clone());
            let bind_addr = "127.0.0.1:0".parse().unwrap();
            let rpc_config = wallet_rpc_lib::config::WalletRpcConfig {
                bind_addr,
                auth_credentials: None,
            };

            let rpc_address = node_rpc_addr.to_string();
            let node_rpc = wallet_controller::make_rpc_client(
                chain_config,
                rpc_address,
                RpcAuthData::Basic {
                    username: RPC_USERNAME.to_string(),
                    password: RPC_PASSWORD.to_string(),
                },
            )
            .await
            .unwrap();

            wallet_rpc_lib::start_services(ws_config, rpc_config, node_rpc, false)
                .await
                .unwrap()
        };

        TestFramework {
            wallet_service,
            shutdown_trigger,
            node_manager_task,
            test_root,
            rpc_server,
        }
    }

    pub fn chain_config(&self) -> &ChainConfig {
        self.wallet_service.chain_config()
    }

    pub fn rpc_client_http(&self) -> rpc::RpcHttpClient {
        let rpc_addr = format!("http://{}", self.rpc_addr());
        let rpc_auth = rpc::RpcAuthData::None;
        rpc::new_http_client(rpc_addr, rpc_auth).unwrap()
    }

    pub async fn rpc_client_ws(&self) -> rpc::RpcWsClient {
        let rpc_addr = format!("ws://{}", self.rpc_addr());
        let rpc_auth = rpc::RpcAuthData::None;
        rpc::new_ws_client(rpc_addr, rpc_auth).await.unwrap()
    }

    pub fn handle(&self) -> WalletHandle<NodeRpcClient> {
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
