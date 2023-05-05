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

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use tokio::sync::oneshot;
use wallet_cli_lib::{
    config::{Network, WalletCliArgs},
    console::{ConsoleInput, ConsoleOutput},
    errors::WalletCliError,
};

#[derive(Clone)]
struct MockConsole {
    input: Arc<Mutex<VecDeque<String>>>,
    output: Arc<Mutex<Vec<String>>>,
}

impl MockConsole {
    fn new(input: &[&str]) -> Self {
        let input = input.iter().map(|&s| s.to_owned()).collect();
        MockConsole {
            input: Arc::new(Mutex::new(input)),
            output: Default::default(),
        }
    }
}

impl ConsoleInput for MockConsole {
    fn is_tty(&self) -> bool {
        false
    }

    fn read_line(&mut self) -> Option<String> {
        self.input.lock().unwrap().pop_front()
    }
}

impl ConsoleOutput for MockConsole {
    fn print_line(&mut self, line: &str) {
        self.output.lock().unwrap().push(line.to_owned());
    }

    fn print_error(&mut self, error: WalletCliError) {
        self.output.lock().unwrap().push(error.to_string());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn basic_wallet_cli() {
    // logging::init_logging::<std::path::PathBuf>(None);

    let test_root = test_utils::test_root!("wallet-cli-tests").unwrap();
    let test_dir = test_root.fresh_test_dir("basic_wallet_cli");

    let rpc_username = "username";
    let rpc_password = "password";

    let (node_controller_tx, node_controller_rx) = oneshot::channel();

    let node_options = node_lib::Options {
        data_dir: Some(test_dir.as_ref().to_owned()),
        command: Some(node_lib::Command::Regtest(
            node_lib::regtest_options::RegtestOptions {
                run_options: node_lib::RunOptions {
                    storage_backend: None,
                    node_type: None,
                    mock_time: None,
                    max_db_commit_attempts: None,
                    max_orphan_blocks: None,
                    tx_index_enabled: None,
                    p2p_addr: Some(vec!["127.0.0.1:0".to_owned()]),
                    p2p_socks5_proxy: None,
                    p2p_disable_noise: None,
                    p2p_boot_node: None,
                    p2p_reserved_node: None,
                    p2p_max_inbound_connections: None,
                    p2p_ban_threshold: None,
                    p2p_outbound_connection_timeout: None,
                    p2p_ping_check_period: None,
                    p2p_ping_timeout: None,
                    max_tip_age: None,
                    http_rpc_addr: Some("127.0.0.1:0".parse().unwrap()),
                    http_rpc_enabled: None,
                    ws_rpc_addr: None,
                    ws_rpc_enabled: None,
                    rpc_username: Some(rpc_username.to_owned()),
                    rpc_password: Some(rpc_password.to_owned()),
                    rpc_cookie_file: None,
                    p2p_sync_stalling_timeout: None,
                },
                chain_config: node_lib::regtest_options::ChainConfigOptions {
                    chain_address_prefix: None,
                    chain_max_future_block_time_offset: None,
                    chain_version: None,
                    chain_target_block_spacing: None,
                    chain_coin_decimals: None,
                    chain_emission_schedule: None,
                    chain_max_block_header_size: None,
                    chain_max_block_size_with_standard_txs: None,
                    chain_max_block_size_with_smart_contracts: None,
                },
            },
        )),
    };

    let node_task = tokio::spawn(async move {
        let manager = node_lib::setup(node_options, Some(node_controller_tx)).await.unwrap();
        manager.main().await;
    });

    let node_controller = node_controller_rx.await.unwrap();

    let wallet_options = WalletCliArgs {
        network: Network::Regtest,
        wallet_file: None,
        rpc_address: node_controller.runtime_info.rpc_http_address,
        rpc_cookie_file: None,
        rpc_username: Some(rpc_username.to_owned()),
        rpc_password: Some(rpc_password.to_owned()),
        commands_file: None,
        history_file: None,
        exit_on_error: None,
        vi_mode: false,
    };

    let console = MockConsole::new(&["nodeversion"]);
    wallet_cli_lib::run(console.clone(), wallet_options).await.unwrap();
    assert!(console.output.lock().unwrap().last().unwrap() == "0.1.0");

    node_controller.shutdown_trigger.initiate();
    node_task.await.unwrap();

    test_root.delete();
}
