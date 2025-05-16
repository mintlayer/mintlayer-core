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

use common::chain::ChainConfig;
use randomness::Rng;
use tokio::task::JoinHandle;
use wallet_rpc_lib::types::NodeInterface;

use std::{
    sync::{mpsc, Arc},
    time::Duration,
};

use subsystem::{ManagerJoinHandle, ShutdownTrigger};
use test_utils::test_dir::TestRoot;
use wallet_cli_lib::{
    config::{Network, RegtestOptions, WalletCliArgs},
    console::{ConsoleInput, ConsoleOutput},
    errors::WalletCliError,
};
use wallet_test_node::{
    create_chain_config, default_chain_config_options, start_node, COLD_WALLET_MENEMONIC,
    RPC_PASSWORD, RPC_USERNAME,
};

pub use wallet_test_node::MNEMONIC;

struct MockConsoleInput {
    input_rx: mpsc::Receiver<String>,
}

struct MockConsoleOutput {
    output_tx: mpsc::Sender<String>,
}

impl ConsoleInput for MockConsoleInput {
    fn is_tty(&self) -> bool {
        false
    }

    fn read_line(&mut self) -> Option<String> {
        self.input_rx.recv().ok()
    }
}

impl ConsoleOutput for MockConsoleOutput {
    fn print_line(&mut self, line: &str) {
        self.output_tx.send(line.to_owned()).unwrap();
    }

    fn print_error<N: NodeInterface>(&mut self, error: WalletCliError<N>) {
        self.output_tx.send(error.to_string()).unwrap();
    }
}

pub struct CliTestFramework {
    pub wallet_task: JoinHandle<()>,
    pub input_tx: mpsc::Sender<String>,
    pub output_rx: mpsc::Receiver<String>,
    pub shutdown_trigger: ShutdownTrigger,
    pub manager_task: ManagerJoinHandle,
    pub test_root: TestRoot,
    #[allow(dead_code)]
    pub chain_config: Arc<ChainConfig>,
}

impl CliTestFramework {
    pub async fn setup(rng: &mut impl Rng) -> Self {
        logging::init_logging();

        let test_root = test_utils::test_root!("wallet-cli-tests").unwrap();

        let chain_config_options = default_chain_config_options();

        let chain_config = Arc::new(create_chain_config(rng, &chain_config_options));

        let (manager, rpc_address) = start_node(Arc::clone(&chain_config)).await;

        let shutdown_trigger = manager.make_shutdown_trigger();
        let manager_task = manager.main_in_task();

        let wallet_options = WalletCliArgs {
            network: Some(Network::Regtest(Box::new(RegtestOptions {
                chain_config: chain_config_options,
                run_options: wallet_cli_lib::config::CliArgs {
                    wallet_file: None,
                    wallet_password: None,
                    force_change_wallet_type: false,
                    hardware_wallet: None,
                    start_staking: false,
                    start_staking_for_account: vec![],
                    node_rpc_address: Some(rpc_address.into()),
                    node_rpc_cookie_file: None,
                    node_rpc_username: Some(RPC_USERNAME.to_owned()),
                    node_rpc_password: Some(RPC_PASSWORD.to_owned()),
                    commands_file: None,
                    history_file: None,
                    exit_on_error: None,
                    vi_mode: false,
                    in_top_x_mb: 5,
                    cold_wallet: false,
                    enable_wallet_rpc_interface: false,
                    wallet_rpc_bind_address: None,
                    wallet_rpc_username: None,
                    wallet_rpc_password: None,
                    wallet_rpc_cookie_file: None,
                    wallet_rpc_no_authentication: false,
                    remote_rpc_wallet_address: None,
                    remote_rpc_wallet_username: None,
                    remote_rpc_wallet_password: None,
                    remote_rpc_wallet_cookie_file: None,
                    remote_rpc_wallet_no_authentication: true,
                    no_qr: false,
                },
            }))),
            run_options: wallet_cli_lib::config::CliArgs {
                wallet_file: None,
                wallet_password: None,
                force_change_wallet_type: false,
                hardware_wallet: None,
                start_staking: false,
                start_staking_for_account: vec![],
                node_rpc_address: Some(rpc_address.into()),
                node_rpc_cookie_file: None,
                node_rpc_username: Some(RPC_USERNAME.to_owned()),
                node_rpc_password: Some(RPC_PASSWORD.to_owned()),
                commands_file: None,
                history_file: None,
                exit_on_error: None,
                vi_mode: false,
                in_top_x_mb: 5,
                cold_wallet: false,
                enable_wallet_rpc_interface: false,
                wallet_rpc_bind_address: None,
                wallet_rpc_username: None,
                wallet_rpc_password: None,
                wallet_rpc_cookie_file: None,
                wallet_rpc_no_authentication: false,
                remote_rpc_wallet_address: None,
                remote_rpc_wallet_username: None,
                remote_rpc_wallet_password: None,
                remote_rpc_wallet_cookie_file: None,
                remote_rpc_wallet_no_authentication: true,
                no_qr: false,
            },
        };

        let (output_tx, output_rx) = std::sync::mpsc::channel();
        let (input_tx, input_rx) = std::sync::mpsc::channel();

        let input = MockConsoleInput { input_rx };

        let output = MockConsoleOutput { output_tx };

        let wallet_chain_config = chain_config.clone();
        let wallet_task = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_secs(120),
                wallet_cli_lib::run(input, output, wallet_options, Some(wallet_chain_config)),
            )
            .await
            .unwrap()
            .unwrap();
        });

        Self {
            wallet_task,
            manager_task,
            shutdown_trigger,
            test_root,
            input_tx,
            output_rx,
            chain_config,
        }
    }

    pub fn exec(&self, command: &str) -> String {
        self.input_tx.send(command.to_string()).unwrap();
        self.output_rx.recv_timeout(Duration::from_secs(60)).unwrap()
    }

    pub fn create_genesis_wallet(&self) {
        // Use dir name with spaces to make sure quoting works as expected
        let file_name = self
            .test_root
            .fresh_test_dir("wallet dir")
            .as_ref()
            .join("genesis_wallet")
            .to_str()
            .unwrap()
            .to_owned();
        let cmd = format!(
            "wallet-recover software \"{}\" store-seed-phrase \"{}\"",
            file_name, MNEMONIC
        );
        assert_eq!(self.exec(&cmd), "Wallet recovered successfully");
    }

    #[allow(dead_code)]
    pub fn create_genesis_cold_wallet(&self) {
        // Use dir name with spaces to make sure quoting works as expected
        let file_name = self
            .test_root
            .fresh_test_dir("wallet dir")
            .as_ref()
            .join("genesis_cold_wallet")
            .to_str()
            .unwrap()
            .to_owned();
        let cmd = format!(
            "wallet-create software \"{}\" store-seed-phrase \"{}\"",
            file_name, COLD_WALLET_MENEMONIC,
        );
        assert_eq!(self.exec(&cmd), "New wallet created successfully");
    }

    pub async fn shutdown(self) {
        drop(self.input_tx);
        self.wallet_task.await.unwrap();

        self.shutdown_trigger.initiate();
        self.manager_task.join().await;

        self.test_root.delete();
    }
}
