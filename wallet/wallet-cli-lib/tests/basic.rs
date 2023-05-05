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
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use chainstate::{
    make_chainstate, rpc::ChainstateRpcServer, ChainstateConfig,
    DefaultTransactionVerificationStrategy,
};
use mempool::{rpc::MempoolRpcServer, MempoolSubsystemInterface};
use p2p::rpc::P2pRpcServer;
use rpc::{rpc_creds::RpcCreds, RpcConfig};
use subsystem::manager::{ManagerJoinHandle, ShutdownTrigger};
use test_utils::test_dir::TestRoot;
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

const RPC_USERNAME: &str = "username";
const RPC_PASSWORD: &str = "password";

async fn start_node() -> (subsystem::Manager, SocketAddr) {
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let p2p_config = p2p::testing_utils::test_p2p_config();
    let rpc_creds = RpcCreds::basic(RPC_USERNAME, RPC_PASSWORD).unwrap();

    let rpc_config = RpcConfig {
        http_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
        http_enabled: true.into(),
        ws_bind_address: Default::default(),
        ws_enabled: false.into(),
    };

    let mut manager = subsystem::Manager::new("wallet-cli-test-manager");

    let chainstate = make_chainstate(
        Arc::clone(&chain_config),
        ChainstateConfig::new(),
        chainstate_storage::inmemory::Store::new_empty().unwrap(),
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();

    let chainstate = manager.add_subsystem("wallet-cli-test-chainstate", chainstate);

    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        chainstate.clone(),
        Default::default(),
        mempool::SystemUsageEstimator {},
    );
    let mempool = manager.add_subsystem_with_custom_eventloop("wallet-cli-test-mempool", {
        move |call, shutdn| mempool.run(call, shutdn)
    });

    let peerdb_storage = p2p::testing_utils::peerdb_inmemory_store();
    let p2p = manager.add_subsystem(
        "p2p",
        p2p::make_p2p(
            Arc::clone(&chain_config),
            Arc::new(p2p_config),
            chainstate.clone(),
            mempool.clone(),
            Default::default(),
            peerdb_storage,
        )
        .await
        .unwrap(),
    );

    let rpc = rpc::Builder::new(rpc_config, Some(rpc_creds))
        .register(node_lib::rpc::init(
            manager.make_shutdown_trigger(),
            chain_config,
        ))
        // .register(block_prod.clone().into_rpc())
        .register(chainstate.clone().into_rpc())
        .register(mempool.clone().into_rpc())
        .register(p2p.clone().into_rpc())
        .build()
        .await
        .unwrap();
    let rpc_http_address = rpc.http_address().cloned().unwrap();
    manager.add_subsystem("rpc", rpc);

    (manager, rpc_http_address)
}

struct CliTestFramework {
    rpc_address: SocketAddr,
    shutdown_trigger: ShutdownTrigger,
    manager_task: ManagerJoinHandle,
    test_root: TestRoot,
}

impl CliTestFramework {
    async fn setup() -> Self {
        // logging::init_logging::<std::path::PathBuf>(None);

        let test_root = test_utils::test_root!("wallet-cli-tests").unwrap();
        // let test_dir = test_root.fresh_test_dir("basic_wallet_cli");

        let (manager, rpc_address) = start_node().await;

        let shutdown_trigger = manager.make_shutdown_trigger();
        let manager_task = manager.main_in_task();

        Self {
            manager_task,
            shutdown_trigger,
            rpc_address,
            test_root,
        }
    }

    async fn run(&self, command: &str, expected: &str) {
        let wallet_options = WalletCliArgs {
            network: Network::Regtest,
            wallet_file: None,
            rpc_address: Some(self.rpc_address),
            rpc_cookie_file: None,
            rpc_username: Some(RPC_USERNAME.to_owned()),
            rpc_password: Some(RPC_PASSWORD.to_owned()),
            commands_file: None,
            history_file: None,
            exit_on_error: None,
            vi_mode: false,
        };

        let console = MockConsole::new(&[command]);
        wallet_cli_lib::run(console.clone(), wallet_options).await.unwrap();
        assert_eq!(console.output.lock().unwrap().last().unwrap(), expected);
    }

    async fn shutdown(self) {
        self.shutdown_trigger.initiate();
        self.manager_task.join().await;
        self.test_root.delete();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn wallet_cli_basic_test() {
    let test = CliTestFramework::setup().await;

    test.run("nodeversion", "0.1.0").await;

    test.shutdown().await;
}
