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

use blockprod::{rpc::BlockProductionRpcServer, test_blockprod_config};
use crypto::{key::PublicKey, random::Rng, vrf::VRFPublicKey};
use hex::FromHex;

use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use chainstate::{
    make_chainstate, rpc::ChainstateRpcServer, ChainstateConfig,
    DefaultTransactionVerificationStrategy,
};
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{self, ChainType},
        create_unittest_pos_config,
        output_value::OutputValue,
        stakelock::StakePoolData,
        ChainConfig, ConsensusUpgrade, Destination, Genesis, NetUpgrades, TxOutput, UpgradeVersion,
    },
    primitives::{per_thousand::PerThousand, Amount, BlockHeight, H256},
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

pub const MNEMONIC: &str = "spawn dove notice resist rigid grass load forum tobacco category motor fantasy prison submit rescue pool panic unable enact oven trap lava floor toward";

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

fn decode_hex<T: serialization::DecodeAll>(hex: &str) -> T {
    let bytes = Vec::from_hex(hex).expect("Hex decoding shouldn't fail");
    <T as serialization::DecodeAll>::decode_all(&mut bytes.as_slice())
        .expect("Decoding shouldn't fail")
}

fn create_custom_regtest_genesis(rng: &mut impl Rng) -> Genesis {
    // TODO: use coin_decimals instead of a fixed value
    const COIN: Amount = Amount::from_atoms(100_000_000_000);

    let total_amount = (COIN * 100_000_000).expect("must be valid");
    let initial_pool_amount = (COIN * 40_000).expect("must be valid");
    let mint_output_amount = (total_amount - initial_pool_amount).expect("must be valid");

    let genesis_mint_destination = decode_hex::<PublicKey>(
        "00027a9771bbb58170a0df36ed43e56490530f0f2f45b100c42f6f405af3ef21f54e",
    );
    let decommission_pub_key = decode_hex::<PublicKey>(
        "0002ea30f3bb179c58022dcf2f4fd2c88685695f9532d6a9dd071da8d7ac1fe91a7d",
    );
    let staker_pub_key = decode_hex::<PublicKey>(
        "0002884adf48b0b32ab3d66e1a8b46576dfacca5dd25b66603650de792de4dd2e483",
    );

    let vrf_pub_key = decode_hex::<VRFPublicKey>(
        "0020b95f66e824fc0df1ff13ba63d6727e013e1ea465cc37c2415a69cc408cf375",
    );

    let mint_output = TxOutput::Transfer(
        OutputValue::Coin(mint_output_amount),
        Destination::PublicKey(genesis_mint_destination),
    );

    let initial_pool = TxOutput::CreateStakePool(
        H256::zero().into(),
        Box::new(StakePoolData::new(
            initial_pool_amount,
            Destination::PublicKey(staker_pub_key),
            vrf_pub_key,
            Destination::PublicKey(decommission_pub_key),
            PerThousand::new(1000).expect("must be valid"),
            Amount::ZERO,
        )),
    );

    // Must be less than the current time, otherwise block production will not work properly
    let genesis_timestamp = rng.gen_range(1685000000..1685030000);

    Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(genesis_timestamp),
        vec![mint_output, initial_pool],
    )
}

fn create_chain_config(rng: &mut impl Rng) -> ChainConfig {
    let genesis = create_custom_regtest_genesis(rng);
    let pos_config = create_unittest_pos_config();
    let upgrades = vec![
        (
            BlockHeight::new(0),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::IgnoreConsensus),
        ),
        (
            BlockHeight::new(1),
            UpgradeVersion::ConsensusUpgrade(ConsensusUpgrade::PoS {
                initial_difficulty: common::chain::initial_difficulty(ChainType::Regtest).into(),
                config: pos_config,
            }),
        ),
    ];
    let net_upgrades = NetUpgrades::initialize(upgrades).expect("net upgrades");

    config::Builder::new(ChainType::Regtest)
        .genesis_custom(genesis)
        .net_upgrades(net_upgrades)
        .epoch_length(5.try_into().unwrap())
        .build()
}

async fn start_node(chain_config: Arc<ChainConfig>) -> (subsystem::Manager, SocketAddr) {
    let p2p_config = p2p::config::P2pConfig {
        bind_addresses: vec!["127.0.0.1:0".to_owned()],
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        max_clock_diff: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: common::primitives::user_agent::mintlayer_core_user_agent(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_unconnected_headers: Default::default(),
        sync_stalling_timeout: Default::default(),
    };
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
    );
    let mempool = manager.add_subsystem_with_custom_eventloop("wallet-cli-test-mempool", {
        move |call, shutdn| mempool.run(call, shutdn)
    });

    let peerdb_storage = p2p::testing_utils::peerdb_inmemory_store();
    let p2p = p2p::make_p2p(
        Arc::clone(&chain_config),
        Arc::new(p2p_config),
        chainstate.clone(),
        mempool.clone(),
        Default::default(),
        peerdb_storage,
    )
    .unwrap();
    let p2p = manager.add_subsystem_with_custom_eventloop("p2p", {
        move |call, shutdown| p2p.run(call, shutdown)
    });

    // Block production
    let block_prod = manager.add_subsystem(
        "blockprod",
        blockprod::make_blockproduction(
            Arc::clone(&chain_config),
            Arc::new(test_blockprod_config()),
            chainstate.clone(),
            mempool.clone(),
            p2p.clone(),
            Default::default(),
        )
        .unwrap(),
    );

    let rpc = rpc::Builder::new(rpc_config, Some(rpc_creds))
        .register(node_lib::rpc::init(
            manager.make_shutdown_trigger(),
            chain_config,
        ))
        .register(block_prod.clone().into_rpc())
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

pub struct CliTestFramework {
    pub chain_config: Arc<ChainConfig>,
    pub rpc_address: SocketAddr,
    pub shutdown_trigger: ShutdownTrigger,
    pub manager_task: ManagerJoinHandle,
    pub test_root: TestRoot,
}

impl CliTestFramework {
    pub async fn setup(rng: &mut impl Rng) -> Self {
        // logging::init_logging::<std::path::PathBuf>(None);

        let test_root = test_utils::test_root!("wallet-cli-tests").unwrap();
        // let test_dir = test_root.fresh_test_dir("basic_wallet_cli");

        let chain_config = Arc::new(create_chain_config(rng));

        let (manager, rpc_address) = start_node(Arc::clone(&chain_config)).await;

        let shutdown_trigger = manager.make_shutdown_trigger();
        let manager_task = manager.main_in_task();

        Self {
            chain_config,
            manager_task,
            shutdown_trigger,
            rpc_address,
            test_root,
        }
    }

    pub async fn run(&self, commands: &[&str]) -> Vec<String> {
        let wallet_options = WalletCliArgs {
            network: Network::Regtest,
            wallet_file: None,
            start_staking: false,
            rpc_address: Some(self.rpc_address),
            rpc_cookie_file: None,
            rpc_username: Some(RPC_USERNAME.to_owned()),
            rpc_password: Some(RPC_PASSWORD.to_owned()),
            commands_file: None,
            history_file: None,
            exit_on_error: None,
            vi_mode: false,
        };

        let console = MockConsole::new(commands);

        tokio::time::timeout(
            Duration::from_secs(60),
            wallet_cli_lib::run(
                console.clone(),
                wallet_options,
                Some(Arc::clone(&self.chain_config)),
            ),
        )
        .await
        .unwrap()
        .unwrap();

        let res = console.output.lock().unwrap().clone();
        res
    }

    pub async fn shutdown(self) {
        self.shutdown_trigger.initiate();
        self.manager_task.join().await;
        self.test_root.delete();
    }
}
