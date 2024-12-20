// Copyright (c) 2022 RBB S.r.l
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

//! Node initialization routine.

use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use file_rotate::{compression::Compression, suffix::AppendCount, ContentLimit, FileRotate};

use anyhow::{anyhow, Context, Result};
use blockprod::rpc::BlockProductionRpcServer;
use chainstate_launcher::{ChainConfig, StorageBackendConfig};
use common::chain::config::regtest_options::regtest_chain_config;

use chainstate::{rpc::ChainstateRpcServer, ChainstateError, InitializationError};
use common::chain::config::{assert_no_ignore_consensus_in_chain_config, ChainType};
use logging::log;

use mempool::rpc::MempoolRpcServer;

use test_rpc_functions::{empty::make_empty_rpc_test_functions, rpc::RpcTestFunctionsRpcServer};

use p2p::{error::P2pError, rpc::P2pRpcServer};
use rpc::rpc_creds::RpcCreds;
use test_rpc_functions::make_rpc_test_functions;

use crate::{
    config_files::{NodeConfigFile, DEFAULT_P2P_NETWORKING_ENABLED, DEFAULT_RPC_ENABLED},
    mock_time::set_mock_time,
    node_controller::NodeController,
    options::{default_data_dir, Command, Options, RunOptions},
    RpcConfigFile,
};

const LOCK_FILE_NAME: &str = ".lock";
const LOG_FILE_NAME: &str = "mintlayer.log";

pub enum NodeSetupResult {
    Node(Node),
    DataDirCleanedUp,
}

pub struct Node {
    manager: subsystem::Manager,
    controller: NodeController,
    lock_file: File,
}

impl Node {
    pub async fn main(self) {
        self.manager.main().await;
        drop(self.lock_file);
    }

    pub fn controller(&self) -> &NodeController {
        &self.controller
    }
}

/// Initialize the node, giving caller the opportunity to add more subsystems before start.
async fn initialize(
    chain_config: ChainConfig,
    data_dir: &Path,
    node_config: NodeConfigFile,
) -> Result<(subsystem::Manager, NodeController)> {
    let chain_config = Arc::new(chain_config);

    assert_no_ignore_consensus_in_chain_config(&chain_config);

    // INITIALIZE SUBSYSTEMS

    let manager_config = subsystem::ManagerConfig::new("mintlayer").enable_signal_handlers();
    let mut manager = subsystem::Manager::new_with_config(manager_config);

    // Chainstate subsystem
    let chainstate = chainstate_launcher::make_chainstate(
        data_dir,
        Arc::clone(&chain_config),
        node_config.chainstate.unwrap_or_default().into(),
    )?;
    let chainstate = manager.add_subsystem("chainstate", chainstate);

    // Mempool subsystem
    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        node_config.mempool.unwrap_or_default().into(),
        subsystem::Handle::clone(&chainstate),
        Default::default(),
    );
    let mempool = manager.add_custom_subsystem("mempool", |handle| mempool.init(handle));

    // P2P subsystem
    let peerdb_storage = {
        use p2p::peer_manager::peerdb::open_storage;

        let peerdb_data_dir = data_dir.join("peerdb-lmdb");
        let open_storage_backend = |data_dir| {
            // TODO: Replace Lmdb with Sqlite backend when it's ready
            storage_lmdb::Lmdb::new(
                data_dir,
                Default::default(),
                Default::default(),
                Default::default(),
            )
        };

        match open_storage(open_storage_backend(peerdb_data_dir.clone())) {
            Ok(storage) => Ok(storage),
            Err(err) => match err {
                P2pError::PeerDbStorageVersionMismatch {
                    expected_version,
                    actual_version,
                } => {
                    log::warn!(
                        "Peer db storage version mismatch, expected {}, got {}; removing the db.",
                        expected_version,
                        actual_version
                    );
                    // TODO: implement a mechanism of upgrading the db, so that the previously collected
                    // addresses are not lost.
                    std::fs::remove_dir_all(&peerdb_data_dir)?;
                    open_storage(open_storage_backend(peerdb_data_dir))
                }
                P2pError::NetworkingError(_)
                | P2pError::ProtocolError(_)
                | P2pError::DialError(_)
                | P2pError::ChannelClosed
                | P2pError::PeerError(_)
                | P2pError::SubsystemFailure
                | P2pError::ChainstateError(_)
                | P2pError::StorageFailure(_)
                | P2pError::NoiseHandshakeError(_)
                | P2pError::InvalidConfigurationValue(_)
                | P2pError::InvalidStorageState(_)
                | P2pError::MempoolError(_)
                | P2pError::ConnectionValidationFailed(_)
                | P2pError::SyncError(_) => Err(err),
            },
        }
    }?;
    let p2p_config_file = node_config.p2p.unwrap_or_default();
    let p2p = p2p::make_p2p(
        p2p_config_file.networking_enabled.unwrap_or(DEFAULT_P2P_NETWORKING_ENABLED),
        Arc::clone(&chain_config),
        Arc::new(p2p_config_file.into()),
        subsystem::Handle::clone(&chainstate),
        subsystem::Handle::clone(&mempool),
        Default::default(),
        peerdb_storage,
    )?
    .add_to_manager("p2p", &mut manager);

    // Block production
    let block_prod = manager.add_subsystem(
        "blockprod",
        blockprod::make_blockproduction(
            Arc::clone(&chain_config),
            Arc::new(node_config.blockprod.unwrap_or_default().into()),
            subsystem::Handle::clone(&chainstate),
            subsystem::Handle::clone(&mempool),
            subsystem::Handle::clone(&p2p),
            Default::default(),
        )?,
    );

    // RPC Functions for tests
    let rpc_test_functions = if chain_config.chain_type() == &ChainType::Regtest {
        // We add the test rpc functions only if we are in regtest mode
        manager.add_direct_subsystem(
            "rpc_test_functions",
            make_rpc_test_functions(Arc::clone(&chain_config)),
        )
    } else {
        // Otherwise we add empty rpc functions
        manager.add_direct_subsystem("rpc_test_functions", make_empty_rpc_test_functions())
    };

    // RPC subsystem
    let rpc_config = node_config.rpc.unwrap_or_default();
    if rpc_config.rpc_enabled.unwrap_or(DEFAULT_RPC_ENABLED) {
        let rpc_creds = RpcCreds::new(
            data_dir,
            rpc_config.username.as_deref(),
            rpc_config.password.as_deref(),
            rpc_config.cookie_file.as_deref(),
        )?;

        let rpc = rpc::Builder::new(
            rpc_config
                .bind_address
                .unwrap_or_else(|| RpcConfigFile::default_bind_address(&chain_config)),
            Some(rpc_creds),
        )
        .with_method_list("node_list_methods")
        .register(crate::rpc::init(
            manager.make_shutdown_trigger(),
            chain_config,
        ))
        .register(block_prod.clone().into_rpc())
        .register(chainstate.clone().into_rpc())
        .register(mempool.clone().into_rpc())
        .register(p2p.clone().into_rpc())
        .register(rpc_test_functions.into_rpc())
        .build();

        let rpc = rpc.await?;
        let _rpc = manager.add_subsystem("rpc", rpc);
    };

    let controller = NodeController {
        shutdown_trigger: manager.make_shutdown_trigger(),
        chainstate: chainstate.clone(),
        block_prod: block_prod.clone(),
        mempool: mempool.clone(),
        p2p: p2p.clone(),
    };

    Ok((manager, controller))
}

/// Processes options and potentially runs the node.
pub async fn setup(options: Options) -> Result<NodeSetupResult> {
    let command = options.command.clone().unwrap_or(Command::Mainnet(RunOptions::default()));
    let run_options = command.run_options();
    let chain_config = match &command {
        Command::Mainnet(_) => common::chain::config::create_mainnet(),
        Command::Testnet(_) => common::chain::config::create_testnet(),
        Command::Regtest(regtest_options) => regtest_chain_config(&regtest_options.chain_config)?,
    };

    // Prepare data dir
    let data_dir = utils::default_data_dir::prepare_data_dir(
        || default_data_dir(*chain_config.chain_type()),
        &options.data_dir,
        options.create_data_dir_if_missing,
    )
    .expect("Failed to prepare data directory");

    // Lock data dir
    let lock_file = lock_data_dir(&data_dir)?;

    // Clean data dir if needed
    if run_options.clean_data.unwrap_or(false) {
        clean_data_dir(
            &data_dir,
            std::slice::from_ref(&data_dir.join(LOCK_FILE_NAME).as_path()),
        )?;
        return Ok(NodeSetupResult::DataDirCleanedUp);
    }

    let main_log_writer_settings = logging::default_writer_settings();

    // Init logging
    if run_options.log_to_file.is_some_and(|log_to_file| log_to_file) {
        let log_file = FileRotate::new(
            data_dir.join(format!("logs/{}", LOG_FILE_NAME)),
            AppendCount::new(2),              // total 3 file
            ContentLimit::Bytes(100_000_000), // 100MB each
            Compression::None,
            #[cfg(unix)]
            None,
        );
        logging::init_logging_generic(
            main_log_writer_settings,
            Some(logging::WriterSettings {
                make_writer: logging::write_to_make_writer(log_file),
                is_terminal: false,
                filter: logging::ValueOrEnvVar::Value("info".into()),
                log_style: logging::ValueOrEnvVar::Value(logging::LogStyle::Text(
                    logging::TextColoring::Off,
                )),
            }),
        );
    } else {
        logging::init_logging_generic(main_log_writer_settings, logging::no_writer_settings());
    }

    logging::log::info!("Command line options: {options:?}");

    let (manager, controller) = start(
        &options.config_path(*chain_config.chain_type()),
        &data_dir,
        run_options,
        chain_config,
    )
    .await?;

    Ok(NodeSetupResult::Node(Node {
        manager,
        controller,
        lock_file,
    }))
}

/// Creates an exclusive lock file in the specified directory.
/// Fails if the lock file cannot be created or is already locked.
fn lock_data_dir(data_dir: &PathBuf) -> Result<std::fs::File> {
    let lock = std::fs::File::create(data_dir.join(LOCK_FILE_NAME))
        .map_err(|e| anyhow!("Cannot create lock file in {data_dir:?}: {e}"))?;
    fs4::FileExt::try_lock_exclusive(&lock)
        .map_err(|e| anyhow!("Cannot lock directory {data_dir:?}: {e}"))?;
    Ok(lock)
}

fn clean_data_dir(data_dir: &Path, exclude: &[&Path]) -> Result<()> {
    for entry in std::fs::read_dir(data_dir)? {
        let entry_path = entry?.path();

        if exclude
            .iter()
            .map(|e| e.file_name())
            .all(|exclude| entry_path.file_name() != exclude)
        {
            if entry_path.is_dir() {
                std::fs::remove_dir_all(entry_path)?;
            } else {
                std::fs::remove_file(entry_path)?;
            }
        }
    }
    Ok(())
}

async fn start(
    config_path: &Path,
    datadir_path: &Path,
    run_options: &RunOptions,
    chain_config: ChainConfig,
) -> Result<(subsystem::Manager, NodeController)> {
    run_options.force_allow_run_as_root_outer.ensure_not_running_as_root_user()?;

    if let Some(mock_time) = run_options.mock_time {
        set_mock_time(*chain_config.chain_type(), mock_time)?;
    }

    let node_config = NodeConfigFile::read(&chain_config, config_path, run_options)
        .context("Failed to initialize config")?;

    log::info!(
        "Starting mintlayer-core version {}",
        chain_config.software_version()
    );

    log::info!("Starting with the following config:\n {node_config:#?}");

    let (manager, controller) = match initialize(
        chain_config.clone(),
        datadir_path,
        node_config.clone(),
    )
    .await
    {
        Ok((manager, controller)) => (manager, controller),
        Err(error) => match error.downcast_ref::<ChainstateError>() {
            Some(ChainstateError::FailedToInitializeChainstate(
                InitializationError::StorageCompatibilityCheckError(e),
            )) => {
                log::warn!("Failed to init chainstate: {e} \n Cleaning up current db and trying from scratch.");

                let storage_config: StorageBackendConfig =
                    node_config.chainstate.clone().unwrap_or_default().storage_backend.into();

                // cleanup storage directory and retry initialization
                if let Some(storage_subdir_name) = storage_config.subdirectory_name() {
                    let path = datadir_path.join(storage_subdir_name);
                    if path.exists() {
                        std::fs::remove_dir_all(path)
                            .expect("Removing chainstate storage directory must succeed");
                    }
                }

                initialize(chain_config, datadir_path, node_config).await?
            }
            _ => return Err(error),
        },
    };

    Ok((manager, controller))
}
