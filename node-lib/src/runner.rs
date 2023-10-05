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

use anyhow::{anyhow, Context, Result};
use blockprod::rpc::BlockProductionRpcServer;
use chainstate_launcher::{ChainConfig, StorageBackendConfig};
use common::chain::config::{regtest_options::regtest_chain_config, Builder as ChainConfigBuilder};

use chainstate::{rpc::ChainstateRpcServer, ChainstateError, InitializationError};
use common::chain::config::{assert_no_ignore_consensus_in_chain_config, ChainType};
use logging::log;

use mempool::{rpc::MempoolRpcServer, MempoolSubsystemInterface};

use test_rpc_functions::{empty::make_empty_rpc_test_functions, rpc::RpcTestFunctionsRpcServer};

use p2p::{peer_manager::peerdb::storage_impl::PeerDbStorageImpl, rpc::P2pRpcServer};
use rpc::rpc_creds::RpcCreds;
use test_rpc_functions::make_rpc_test_functions;
use utils::default_data_dir::prepare_data_dir;

use crate::{
    config_files::NodeConfigFile,
    mock_time::set_mock_time,
    node_controller::NodeController,
    options::{default_data_dir, Command, Options, RunOptions},
};

const LOCK_FILE_NAME: &str = ".lock";

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
    data_dir: PathBuf,
    node_config: NodeConfigFile,
) -> Result<(subsystem::Manager, NodeController)> {
    let chain_config = Arc::new(chain_config);

    assert_no_ignore_consensus_in_chain_config(&chain_config);

    // INITIALIZE SUBSYSTEMS

    let mut manager = subsystem::Manager::new("mintlayer");
    manager.install_signal_handlers();

    // Chainstate subsystem
    let chainstate = chainstate_launcher::make_chainstate(
        &data_dir,
        Arc::clone(&chain_config),
        node_config.chainstate.unwrap_or_default().into(),
    )?;
    let chainstate = manager.add_subsystem("chainstate", chainstate);

    // Mempool subsystem
    let mempool = mempool::make_mempool(
        Arc::clone(&chain_config),
        subsystem::Handle::clone(&chainstate),
        Default::default(),
    );
    let mempool = manager.add_subsystem_with_custom_eventloop("mempool", {
        move |call, shutdn| mempool.run(call, shutdn)
    });

    // P2P subsystem
    // TODO: Replace Lmdb with Sqlite backend when it's ready
    let peerdb_storage = PeerDbStorageImpl::new(storage_lmdb::Lmdb::new(
        data_dir.join("peerdb-lmdb"),
        Default::default(),
        Default::default(),
        Default::default(),
    ))?;
    let p2p = p2p::make_p2p(
        Arc::clone(&chain_config),
        Arc::new(node_config.p2p.unwrap_or_default().into()),
        subsystem::Handle::clone(&chainstate),
        subsystem::Handle::clone(&mempool),
        Default::default(),
        peerdb_storage,
    )?;
    let p2p = manager.add_subsystem_with_custom_eventloop("p2p", {
        move |call, shutdown| p2p.run(call, shutdown)
    });

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
        manager.add_subsystem(
            "rpc_test_functions",
            make_rpc_test_functions(Arc::clone(&chain_config)),
        )
    } else {
        // Otherwise we add empty rpc functions
        manager.add_subsystem("rpc_test_functions", make_empty_rpc_test_functions())
    };

    // RPC subsystem
    let rpc_config = node_config.rpc.unwrap_or_default();
    if rpc_config.http_enabled.unwrap_or(true) || rpc_config.ws_enabled.unwrap_or(true) {
        let rpc_creds = RpcCreds::new(
            &data_dir,
            rpc_config.username.as_deref(),
            rpc_config.password.as_deref(),
            rpc_config.cookie_file.as_deref(),
        )?;
        // TODO: get rid of the unwrap_or() after fixing the issue in #446
        let rpc = rpc::Builder::new(rpc_config.into(), Some(rpc_creds))
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
pub async fn setup(options: Options) -> Result<Node> {
    let command = options.command.clone().unwrap_or(Command::Testnet(RunOptions::default()));
    match command {
        Command::Mainnet(ref run_options) => {
            let chain_config = common::chain::config::create_mainnet();
            start(
                &options.config_path(*chain_config.chain_type()),
                &options.data_dir,
                run_options,
                chain_config,
            )
            .await
        }
        Command::Testnet(ref run_options) => {
            let chain_config = ChainConfigBuilder::new(ChainType::Testnet).build();
            start(
                &options.config_path(*chain_config.chain_type()),
                &options.data_dir,
                run_options,
                chain_config,
            )
            .await
        }
        Command::Regtest(ref regtest_options) => {
            let chain_config = regtest_chain_config(&regtest_options.chain_config)?;
            start(
                &options.config_path(*chain_config.chain_type()),
                &options.data_dir,
                &regtest_options.run_options,
                chain_config,
            )
            .await
        }
    }
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
    datadir_path_opt: &Option<PathBuf>,
    run_options: &RunOptions,
    chain_config: ChainConfig,
) -> Result<Node> {
    if let Some(mock_time) = run_options.mock_time {
        set_mock_time(*chain_config.chain_type(), mock_time)?;
    }

    let node_config =
        NodeConfigFile::read(config_path, run_options).context("Failed to initialize config")?;

    let data_dir = prepare_data_dir(
        || default_data_dir(*chain_config.chain_type()),
        datadir_path_opt,
    )
    .expect("Failed to prepare data directory");
    let lock_file = lock_data_dir(&data_dir)?;

    if run_options.clean_data.unwrap_or(false) {
        clean_data_dir(
            &data_dir,
            std::slice::from_ref(&data_dir.join(LOCK_FILE_NAME).as_path()),
        )?;
    }

    log::info!("Starting with the following config:\n {node_config:#?}");
    let (manager, controller) = match initialize(
        chain_config.clone(),
        data_dir.clone(),
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
                    let path = data_dir.join(storage_subdir_name);
                    if path.exists() {
                        std::fs::remove_dir_all(path)
                            .expect("Removing chainstate storage directory must succeed");
                    }
                }

                initialize(chain_config, data_dir, node_config).await?
            }
            _ => return Err(error),
        },
    };

    Ok(Node {
        manager,
        controller,
        lock_file,
    })
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};

    use crypto::random::{make_pseudo_rng, Rng};
    use tempfile::TempDir;

    use super::*;

    fn test_file_data(file_path: &Path, expected_contents: &[u8]) {
        let mut file = std::fs::File::open(file_path).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, expected_contents);
    }

    #[test]
    fn data_dir_default_creation() {
        let base_dir = TempDir::new().unwrap();
        let supposed_default_dir = base_dir.path().join("supposed_default");

        let default_data_dir_getter = || supposed_default_dir.clone();

        // Ensure path doesn't exist beforehand
        assert!(!supposed_default_dir.is_dir());

        let returned_data_dir = prepare_data_dir(default_data_dir_getter, &None).unwrap();

        // We expect now the default from the getter
        assert_eq!(
            returned_data_dir.canonicalize().unwrap(),
            supposed_default_dir.canonicalize().unwrap()
        );

        // We also expect the default directory to exist
        assert!(supposed_default_dir.is_dir());

        // Now let's use the data directory
        let file_path = supposed_default_dir.join("SomeFile.txt");
        let file_data: Vec<u8> = (0..1024).map(|_| make_pseudo_rng().gen::<u8>()).collect();
        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            file.write_all(&file_data).unwrap();
        }

        test_file_data(&file_path, &file_data);

        // Now we prepare again, and ensure that our file is unchanged
        let returned_data_dir = prepare_data_dir(default_data_dir_getter, &None).unwrap();

        // Same path is returned
        assert_eq!(
            returned_data_dir.canonicalize().unwrap(),
            supposed_default_dir.canonicalize().unwrap()
        );

        test_file_data(&file_path, &file_data);
    }

    #[test]
    fn data_dir_custom_must_exist_beforehand() {
        let base_dir = TempDir::new().unwrap();
        let supposed_default_dir = base_dir.path().join("supposed_default");
        let supposed_custom_dir = base_dir.path().join("supposed_custom");

        let default_data_dir_getter = || supposed_default_dir.clone();

        // Both default and custom don't exist beforehand
        assert!(!supposed_default_dir.is_dir());
        assert!(!supposed_custom_dir.is_dir());

        // Call fails because custom doesn't exist
        let _returned_data_dir =
            prepare_data_dir(default_data_dir_getter, &Some(supposed_custom_dir.clone()))
                .unwrap_err();

        // Nothing has changed after the call
        assert!(!supposed_default_dir.is_dir());
        assert!(!supposed_custom_dir.is_dir());

        // Now we create the directory by hand
        std::fs::create_dir_all(supposed_custom_dir.clone()).unwrap();

        // Now custom directory exists
        assert!(!supposed_default_dir.is_dir());
        assert!(supposed_custom_dir.is_dir());

        // Now call succeeds because custom exists
        let returned_data_dir =
            prepare_data_dir(default_data_dir_getter, &Some(supposed_custom_dir.clone())).unwrap();

        // We expect now the custom to be returned
        assert_eq!(
            returned_data_dir.canonicalize().unwrap(),
            supposed_custom_dir.canonicalize().unwrap()
        );

        // Last state of directories didn't change
        assert!(!supposed_default_dir.is_dir());
        assert!(supposed_custom_dir.is_dir());

        // Now let's use the data directory
        let file_path = supposed_custom_dir.join("SomeFile.txt");
        let file_data: Vec<u8> = (0..1024).map(|_| make_pseudo_rng().gen::<u8>()).collect();
        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            file.write_all(&file_data).unwrap();
        }

        test_file_data(&file_path, &file_data);

        // Now we prepare again, and ensure that our file is unchanged
        let returned_data_dir =
            prepare_data_dir(default_data_dir_getter, &Some(supposed_custom_dir.clone())).unwrap();

        // Same path is returned
        assert_eq!(
            returned_data_dir.canonicalize().unwrap(),
            supposed_custom_dir.canonicalize().unwrap()
        );

        test_file_data(&file_path, &file_data);
    }
}
