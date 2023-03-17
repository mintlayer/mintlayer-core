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
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use paste::paste;

use chainstate::rpc::ChainstateRpcServer;
use common::{
    chain::config::{
        Builder as ChainConfigBuilder, ChainConfig, ChainType, EmissionScheduleTabular,
    },
    primitives::semver::SemVer,
};
use logging::log;

use mempool::{rpc::MempoolRpcServer, MempoolSubsystemInterface};

use p2p::{peer_manager::peerdb::storage_impl::PeerDbStorageImpl, rpc::P2pRpcServer};

use crate::{
    config_files::NodeConfigFile,
    mock_time::set_mock_time,
    options::{default_data_dir, Command, Options, RunOptions},
    regtest_options::ChainConfigOptions,
};

/// Initialize the node, giving caller the opportunity to add more subsystems before start.
pub async fn initialize(
    chain_config: ChainConfig,
    data_dir: PathBuf,
    node_config: NodeConfigFile,
) -> Result<subsystem::Manager> {
    let chain_config = Arc::new(chain_config);

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
        chainstate.clone(),
        Default::default(),
        mempool::SystemUsageEstimator {},
    );
    let mempool = manager.add_subsystem_with_custom_eventloop("mempool", move |call, shutdn| {
        mempool.run(call, shutdn)
    });

    // P2P subsystem
    // TODO: Replace Lmdb with Sqlite backend when it's ready
    let peerdb_storage = PeerDbStorageImpl::new(storage_lmdb::Lmdb::new(
        data_dir.join("peerdb-lmdb"),
        Default::default(),
        Default::default(),
        Default::default(),
    ))?;
    let p2p = manager.add_subsystem(
        "p2p",
        p2p::make_p2p(
            Arc::clone(&chain_config),
            Arc::new(node_config.p2p.unwrap_or_default().into()),
            chainstate.clone(),
            mempool.clone(),
            Default::default(),
            peerdb_storage,
        )
        .await
        .expect("The p2p subsystem initialization failed"),
    );

    // Block production
    let _block_prod = manager.add_subsystem(
        "blockprod",
        blockprod::make_blockproduction(
            Arc::clone(&chain_config),
            chainstate.clone(),
            mempool.clone(),
            Default::default(),
        )
        .await?,
    );

    let rpc_config = node_config.rpc.unwrap_or_default();

    // RPC subsystem
    if rpc_config.http_enabled.unwrap_or(true) || rpc_config.ws_enabled.unwrap_or(true) {
        // TODO: get rid of the unwrap_or() after fixing the issue in #446
        let _rpc = manager.add_subsystem(
            "rpc",
            rpc::Builder::new(rpc_config.into())
                .register(crate::rpc::init(
                    manager.make_shutdown_trigger(),
                    chain_config,
                ))
                .register(chainstate.clone().into_rpc())
                .register(mempool.into_rpc())
                .register(p2p.clone().into_rpc())
                .build()
                .await?,
        );
    }

    Ok(manager)
}

/// Processes options and potentially runs the node.
pub async fn run(options: Options) -> Result<()> {
    match options.command {
        Command::Mainnet(ref run_options) => {
            let chain_config = common::chain::config::create_mainnet();
            start(
                &options.config_path(),
                &options.data_dir,
                run_options,
                chain_config,
            )
            .await
        }
        Command::Testnet(ref run_options) => {
            let chain_config = ChainConfigBuilder::new(ChainType::Testnet).build();
            start(
                &options.config_path(),
                &options.data_dir,
                run_options,
                chain_config,
            )
            .await
        }
        Command::Regtest(ref regtest_options) => {
            let chain_config = regtest_chain_config(&regtest_options.chain_config)?;
            start(
                &options.config_path(),
                &options.data_dir,
                &regtest_options.run_options,
                chain_config,
            )
            .await
        }
    }
}

/// Prepare data directory for the node.
/// Two possibilities:
/// 1. If no data directory is specified, use the default data directory provided by default_data_dir_getter;
///    it doesn't have to exist. It will be automatically created.
/// 2. If a custom data directory is specified, it MUST exist. Otherwise, an error is returned.
fn prepare_data_dir<F: Fn() -> PathBuf>(
    default_data_dir_getter: F,
    datadir_path_opt: &Option<PathBuf>,
) -> Result<PathBuf> {
    let data_dir = match datadir_path_opt {
        Some(data_dir) => {
            if !data_dir.exists() {
                return Err(anyhow::anyhow!("Custom data directory '{}' does not exist. Please create it or use the default data directory.", data_dir.display()));
            }
            data_dir.clone()
        }
        None => {
            std::fs::create_dir_all(default_data_dir_getter()).with_context(|| {
                format!(
                    "Failed to create the '{}' data directory",
                    default_data_dir_getter().display()
                )
            })?;
            default_data_dir_getter()
        }
    };
    Ok(data_dir)
}

async fn start(
    config_path: &Path,
    datadir_path_opt: &Option<PathBuf>,
    run_options: &RunOptions,
    chain_config: ChainConfig,
) -> Result<()> {
    if let Some(mock_time) = run_options.mock_time {
        set_mock_time(*chain_config.chain_type(), mock_time)?;
    }

    let node_config =
        NodeConfigFile::read(config_path, run_options).context("Failed to initialize config")?;

    let data_dir = prepare_data_dir(default_data_dir, datadir_path_opt)
        .expect("Failed to prepare data directory");

    log::info!("Starting with the following config:\n {node_config:#?}");
    let manager = initialize(chain_config, data_dir, node_config).await?;
    manager.main().await;
    Ok(())
}

fn regtest_chain_config(options: &ChainConfigOptions) -> Result<ChainConfig> {
    let ChainConfigOptions {
        chain_address_prefix,
        chain_max_future_block_time_offset,
        chain_version,
        chain_target_block_spacing,
        chain_coin_decimals,
        chain_emission_schedule,
        chain_max_block_header_size,
        chain_max_block_size_with_standard_txs,
        chain_max_block_size_with_smart_contracts,
    } = options;

    let mut builder = ChainConfigBuilder::new(ChainType::Regtest);

    macro_rules! update_builder {
        ($field: ident) => {
            update_builder!($field, std::convert::identity)
        };
        ($field: ident, $converter: stmt) => {
            paste! {
                if let Some(val) = [<chain_ $field>] {
                    builder = builder.$field($converter(val.to_owned()));
                }
            }
        };
        ($field: ident, $converter: stmt, map_err) => {
            paste! {
                if let Some(val) = [<chain_ $field>] {
                    builder = builder.$field($converter(val.to_owned()).map_err(|e| anyhow!(e))?);
                }
            }
        };
    }

    update_builder!(address_prefix);
    update_builder!(max_future_block_time_offset, Duration::from_secs);
    update_builder!(version, SemVer::try_from, map_err);
    update_builder!(target_block_spacing, Duration::from_secs);
    update_builder!(coin_decimals);
    if let Some(val) = chain_emission_schedule {
        builder =
            builder.emission_schedule_tabular(EmissionScheduleTabular::from_str(val.as_str())?);
    }
    update_builder!(max_block_header_size);
    update_builder!(max_block_size_with_standard_txs);
    update_builder!(max_block_size_with_smart_contracts);

    Ok(builder.build())
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
