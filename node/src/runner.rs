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

use std::{fs, path::Path, str::FromStr, sync::Arc, time::Duration};

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

use p2p::rpc::P2pRpcServer;

use crate::{
    config_files::NodeConfigFile,
    options::{Command, Options, RunOptions},
    regtest_options::ChainConfigOptions,
};

/// Initialize the node, giving caller the opportunity to add more subsystems before start.
pub async fn initialize(
    chain_config: ChainConfig,
    node_config: NodeConfigFile,
) -> Result<subsystem::Manager> {
    let chain_config = Arc::new(chain_config);

    // INITIALIZE SUBSYSTEMS

    let mut manager = subsystem::Manager::new("mintlayer");
    manager.install_signal_handlers();

    // Chainstate subsystem
    let chainstate = chainstate_launcher::make_chainstate(
        &node_config.datadir,
        Arc::clone(&chain_config),
        node_config.chainstate.into(),
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
    let p2p = manager.add_subsystem(
        "p2p",
        p2p::make_p2p(
            Arc::clone(&chain_config),
            Arc::new(node_config.p2p.into()),
            chainstate.clone(),
            mempool.clone(),
        )
        .await
        .expect("The p2p subsystem initialization failed"),
    );

    // Block production
    let _block_prod = manager.add_subsystem(
        "blockprod",
        blockprod::make_blockproduction(
            chain_config,
            chainstate.clone(),
            mempool.clone(),
            Default::default(),
        )
        .await?,
    );

    // RPC subsystem
    if node_config.rpc.http_enabled.unwrap_or(true) || node_config.rpc.ws_enabled.unwrap_or(true) {
        // TODO: get rid of the unwrap_or() after fixing the issue in #446
        let _rpc = manager.add_subsystem(
            "rpc",
            rpc::Builder::new(node_config.rpc.into())
                .register(crate::rpc::init(manager.make_shutdown_trigger()))
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
        Command::CreateConfig => {
            let path = options.config_path();
            let config = NodeConfigFile::new(options.data_dir())?;
            let config = toml::to_string(&config).context("Failed to serialize config")?;
            log::trace!("Saving config to {path:?}\n: {config:#?}");
            fs::write(&path, config)
                .with_context(|| format!("Failed to write config to the '{path:?}' file"))?;
            Ok(())
        }
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

async fn start(
    config_path: &Path,
    datadir_path_opt: &Option<std::path::PathBuf>,
    run_options: &RunOptions,
    chain_config: ChainConfig,
) -> Result<()> {
    let node_config = NodeConfigFile::read(config_path, datadir_path_opt, run_options)
        .context("Failed to initialize config")?;
    log::info!("Starting with the following config:\n {node_config:#?}");
    let manager = initialize(chain_config, node_config).await?;
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
