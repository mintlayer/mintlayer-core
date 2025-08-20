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

pub mod error;
pub mod messages;

mod account_id;
mod backend_impl;
mod chainstate_event_handler;
mod p2p_event_handler;
mod wallet_events;

use std::fmt::Debug;
use std::sync::Arc;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use chainstate::ChainInfo;
use common::{
    address::{Address, AddressError},
    chain::{ChainConfig, Destination},
    primitives::{Amount, BlockHeight},
};
use logging::log;
use node_lib::OptionsWithResolvedCommand;

use crate::{chainstate_event_handler::ChainstateEventHandler, p2p_event_handler::P2pEventHandler};

use self::{
    error::BackendError,
    messages::{BackendEvent, BackendRequest},
};

pub use account_id::AccountId;

#[derive(Debug, Clone, Copy)]
pub enum InitNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Debug, Clone, Copy)]
pub enum WalletMode {
    Cold,
    Hot,
}

#[derive(Debug)]
pub struct BackendControls {
    pub initialized_node: InitializedNode,
    pub backend_sender: BackendSender,
    pub backend_receiver: UnboundedReceiver<BackendEvent>,
    pub low_priority_backend_receiver: UnboundedReceiver<BackendEvent>,
}

/// `UnboundedSender` wrapper, used to make sure there is only one instance and it doesn't get cloned
#[derive(Debug)]
pub struct BackendSender {
    request_tx: UnboundedSender<BackendRequest>,
}

impl BackendSender {
    fn new(request_tx: UnboundedSender<BackendRequest>) -> Self {
        Self { request_tx }
    }

    pub fn send(&self, msg: BackendRequest) {
        let _ = self.request_tx.send(msg);
    }
}

fn parse_coin_amount(chain_config: &ChainConfig, value: &str) -> Option<Amount> {
    Amount::from_fixedpoint_str(value, chain_config.coin_decimals())
}

fn parse_address(
    chain_config: &ChainConfig,
    address: &str,
) -> Result<Address<Destination>, AddressError> {
    Address::from_string(chain_config, address)
}

#[derive(Debug)]
pub struct InitializedNode {
    pub chain_config: Arc<ChainConfig>,
    pub chain_info: ChainInfo,
}

#[derive(Debug)]
pub enum NodeInitializationOutcome {
    BackendControls(BackendControls),
    DataDirCleanedUp,
}

pub async fn node_initialize(
    opts: node_lib::OptionsWithResolvedCommand,
    mode: WalletMode,
) -> anyhow::Result<NodeInitializationOutcome> {
    if std::env::var("RUST_LOG").is_err() {
        // Note: wgpu_hal=error is included to prevent it from spamming warnings
        // "Unrecognized present mode 1000361000" on Windows. Note that this seems
        // to have been fixed in https://github.com/gfx-rs/wgpu/pull/7850 and
        // the fix has already been released, however our dependencies still use
        // a pretty old version of wgpu.
        std::env::set_var(
            "RUST_LOG",
            "info,wgpu_core=error,wgpu_hal=error,hyper=error,jsonrpsee-server=error",
        );
    }

    let opts = {
        let mut opts = opts;
        let run_opts = opts.command.run_options_mut();

        // For the GUI, we configure different defaults, such as disabling RPC server binding
        // and enabling logging to a file.
        run_opts.rpc_enabled = Some(run_opts.rpc_enabled.unwrap_or(false));
        opts.top_level.log_to_file = Some(opts.top_level.log_to_file.unwrap_or(true));

        opts
    };

    let (request_tx, request_rx) = unbounded_channel();
    let (event_tx, event_rx) = unbounded_channel();
    let (low_priority_event_tx, low_priority_event_rx) = unbounded_channel();
    let (wallet_updated_tx, wallet_updated_rx) = unbounded_channel();

    let (chain_config, chain_info) = match mode {
        WalletMode::Hot => {
            let setup_result = node_lib::setup(opts).await?;
            let node = match setup_result {
                node_lib::NodeSetupResult::Node(node) => node,
                node_lib::NodeSetupResult::DataDirCleanedUp => {
                    return Ok(NodeInitializationOutcome::DataDirCleanedUp);
                }
            };

            let controller = node.controller().clone();

            let manager_join_handle = tokio::spawn(async move { node.main().await });

            // Subscribe to chainstate before getting the current chain_info!
            let chainstate_event_handler =
                ChainstateEventHandler::new(controller.chainstate.clone(), event_tx.clone())
                    .await?;

            let p2p_event_handler = P2pEventHandler::new(&controller.p2p, event_tx.clone()).await?;

            let chain_config =
                controller.chainstate.call(|this| Arc::clone(this.get_chain_config())).await?;
            let chain_info = controller.chainstate.call(|this| this.info()).await??;

            let backend = backend_impl::Backend::new_hot(
                chain_config.clone(),
                event_tx,
                low_priority_event_tx,
                wallet_updated_tx,
                controller,
                manager_join_handle,
            );

            tokio::spawn(async move {
                backend_impl::run(
                    backend,
                    request_rx,
                    wallet_updated_rx,
                    chainstate_event_handler,
                    p2p_event_handler,
                )
                .await;
            });
            (chain_config, chain_info)
        }
        WalletMode::Cold => spawn_cold_backend(
            opts,
            event_tx,
            request_rx,
            low_priority_event_tx,
            wallet_updated_tx,
            wallet_updated_rx,
        )?,
    };

    let initialized_node = InitializedNode {
        chain_config: Arc::clone(&chain_config),
        chain_info,
    };

    let backend_controls = BackendControls {
        initialized_node,
        backend_sender: BackendSender::new(request_tx),
        backend_receiver: event_rx,
        low_priority_backend_receiver: low_priority_event_rx,
    };

    Ok(NodeInitializationOutcome::BackendControls(backend_controls))
}

fn spawn_cold_backend(
    options: OptionsWithResolvedCommand,
    event_tx: UnboundedSender<BackendEvent>,
    request_rx: UnboundedReceiver<BackendRequest>,
    low_priority_event_tx: UnboundedSender<BackendEvent>,
    wallet_updated_tx: UnboundedSender<messages::WalletId>,
    wallet_updated_rx: UnboundedReceiver<messages::WalletId>,
) -> anyhow::Result<(Arc<ChainConfig>, ChainInfo)> {
    logging::init_logging();

    let chain_config = Arc::new(handle_options_in_cold_wallet_mode(options)?);
    let chain_info = ChainInfo {
        best_block_id: chain_config.genesis_block_id(),
        best_block_height: BlockHeight::zero(),
        median_time: chain_config.genesis_block().timestamp(),
        best_block_timestamp: chain_config.genesis_block().timestamp(),
        is_initial_block_download: false,
    };

    let manager_join_handle = tokio::spawn(async move {});

    let backend = backend_impl::Backend::new_cold(
        chain_config.clone(),
        event_tx,
        low_priority_event_tx,
        wallet_updated_tx,
        manager_join_handle,
    );

    tokio::spawn(async move {
        backend_impl::run_cold(backend, request_rx, wallet_updated_rx).await;
    });

    Ok((chain_config, chain_info))
}

fn handle_options_in_cold_wallet_mode(
    options: OptionsWithResolvedCommand,
) -> anyhow::Result<ChainConfig> {
    if options.clean_data_option_set() {
        log::warn!("Ignoring clean-data option in cold wallet mode");
    }

    if options.log_to_file_option_set() {
        log::warn!("Log-to-file disabled in cold wallet mode");
    }

    // TODO: check all other options?

    options.command.create_chain_config()
}
