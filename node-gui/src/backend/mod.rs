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

pub mod messages;

mod backend_impl;
mod chainstate_event_handler;
mod error;
mod p2p_event_handler;
mod wallet_events;

use chainstate::ChainInfo;
use common::address::{Address, AddressError};
use common::chain::{ChainConfig, Destination};
use common::primitives::Amount;
use common::time_getter::TimeGetter;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::backend::chainstate_event_handler::ChainstateEventHandler;
use crate::backend::p2p_event_handler::P2pEventHandler;

use self::error::BackendError;
use self::messages::{BackendEvent, BackendRequest};

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

pub async fn node_initialize(_time_getter: TimeGetter) -> anyhow::Result<BackendControls> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var(
            "RUST_LOG",
            "info,wgpu_core=error,hyper=error,jsonrpsee-server=error",
        );
    }

    let opts = node_lib::Options::from_args(std::env::args_os());

    logging::init_logging();
    logging::log::info!("Command line options: {opts:?}");

    let setup_result = node_lib::setup(opts, true).await?;
    let node = match setup_result {
        node_lib::NodeSetupResult::Node(node) => node,
        node_lib::NodeSetupResult::DataDirCleanedUp => {
            // TODO: find more friendly way to report the message and shut down GUI
            anyhow::bail!(
                "Data directory is now clean. Please restart the node without `--clean-data` flag"
            );
        }
    };

    let controller = node.controller().clone();

    let manager_join_handle = tokio::spawn(async move { node.main().await });

    let (request_tx, request_rx) = unbounded_channel();
    let (event_tx, event_rx) = unbounded_channel();
    let (low_priority_event_tx, low_priority_event_rx) = unbounded_channel();
    let (wallet_updated_tx, wallet_updated_rx) = unbounded_channel();

    // Subscribe to chainstate before getting the current chain_info!
    let chainstate_event_handler =
        ChainstateEventHandler::new(controller.chainstate.clone(), event_tx.clone()).await;

    let p2p_event_handler = P2pEventHandler::new(&controller.p2p, event_tx.clone()).await;

    let chain_config =
        controller.chainstate.call(|this| Arc::clone(this.get_chain_config())).await?;
    let chain_info = controller.chainstate.call(|this| this.info()).await??;

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

    let backend = backend_impl::Backend::new(
        chain_config,
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

    Ok(backend_controls)
}
