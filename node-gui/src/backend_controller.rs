// Copyright (c) 2021-2023 RBB S.r.l
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
use node_lib::node_controller::NodeController;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::oneshot;

pub struct NodeBackendController {
    chain_config: Arc<ChainConfig>,
    controller: NodeController,
    manager_join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Debug for NodeBackendController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeInitializationData")
            .field("chain_config", &self.chain_config)
            .finish()
    }
}

impl NodeBackendController {
    pub async fn initialize() -> anyhow::Result<NodeBackendController> {
        let (node_controller_sender, node_controller_receiver) = oneshot::channel();

        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "info");
        }

        let opts = node_lib::Options::from_args(std::env::args_os());
        logging::init_logging::<&std::path::Path>(None);
        logging::log::info!("Command line options: {opts:?}");

        let manager = node_lib::run(opts, Some(node_controller_sender)).await?;

        let controller = node_controller_receiver.await.expect("Node controller receiving failed");

        let manager_join_handle = tokio::spawn(async move { manager.main().await });

        let chain_config = controller
            .chainstate
            .call(|this| this.get_chain_config().clone())
            .await
            .expect("Chain config retrieval failed after node initialization");

        let node_controller = NodeBackendController {
            chain_config,
            controller,
            manager_join_handle: Some(manager_join_handle),
        };

        Ok(node_controller)
    }

    /// Triggers shutdown process synchronously
    /// Returns the subsystem manager join handle ONLY ONCE.
    /// If the shutdown was already triggered, returns None.
    pub fn trigger_shutdown(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        if self.manager_join_handle.is_none() {
            // We shutdown and join only once, so this being None means we took the handle already
            logging::log::warn!("Shutdown already requested.");
            return None;
        }
        logging::log::info!("Starting shutdown process...");

        self.controller.shutdown_trigger.clone().initiate();

        let mut join_handle = None;
        std::mem::swap(&mut self.manager_join_handle, &mut join_handle);

        join_handle
    }

    pub fn chain_config(&self) -> &ChainConfig {
        self.chain_config.as_ref()
    }
}
