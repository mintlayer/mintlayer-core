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
use node_lib::remote_controller::RemoteController;
use std::fmt::Debug;
use std::sync::Arc;
use subsystem::manager::ShutdownTrigger;
use tokio::sync::oneshot;

pub struct NodeController {
    chain_config: Arc<ChainConfig>,
    _controller: RemoteController,
    shutdown_trigger: ShutdownTrigger,
    manager_join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Debug for NodeController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeInitializationData")
            .field("chain_config", &self.chain_config)
            .finish()
    }
}

impl NodeController {
    pub async fn initialize() -> anyhow::Result<NodeController> {
        let (remote_controller_sender, remote_controller_receiver) = oneshot::channel();

        let opts = node_lib::Options::from_args(std::env::args_os());
        logging::init_logging::<&std::path::Path>(None);
        logging::log::info!("Command line options: {opts:?}");

        let manager = node_lib::run(opts, Some(remote_controller_sender)).await?;
        let shutdown_trigger = manager.make_shutdown_trigger();

        let controller =
            remote_controller_receiver.await.expect("Node controller receiving failed");

        let manager_join_handle = tokio::spawn(async move { manager.main().await });

        let chain_config = controller
            .chainstate
            .call(|this| this.get_chain_config().clone())
            .await
            .expect("Chain config retrieval failed after node initialization");

        let node_controller = NodeController {
            chain_config,
            _controller: controller,
            shutdown_trigger,
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
            logging::log::error!("Shutdown already requested.");
            return None;
        }
        logging::log::error!("Starting shutdown process...");

        self.shutdown_trigger.initiate();

        let mut join_handle = None;
        std::mem::swap(&mut self.manager_join_handle, &mut join_handle);

        join_handle
    }

    pub fn chain_config(&self) -> &ChainConfig {
        self.chain_config.as_ref()
    }
}
