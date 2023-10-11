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

//! Node RPC methods

use std::{sync::Arc, time::Duration};

use chainstate_launcher::ChainConfig;
use rpc::Result as RpcResult;
use subsystem::ShutdownTrigger;

#[rpc::rpc(server, client, namespace = "node")]
pub trait NodeRpc {
    /// Order the node to shutdown
    #[method(name = "shutdown")]
    fn shutdown(&self) -> RpcResult<()>;

    /// Get node software version
    #[method(name = "version")]
    fn version(&self) -> RpcResult<String>;

    #[method(name = "set_mock_time")]
    fn set_mock_time(&self, time: u64) -> RpcResult<()>;
}

struct NodeRpc {
    shutdown_trigger: ShutdownTrigger,
    chain_config: Arc<ChainConfig>,
}

impl NodeRpc {
    fn new(shutdown_trigger: ShutdownTrigger, chain_config: Arc<ChainConfig>) -> Self {
        Self {
            shutdown_trigger,
            chain_config,
        }
    }
}

impl NodeRpcServer for NodeRpc {
    fn shutdown(&self) -> RpcResult<()> {
        // There is no easy way to gracefully shut down the jsonrpsee server to make it finish existing RPC requests first.
        // So it's possible that the current RPC call will return an error because the process is terminated before the response is sent.
        // As a workaround, shutdown is started in background with some delay.
        // TODO: This is supposedly fixed in jsonrpsee 0.17.1: https://github.com/paritytech/jsonrpsee/releases/tag/v0.17.1
        // See if we can remove this workaround since we're using that version now.
        let shutdown_trigger = self.shutdown_trigger.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            shutdown_trigger.initiate();
        });
        Ok(())
    }

    fn version(&self) -> RpcResult<String> {
        Ok(env!("CARGO_PKG_VERSION").into())
    }

    fn set_mock_time(&self, time: u64) -> RpcResult<()> {
        crate::mock_time::set_mock_time(*self.chain_config.chain_type(), time)?;
        Ok(())
    }
}

pub fn init(shutdown_trigger: ShutdownTrigger, chain_config: Arc<ChainConfig>) -> rpc::Methods {
    NodeRpc::new(shutdown_trigger, chain_config).into_rpc().into()
}
