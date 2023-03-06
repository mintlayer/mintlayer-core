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

use common::chain::config::ChainType;
use subsystem::manager::ShutdownTrigger;

#[rpc::rpc(server, namespace = "node")]
trait NodeRpc {
    /// Order the node to shutdown
    #[method(name = "shutdown")]
    fn shutdown(&self) -> rpc::Result<()>;

    /// Get node software version
    #[method(name = "version")]
    fn version(&self) -> rpc::Result<String>;

    #[method(name = "set_mock_time")]
    fn set_mock_time(&self, time: u64) -> rpc::Result<()>;
}

struct NodeRpc {
    shutdown_trigger: ShutdownTrigger,
    chain_type: ChainType,
}

impl NodeRpc {
    fn new(shutdown_trigger: ShutdownTrigger, chain_type: ChainType) -> Self {
        Self {
            shutdown_trigger,
            chain_type,
        }
    }
}

impl NodeRpcServer for NodeRpc {
    fn shutdown(&self) -> rpc::Result<()> {
        self.shutdown_trigger.initiate();
        Ok(())
    }

    fn version(&self) -> rpc::Result<String> {
        Ok(env!("CARGO_PKG_VERSION").into())
    }

    fn set_mock_time(&self, time: u64) -> rpc::Result<()> {
        crate::mock_time::set_mock_time(self.chain_type, time)?;
        Ok(())
    }
}

pub fn init(shutdown_trigger: ShutdownTrigger, chain_type: ChainType) -> rpc::Methods {
    NodeRpc::new(shutdown_trigger, chain_type).into_rpc().into()
}
