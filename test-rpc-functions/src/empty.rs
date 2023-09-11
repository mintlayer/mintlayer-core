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

use std::sync::Arc;

use crate::interface::rpc_test_interface::RpcTestFunctionsInterface;
use common::chain::ChainConfig;

// Empty implementation to exclude test functions under certain conditions, such as mainnet
pub struct EmptyRpcTestFunctionsRpc;

impl EmptyRpcTestFunctionsRpc {
    pub fn new() -> Self {
        Self {}
    }
}

impl From<EmptyRpcTestFunctionsRpc> for rpc::Methods {
    fn from(_: EmptyRpcTestFunctionsRpc) -> Self {
        rpc::Methods::new()
    }
}

pub fn make_empty_rpc_test_functions() -> super::RpcTestFunctionsSubsystem {
    let subsys = EmptyRpcTestFunctionsRpc::new();
    Box::new(subsys)
}

impl RpcTestFunctionsInterface for EmptyRpcTestFunctionsRpc {
    fn get_chain_config(&self) -> Option<Arc<ChainConfig>> {
        None
    }
}
