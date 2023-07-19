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

use crate::RpcTestFunctions;
use common::chain::ChainConfig;

use super::rpc_test_interface::RpcTestFunctionsInterface;

pub struct RpcTestFunctionsImpl {
    rpc_test_functions: RpcTestFunctions,
}

impl RpcTestFunctionsImpl {
    pub fn new(rpc_test_functions: RpcTestFunctions) -> Self {
        Self { rpc_test_functions }
    }
}

#[async_trait::async_trait]
impl RpcTestFunctionsInterface for RpcTestFunctionsImpl {
    fn get_chain_config(&self) -> Option<Arc<ChainConfig>> {
        Some(Arc::clone(&self.rpc_test_functions.chain_config))
    }
}
