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

use chainstate_types::vrf_tools::ProofOfStakeVRFError;
use common::chain::{signature::DestinationSigError, ChainConfig};
use crypto::key::SignatureError;
use interface::{
    rpc_test_interface::RpcTestFunctionsInterface, rpc_test_interface_impl::RpcTestFunctionsImpl,
};
use subsystem::error::CallError;

pub mod empty;
mod interface;
pub mod rpc;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum RpcTestFunctionsError {
    #[error("Subsystem call error")]
    SubsystemCallError(#[from] CallError),
    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),
    #[error("Proof of stake VRF error: {0}")]
    ProofOfStakeVRFError(#[from] ProofOfStakeVRFError),
    #[error("Signature error: {0}")]
    DestSignatureError(#[from] DestinationSigError),
}

pub struct RpcTestFunctions {
    chain_config: Arc<ChainConfig>,
}

impl RpcTestFunctions {
    pub fn new(chain_config: Arc<ChainConfig>) -> Self {
        Self { chain_config }
    }
}

pub type RpcTestFunctionsSubsystem = Box<dyn RpcTestFunctionsInterface>;
pub type RpcTestFunctionsHandle = subsystem::Handle<Box<dyn RpcTestFunctionsInterface>>;

pub fn make_rpc_test_functions(chain_config: Arc<ChainConfig>) -> RpcTestFunctionsSubsystem {
    let rpc_test_functions = RpcTestFunctions::new(chain_config);
    let rpc_test_functions_interface = RpcTestFunctionsImpl::new(rpc_test_functions);
    Box::new(rpc_test_functions_interface)
}
