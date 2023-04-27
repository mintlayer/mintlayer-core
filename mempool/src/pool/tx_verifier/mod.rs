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

//! Transaction verifier adapted to mempool

mod chainstate_handle;

use std::sync::Arc;

pub use chainstate::{tx_verifier::flush_to_storage, ConnectTransactionError};
use common::chain::ChainConfig;
use utils::shallow_clone::ShallowClone;

use chainstate_handle::{Chainstate, ChainstateHandle};

/// Mempool instantiation of [chainstate::tx_verifier::TransactionVerifier]
pub type TransactionVerifier = chainstate::tx_verifier::TransactionVerifier<
    Arc<ChainConfig>,
    ChainstateHandle,
    ChainstateHandle,
    ChainstateHandle,
>;

/// Make a new transaction verifier
pub fn create(
    chain_config: Arc<ChainConfig>,
    chainstate: subsystem::Handle<Chainstate>,
) -> Result<TransactionVerifier, ConnectTransactionError> {
    let verifier_config = chainstate::tx_verifier::TransactionVerifierConfig::new(false);
    let chainstate = ChainstateHandle::new(chainstate);
    TransactionVerifier::new_generic(
        chainstate.shallow_clone(),
        chain_config,
        chainstate.shallow_clone(),
        chainstate,
        verifier_config,
    )
}
