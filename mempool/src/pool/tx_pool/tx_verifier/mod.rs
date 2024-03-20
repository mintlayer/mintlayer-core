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
mod utxo_view;

use std::sync::Arc;

pub use chainstate::tx_verifier::flush_to_storage;
use common::chain::ChainConfig;
use utils::shallow_clone::ShallowClone;

pub use chainstate_handle::ChainstateHandle;
pub use utxo_view::MempoolUtxoView;

use super::TxPool;

/// Mempool instantiation of [chainstate::tx_verifier::TransactionVerifier]
pub type TransactionVerifier = chainstate::tx_verifier::TransactionVerifier<
    Arc<ChainConfig>,
    ChainstateHandle,
    ChainstateHandle,
    ChainstateHandle,
    ChainstateHandle,
>;

/// Make a new transaction verifier
pub fn create(
    chain_config: Arc<ChainConfig>,
    chainstate: chainstate::ChainstateHandle,
) -> TransactionVerifier {
    let chainstate = chainstate_handle::ChainstateHandle::new(chainstate);
    chainstate::tx_verifier::TransactionVerifier::new_generic(
        chainstate.shallow_clone(),
        chain_config,
        chainstate.shallow_clone(),
        chainstate.shallow_clone(),
        chainstate,
    )
}
