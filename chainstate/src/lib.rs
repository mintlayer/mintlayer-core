// Copyright (c) 2021-2022 RBB S.r.l
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

mod interface;
use detail::bootstrap::BootstrapError;
pub use detail::tx_verification_strategy::*;
pub use interface::chainstate_interface;
use interface::chainstate_interface_impl;
pub use interface::chainstate_interface_impl_delegation;

pub mod rpc;

pub use crate::{
    config::ChainstateConfig,
    detail::{
        ban_score, calculate_median_time_past, is_rfc3986_valid_symbol, BlockError, BlockSource,
        CheckBlockError, CheckBlockTransactionsError, ConnectTransactionError, InitializationError,
        Locator, OrphanCheckError, PoSError, TokensError, TransactionVerifierStorageError,
        TxIndexError,
    },
};

mod config;
mod detail;

use std::sync::Arc;

pub use chainstate_types::PropertyQueryError;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
};

use chainstate_interface::ChainstateInterface;
use chainstate_interface_impl::ChainstateInterfaceImpl;
use common::time_getter::TimeGetter;
use detail::Chainstate;

#[derive(Debug, Clone)]
pub enum ChainstateEvent {
    NewTip(Id<Block>, BlockHeight),
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ChainstateError {
    #[error("Initialization error: {0}")]
    FailedToInitializeChainstate(#[from] InitializationError),
    #[error("Block processing failed: `{0}`")]
    ProcessBlockError(#[from] BlockError),
    #[error("Property read error: `{0}`")]
    FailedToReadProperty(#[from] PropertyQueryError),
    #[error("Block import error {0}")]
    BootstrapError(#[from] BootstrapError),
}

impl subsystem::Subsystem for Box<dyn ChainstateInterface> {}

pub type ChainstateHandle = subsystem::Handle<Box<dyn ChainstateInterface>>;

pub fn make_chainstate<
    S: chainstate_storage::BlockchainStorage + 'static,
    V: TransactionVerificationStrategy + 'static,
>(
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: S,
    tx_verification_strategy: V,
    custom_orphan_error_hook: Option<Arc<detail::OrphanErrorHandler>>,
    time_getter: TimeGetter,
) -> Result<Box<dyn ChainstateInterface>, ChainstateError> {
    let chainstate = Chainstate::new(
        chain_config,
        chainstate_config,
        chainstate_storage,
        tx_verification_strategy,
        custom_orphan_error_hook,
        time_getter,
    )?;
    let chainstate_interface = ChainstateInterfaceImpl::new(chainstate);
    Ok(Box::new(chainstate_interface))
}
