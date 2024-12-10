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

mod config;
mod detail;
mod interface;

pub mod rpc;

use std::sync::Arc;

use chainstate_interface::ChainstateInterface;
use chainstate_interface_impl::ChainstateInterfaceImpl;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use detail::{bootstrap::BootstrapError, Chainstate};
use interface::chainstate_interface_impl;

pub use crate::{
    config::{ChainstateConfig, MaxTipAge},
    detail::{
        ban_score, block_invalidation::BlockInvalidatorError, calculate_median_time_past,
        calculate_median_time_past_from_blocktimestamps, BlockError, BlockProcessingErrorClass,
        BlockProcessingErrorClassification, BlockSource, ChainInfo, CheckBlockError,
        CheckBlockTransactionsError, ConnectTransactionError, IOPolicyError, InitializationError,
        Locator, NonZeroPoolBalances, OrphanCheckError, SpendStakeError,
        StorageCompatibilityCheckError, TokenIssuanceError, TokensError,
        TransactionVerifierStorageError, MEDIAN_TIME_SPAN,
    },
};
pub use chainstate_types::{BlockIndex, GenBlockIndex, PropertyQueryError};
pub use constraints_value_accumulator;
pub use detail::tx_verification_strategy::*;
pub use interface::{chainstate_interface, chainstate_interface_impl_delegation};
pub use tx_verifier;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChainstateEvent {
    NewTip(Id<Block>, BlockHeight),
}

/// A struct that will be used to print ChainstateEvent when it becomes a part of tracing's span.
/// Here we favor compactness of the info over its precision, so ids are printed in their
/// shortened form.
pub struct ChainstateEventTracingWrapper<'a>(pub &'a ChainstateEvent);

impl std::fmt::Display for ChainstateEventTracingWrapper<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            ChainstateEvent::NewTip(id, height) => {
                write!(f, "NewTip({id}, {height})")
            }
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ChainstateError {
    #[error("Initialization error: {0}")]
    FailedToInitializeChainstate(#[from] InitializationError),
    #[error("Block processing failed: `{0}`")]
    ProcessBlockError(#[from] BlockError),
    #[error("Property read error: `{0}`")]
    FailedToReadProperty(#[from] PropertyQueryError),
    #[error("Block import error {0}")]
    BootstrapError(#[from] BootstrapError),
    #[error("Error invoking block invalidator: {0}")]
    BlockInvalidatorError(#[from] BlockInvalidatorError),
}

pub type ChainstateSubsystem = Box<dyn ChainstateInterface>;

pub type ChainstateHandle = subsystem::Handle<dyn ChainstateInterface>;

pub fn make_chainstate<S, V>(
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: S,
    tx_verification_strategy: V,
    custom_orphan_error_hook: Option<Arc<detail::OrphanErrorHandler>>,
    time_getter: TimeGetter,
) -> Result<ChainstateSubsystem, ChainstateError>
where
    S: chainstate_storage::BlockchainStorage + Sync + 'static,
    V: TransactionVerificationStrategy + Sync + 'static,
{
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
