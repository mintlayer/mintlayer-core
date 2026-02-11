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

use std::{path::Path, sync::Arc};

use tokio::sync::watch;

use chainstate_interface::ChainstateInterface;
use chainstate_interface_impl::ChainstateInterfaceImpl;
use common::{
    chain::{Block, ChainConfig, GenBlock},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use detail::Chainstate;
use interface::chainstate_interface_impl;
use utils::set_flag::SetFlag;

pub use crate::{
    config::{ChainstateConfig, MaxTipAge},
    detail::{
        ban_score, block_invalidation::BlockInvalidatorError, bootstrap::BootstrapError,
        calculate_median_time_past, calculate_median_time_past_from_blocktimestamps, BlockError,
        BlockProcessingErrorClass, BlockProcessingErrorClassification, BlockSource, ChainInfo,
        CheckBlockError, CheckBlockTransactionsError, ConnectTransactionError, IOPolicyError,
        InitializationError, Locator, NonZeroPoolBalances, OrphanCheckError, SpendStakeError,
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
    NewTip {
        id: Id<GenBlock>,
        height: BlockHeight,
        is_initial_block_download: bool,
    },
}

/// A struct that will be used to print ChainstateEvent when it becomes a part of tracing's span.
/// Here we favor compactness of the info over its precision, so ids are printed in their
/// shortened form.
pub struct ChainstateEventTracingWrapper<'a>(pub &'a ChainstateEvent);

impl std::fmt::Display for ChainstateEventTracingWrapper<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            ChainstateEvent::NewTip {
                id: block_id,
                height: block_height,
                is_initial_block_download,
            } => {
                write!(
                    f,
                    "NewTip({block_id}, {block_height}, ibd={is_initial_block_download})"
                )
            }
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ChainstateError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),

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

    #[error("I/O error: {0}")]
    IoError(String),
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
    shutdown_initiated_rx: Option<watch::Receiver<SetFlag>>,
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
        shutdown_initiated_rx,
    )?;
    let chainstate_interface = ChainstateInterfaceImpl::new(chainstate);
    Ok(Box::new(chainstate_interface))
}

pub fn export_bootstrap_file<CS: ChainstateInterface + ?Sized>(
    chainsate: &CS,
    file_path: &Path,
    include_stale_blocks: bool,
) -> Result<(), ChainstateError> {
    let file_obj = std::fs::File::create(file_path)
        .map_err(|err| ChainstateError::IoError(err.to_string()))?;
    let writer: std::io::BufWriter<Box<dyn std::io::Write + Send>> =
        std::io::BufWriter::new(Box::new(file_obj));

    chainsate.export_bootstrap_stream(writer, include_stale_blocks)
}

pub fn import_bootstrap_file<CS: ChainstateInterface + ?Sized>(
    chainsate: &mut CS,
    file_path: &Path,
) -> Result<(), ChainstateError> {
    let file_obj =
        std::fs::File::open(file_path).map_err(|err| ChainstateError::IoError(err.to_string()))?;
    let reader: std::io::BufReader<Box<dyn std::io::Read + Send>> =
        std::io::BufReader::new(Box::new(file_obj));

    chainsate.import_bootstrap_stream(reader)
}
