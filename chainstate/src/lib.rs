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
    config::{ChainstateAndStorageConfig, ChainstateConfig, StorageBackend},
    detail::{
        ban_score, calculate_median_time_past, is_rfc3986_valid_symbol, BlockError, BlockSource,
        CheckBlockError, CheckBlockTransactionsError, ConnectTransactionError, Locator,
        OrphanCheckError, TokensError, TransactionVerifierStorageError, TxIndexError, HEADER_LIMIT,
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
    #[error("Initialization error")]
    FailedToInitializeChainstate(String),
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
    let cons = Chainstate::new(
        chain_config,
        chainstate_config,
        chainstate_storage,
        tx_verification_strategy,
        custom_orphan_error_hook,
        time_getter,
    )?;
    let cons_interface = ChainstateInterfaceImpl::new(cons);
    Ok(Box::new(cons_interface))
}

fn make_chainstate_and_storage_impl<B: 'static + storage::Backend>(
    storage_backend: B,
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
) -> Result<Box<dyn ChainstateInterface>, ChainstateError> {
    let storage = chainstate_storage::Store::new(storage_backend)
        .map_err(|e| ChainstateError::FailedToInitializeChainstate(e.to_string()))?;
    let chainstate = make_chainstate(
        chain_config,
        chainstate_config,
        storage,
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )?;
    Ok(chainstate)
}

pub fn make_chainstate_and_storage(
    datadir: &std::path::Path,
    chain_config: Arc<ChainConfig>,
    chainstate_and_storage_config: ChainstateAndStorageConfig,
) -> Result<Box<dyn ChainstateInterface>, ChainstateError> {
    let ChainstateAndStorageConfig {
        storage_backend,
        chainstate_config,
    } = chainstate_and_storage_config;

    let chainstate = match storage_backend {
        StorageBackend::Lmdb => {
            let storage = storage_lmdb::Lmdb::new(datadir.join("chainstate-lmdb"));
            make_chainstate_and_storage_impl(storage, chain_config, chainstate_config)?
        }
        StorageBackend::InMemory => {
            let storage = storage_inmemory::InMemory::new();
            make_chainstate_and_storage_impl(storage, chain_config, chainstate_config)?
        }
    };
    Ok(chainstate)
}
