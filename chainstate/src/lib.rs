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
pub use interface::chainstate_interface;
use interface::chainstate_interface_impl;
pub use interface::chainstate_interface_impl_delegation;

pub mod rpc;

pub use crate::detail::calculate_median_time_past;
pub use crate::detail::CheckBlockError;
pub use crate::detail::CheckBlockTransactionsError;
pub use crate::detail::ConnectTransactionError;
pub use crate::detail::OrphanCheckError;
pub use crate::detail::TokensError;

pub use crate::{
    config::ChainstateConfig,
    detail::{ban_score, BlockError, BlockSource, Locator, HEADER_LIMIT},
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
    ProcessBlockError(BlockError),
    #[error("Property read error: `{0}`")]
    FailedToReadProperty(PropertyQueryError),
}

impl subsystem::Subsystem for Box<dyn ChainstateInterface> {}

type ChainstateHandle = subsystem::Handle<Box<dyn ChainstateInterface>>;

pub fn make_chainstate<S: chainstate_storage::BlockchainStorage + 'static>(
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    chainstate_storage: S,
    custom_orphan_error_hook: Option<Arc<detail::OrphanErrorHandler>>,
    time_getter: TimeGetter,
) -> Result<Box<dyn ChainstateInterface>, ChainstateError> {
    let cons = Chainstate::new(
        chain_config,
        chainstate_config,
        chainstate_storage,
        custom_orphan_error_hook,
        time_getter,
    )?;
    let cons_interface = ChainstateInterfaceImpl::new(cons);
    Ok(Box::new(cons_interface))
}
