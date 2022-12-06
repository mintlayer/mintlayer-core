// Copyright (c) 2022 RBB S.r.l
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

#![deny(clippy::clone_on_ref_ptr)]

use std::sync::Arc;

use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{Block, ChainConfig},
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
pub use interface::mempool_interface::MempoolInterface;

use crate::{
    error::Error as MempoolError, get_memory_usage::GetMemoryUsage,
    interface::mempool_interface_impl::MempoolInterfaceImpl,
};

pub use crate::get_memory_usage::SystemUsageEstimator;

mod config;
pub mod error;
mod get_memory_usage;
mod interface;
mod pool;
pub mod rpc;
pub mod tx_accumulator;

#[derive(Debug, Clone)]
pub enum MempoolEvent {
    NewTip(Id<Block>, BlockHeight),
}

pub type MempoolHandle = subsystem::Handle<dyn MempoolInterface>;

pub type Result<T> = core::result::Result<T, MempoolError>;

pub fn make_mempool<M>(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    memory_usage_estimator: M,
) -> MempoolInterfaceImpl<M>
where
    M: GetMemoryUsage + 'static + Send + Sync,
{
    MempoolInterfaceImpl::new(
        chain_config,
        chainstate_handle,
        time_getter,
        memory_usage_estimator,
    )
}
