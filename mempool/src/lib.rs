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
use common::chain::{Block, ChainConfig};
use common::primitives::{BlockHeight, Id};
use common::time_getter::TimeGetter;
pub use interface::MempoolInterface;

use crate::config::GetMemoryUsage;
use crate::error::Error as MempoolError;
use crate::pool::Mempool;
use crate::pool::MempoolInterfaceHandle;

pub use crate::pool::SystemClock;
pub use crate::pool::SystemUsageEstimator;

mod config;
pub mod error;
mod feerate;
mod interface;
mod pool;
pub mod rpc;
pub mod tx_accumulator;

#[derive(Debug, Clone)]
pub enum MempoolEvent {
    NewTip(Id<Block>, BlockHeight),
}

impl subsystem::Subsystem for Box<dyn MempoolInterface> {}

pub type MempoolHandle = subsystem::Handle<Box<dyn MempoolInterface>>;

pub type Result<T> = core::result::Result<T, MempoolError>;

pub async fn make_mempool<M>(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    memory_usage_estimator: M,
) -> crate::Result<Box<dyn MempoolInterface>>
where
    M: GetMemoryUsage + 'static + Send + std::marker::Sync,
{
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

    Mempool::new(
        chain_config,
        chainstate_handle,
        time_getter,
        memory_usage_estimator,
        receiver,
    )
    .run()
    .await?;

    Ok(Box::new(MempoolInterfaceHandle::new(sender)))
}
