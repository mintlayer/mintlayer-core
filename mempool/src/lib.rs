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
use common::chain::ChainConfig;
use common::time_getter::TimeGetter;
use pool::MempoolInterface;

use crate::config::GetMemoryUsage;
use crate::error::Error as MempoolError;
use crate::pool::Mempool;

mod config;
pub mod error;
mod fee_rate;
pub mod pool;
pub mod rpc;

impl subsystem::Subsystem for Box<dyn MempoolInterface> {}

type MempoolHandle = subsystem::Handle<Box<dyn MempoolInterface>>;

pub type Result<T> = core::result::Result<T, MempoolError>;

pub fn make_mempool<M>(
    chain_config: Arc<ChainConfig>,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    time_getter: TimeGetter,
    memory_usage_estimator: M,
) -> crate::Result<Box<dyn MempoolInterface>>
where
    M: GetMemoryUsage + 'static + Send + std::marker::Sync,
{
    Ok(Box::new(Mempool::new(
        chain_config,
        chainstate_handle,
        time_getter,
        memory_usage_estimator,
    )))
}
