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

use pool::MempoolInterface;

use crate::config::GetMemoryUsage;
use crate::config::GetTime;
use crate::error::Error as MempoolError;
use crate::pool::ChainState;
use crate::pool::Mempool;

mod config;
pub mod error;
mod feerate;
pub mod pool;
pub mod rpc;

impl<C: 'static> subsystem::Subsystem for Box<dyn MempoolInterface<C>> {}

#[allow(dead_code)]
type MempoolHandle<C> = subsystem::Handle<Box<dyn MempoolInterface<C>>>;

pub type Result<T> = core::result::Result<T, MempoolError>;

#[derive(Debug)]
pub struct DummyMempoolChainState;

impl ChainState for DummyMempoolChainState {
    fn contains_outpoint(&self, _outpoint: &common::chain::OutPoint) -> bool {
        false
    }
    fn get_outpoint_value(
        &self,
        _outpoint: &common::chain::OutPoint,
    ) -> core::result::Result<common::primitives::Amount, anyhow::Error> {
        Err(anyhow::Error::msg("this is a dummy placeholder chainstate"))
    }
}

pub fn make_mempool<C, T, M, H>(
    chainstate: C,
    chainstate_handle: H,
    time_getter: T,
    memory_usage_estimator: M,
) -> crate::Result<Box<dyn MempoolInterface<C>>>
where
    C: ChainState + 'static + Send,
    H: 'static + Send,
    T: GetTime + 'static + Send,
    M: GetMemoryUsage + 'static + Send,
{
    Ok(Box::new(Mempool::new(
        chainstate,
        chainstate_handle,
        time_getter,
        memory_usage_estimator,
    )))
}
