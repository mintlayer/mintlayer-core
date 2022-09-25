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

use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{chain::ChainConfig, time_getter::TimeGetter};
use detail::BlockProduction;
use interface::BlockProductionInterface;
use mempool::MempoolHandle;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockProductionError {
    #[error("Initialization error")]
    FailedToInitializeBlockProduction(String),
}

mod detail;
pub mod interface;

impl subsystem::Subsystem for Box<dyn BlockProductionInterface> {}

#[allow(dead_code)]
pub type BlockProductionHandle = subsystem::Handle<Box<dyn BlockProductionInterface>>;

pub fn make_blockproduction(
    _chain_config: Arc<ChainConfig>,
    // blockprod_config: BlockProductionConfig,
    _chainstate_handle: ChainstateHandle,
    _mempool_handle: MempoolHandle,
    _time_getter: TimeGetter,
) -> Result<Box<dyn BlockProductionInterface>, BlockProductionError> {
    Ok(Box::new(BlockProduction::new()))
}
