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
use common::{
    chain::{block::BlockCreationError, ChainConfig},
    time_getter::TimeGetter,
};
use detail::{builder::PerpetualBlockBuilder, BlockProduction};
use interface::BlockProductionInterface;
use mempool::MempoolHandle;
use subsystem::subsystem::CallError;
use tokio::sync::mpsc;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum BlockProductionError {
    #[error("Initialization error")]
    FailedToInitializeBlockProduction(String),
    #[error("Mempool channel closed")]
    MempoolChannelClosed,
    #[error("Chainstate channel closed")]
    ChainstateChannelClosed,
    #[error("Block builder command channel closed")]
    BlockBuilderChannelClosed,
    #[error("Subsystem call error")]
    SubsystemCallError(#[from] CallError),
    #[error("Block creation error: {0}")]
    FailedToConstructBlock(#[from] BlockCreationError),
}

mod detail;
pub mod interface;

impl subsystem::Subsystem for Box<dyn BlockProductionInterface> {}

pub type BlockProductionHandle = subsystem::Handle<Box<dyn BlockProductionInterface>>;

pub async fn make_blockproduction(
    chain_config: Arc<ChainConfig>,
    // blockprod_config: BlockProductionConfig,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
) -> Result<Box<dyn BlockProductionInterface>, BlockProductionError> {
    let (tx_builder, rx_builder) = mpsc::unbounded_channel();

    {
        let chain_config = Arc::clone(&chain_config);
        let chainstate_handle = chainstate_handle.clone();
        let mempool_handle = mempool_handle.clone();
        let time_getter = time_getter.clone();
        tokio::spawn(async move {
            PerpetualBlockBuilder::new(
                chain_config,
                chainstate_handle,
                mempool_handle,
                time_getter,
                rx_builder,
                true, // TODO: take this from BlockProductionConfig
            )
            .run()
            .await
        });
    }

    let result = BlockProduction::new(
        chain_config,
        chainstate_handle,
        mempool_handle,
        time_getter,
        tx_builder,
    )?;

    Ok(Box::new(result))
}
