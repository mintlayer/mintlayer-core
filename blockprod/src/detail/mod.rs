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

mod block_maker;
pub mod builder;

use std::sync::Arc;

use chainstate::ChainstateHandle;
use common::{chain::ChainConfig, time_getter::TimeGetter};
use mempool::MempoolHandle;
use tokio::sync::mpsc;

use crate::{interface::BlockProductionInterface, BlockProductionError};

use self::builder::BlockBuilderControlCommand;

#[allow(dead_code)]
pub struct BlockProduction {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    builder_tx: mpsc::UnboundedSender<BlockBuilderControlCommand>,
}

impl BlockProduction {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        builder_tx: mpsc::UnboundedSender<BlockBuilderControlCommand>,
    ) -> Result<Self, BlockProductionError> {
        let block_production = Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            builder_tx,
        };
        Ok(block_production)
    }
}

impl BlockProductionInterface for BlockProduction {
    fn stop(&self) -> Result<(), BlockProductionError> {
        self.builder_tx
            .send(BlockBuilderControlCommand::Stop)
            .map_err(|_| BlockProductionError::BlockBuilderChannelClosed)?;
        Ok(())
    }

    fn start(&self) -> Result<(), BlockProductionError> {
        self.builder_tx
            .send(BlockBuilderControlCommand::Start)
            .map_err(|_| BlockProductionError::BlockBuilderChannelClosed)?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        !self.builder_tx.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::tests::setup_blockprod_test;

    #[tokio::test]
    async fn stop() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (builder_tx, mut builder_rx) = mpsc::unbounded_channel();

        let block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            builder_tx,
        )
        .expect("Error initializing Block Builder");

        block_production.stop().expect("Error stopping Block Builder");

        let recv = timeout(Duration::from_millis(1000), builder_rx.recv());

        tokio::select! {
            msg = recv => match msg.expect("Block Builder timed out").expect("Error reading from Block Builder") {
                BlockBuilderControlCommand::Stop => {},
                _ => panic!("Invalid message received from Block Builder"),
            }
        }
    }

    #[tokio::test]
    async fn start() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (builder_tx, mut builder_rx) = mpsc::unbounded_channel();

        let block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            builder_tx,
        )
        .expect("Error initializing Block Builder");

        block_production.start().expect("Error starting Block Builder");

        let recv = timeout(Duration::from_millis(1000), builder_rx.recv());

        tokio::select! {
            msg = recv => match msg.expect("Block Builder timed out").expect("Error reading from Block Builder") {
                BlockBuilderControlCommand::Start => {},
                _ => panic!("Invalid message received from Block Builder"),
            }
        }
    }

    #[tokio::test]
    async fn is_connected() {
        let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        let (builder_tx, _builder_rx) = mpsc::unbounded_channel();

        let block_production = BlockProduction::new(
            chain_config,
            chainstate,
            mempool,
            Default::default(),
            builder_tx,
        )
        .expect("Error initializing Block Builder");

        assert!(
            block_production.is_connected(),
            "Block Builder is not connected"
        );
    }
}
