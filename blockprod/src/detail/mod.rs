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
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, timestamp::BlockTimestamp,
            BlockBody, BlockCreationError, BlockHeader, BlockReward,
        },
        Block, ChainConfig, Destination, SignedTransaction,
    },
    time_getter::TimeGetter,
};
use mempool::MempoolHandle;
use tokio::sync::mpsc;

use crate::{
    detail::block_maker::BlockMaker, interface::BlockProductionInterface, BlockProductionError,
};

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

#[async_trait::async_trait]
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

    async fn generate_block(
        &self,
        reward_destination: Destination,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Block, BlockProductionError> {
        let (current_tip_id, current_tip_height) = self
            .chainstate_handle
            .call(|this| {
                if let Ok(current_tip_id) = this.get_best_block_id() {
                    if let Ok(Some(current_tip_height)) =
                        this.get_block_height_in_main_chain(&current_tip_id)
                    {
                        return Some((current_tip_id, current_tip_height));
                    }
                }

                None
            })
            .await?
            .ok_or(BlockProductionError::FailedToConstructBlock(
                BlockCreationError::CurrentTipRetrievalError,
            ))?;

        let (_tx, dummy_rx) = crossbeam_channel::unbounded();

        let block_maker = BlockMaker::new(
            self.chain_config.clone(),
            self.chainstate_handle.clone(),
            self.mempool_handle.clone(),
            self.time_getter.clone(),
            reward_destination,
            current_tip_id,
            current_tip_height,
            dummy_rx,
        );

        let timestamp = BlockTimestamp::from_duration_since_epoch(self.time_getter.get_time());

        let consensus_data = block_maker.pull_consensus_data(current_tip_id, timestamp).await?;

        let block_reward = BlockReward::new(vec![]);

        let block_body = BlockBody::new(block_reward, transactions.clone());

        let tx_merkle_root =
            calculate_tx_merkle_root(&block_body).map_err(BlockCreationError::MerkleTreeError)?;
        let witness_merkle_root = calculate_witness_merkle_root(&block_body)
            .map_err(BlockCreationError::MerkleTreeError)?;

        let block_header = BlockHeader::new(
            current_tip_id,
            tx_merkle_root,
            witness_merkle_root,
            timestamp,
            consensus_data,
        );

        let block_header = block_maker.solve_block(block_header, Arc::new(false.into()))?;

        let block = Block::new_from_header(block_header, block_body)?;

        Ok(block)
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
