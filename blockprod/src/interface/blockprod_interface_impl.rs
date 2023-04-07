// Copyright (c) 2023 RBB S.r.l
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

use common::chain::{
    block::{
        calculate_tx_merkle_root, calculate_witness_merkle_root, timestamp::BlockTimestamp,
        BlockBody, BlockCreationError, BlockHeader, BlockReward,
    },
    Block, Destination, SignedTransaction,
};

use crate::{
    detail::{block_maker::BlockMaker, builder::BlockBuilderControlCommand, BlockProduction},
    BlockProductionError,
};

use super::blockprod_interface::BlockProductionInterface;

#[async_trait::async_trait]
impl BlockProductionInterface for BlockProduction {
    fn start(&self) -> Result<(), BlockProductionError> {
        self.builder_tx()
            .send(BlockBuilderControlCommand::Start)
            .map_err(|_| BlockProductionError::BlockBuilderChannelClosed)?;
        Ok(())
    }

    fn stop(&self) -> Result<(), BlockProductionError> {
        self.builder_tx()
            .send(BlockBuilderControlCommand::Stop)
            .map_err(|_| BlockProductionError::BlockBuilderChannelClosed)?;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        !self.builder_tx().is_closed()
    }

    async fn generate_block(
        &self,
        reward_destination: Destination,
        transactions: Vec<SignedTransaction>,
    ) -> Result<Block, BlockProductionError> {
        let (current_tip_id, current_tip_height) = self
            .chainstate_handle()
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
            Arc::clone(self.chain_config()),
            self.chainstate_handle().clone(),
            self.mempool_handle().clone(),
            self.time_getter().clone(),
            reward_destination,
            current_tip_id,
            current_tip_height,
            dummy_rx,
            Arc::clone(self.mining_thread_pool()),
        );

        let timestamp = BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

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

        let block_header = BlockMaker::solve_block(
            Arc::clone(self.chain_config()),
            block_header,
            current_tip_height,
            Arc::new(false.into()),
        )?;

        let block = Block::new_from_header(block_header, block_body)?;

        Ok(block)
    }
}
