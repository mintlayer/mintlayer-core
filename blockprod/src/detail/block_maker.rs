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
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward},
        Block, ChainConfig,
    },
    primitives::{BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};
use utils::tap_error_log::LogError;

use crate::BlockProductionError;

pub enum BlockMakerControlCommand {
    StopBecauseNewTip(Id<Block>, BlockHeight),
    JustStop,
}

/// Slave to the PerpetualBlockBuilder. Every new block tip gets one BlockMaker, and keeps running
/// until either it's successful in submitting a block, or there's a new tip in chainstate, deeming
/// the effort pointless
pub struct BlockMaker {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    current_tip_id: Id<Block>,
    current_tip_height: BlockHeight,
    block_maker_rx: crossbeam_channel::Receiver<BlockMakerControlCommand>,
}

enum BlockSubmitResult {
    Failed,
    Success,
}

impl BlockMaker {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        current_tip_id: Id<Block>,
        current_tip_height: BlockHeight,
        block_maker_rx: crossbeam_channel::Receiver<BlockMakerControlCommand>,
    ) -> Self {
        Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            current_tip_id,
            current_tip_height,
            block_maker_rx,
        }
    }

    pub async fn collect_transactions(
        &self,
    ) -> Result<Box<dyn TransactionAccumulator>, BlockProductionError> {
        let max_block_size = self.chain_config.max_block_size_from_txs();
        let returned_accumulator = self
            .mempool_handle
            .call(move |mempool| {
                mempool.collect_txs(Box::new(DefaultTxAccumulator::new(max_block_size)))
            })
            .await?;
        Ok(returned_accumulator)
    }

    pub fn make_block(
        &self,
        current_tip_id: Id<Block>,
        accumulator: &dyn TransactionAccumulator,
    ) -> Result<Block, BlockProductionError> {
        // TODO: this isn't efficient. We have to create the header first, then see if it obeys consensus rules, then construct the full block
        let current_time = self.time_getter.get_time();
        let block = Block::new(
            accumulator.txs().clone(),
            current_tip_id.into(),
            BlockTimestamp::from_duration_since_epoch(current_time),
            common::chain::block::ConsensusData::None,
            BlockReward::new(vec![]), // TODO: define consensus and rewards through NetworkUpgrades
        )?;
        Ok(block)
    }

    async fn attempt_submit_new_block(
        &mut self,
        block: Block,
    ) -> Result<BlockSubmitResult, BlockProductionError> {
        let block_check_result = self
            .chainstate_handle
            .call(|chainstate| chainstate.preliminary_block_check(block))
            .await
            .log_err()?;
        if let Ok(block) = block_check_result {
            let block_id = block.get_id();
            let block_submit_result = self
                .chainstate_handle
                .call_mut(|chainstate| {
                    chainstate.process_block(block, chainstate::BlockSource::Local)
                })
                .await
                .log_err()?;
            if let Ok(_new_block_index) = block_submit_result {
                log::info!(
                "Success in submitting block {} at height {}. Exiting block maker at tip {} and height {}",
                block_id,
                self.current_tip_height.next_height(),
                self.current_tip_id,
                self.current_tip_height
            );
                return Ok(BlockSubmitResult::Success);
            }
        }

        Ok(BlockSubmitResult::Failed)
    }

    /// Keeps trying to construct a new block, until one of two things happen:
    /// 1. A new block is successfully created and is submitted to chainstate
    /// 2. A new tip is now on chainstate, indicating that there's no point in continuing to mine/stake at that tip
    pub async fn run(&mut self) -> Result<(), BlockProductionError> {
        let accumulator = self.collect_transactions().await?;

        loop {
            let block = self.make_block(self.current_tip_id, &*accumulator)?;

            match self.attempt_submit_new_block(block).await? {
                BlockSubmitResult::Failed => (),
                BlockSubmitResult::Success => break,
            }

            // attempt to receive new commands from the perpetual builder
            let new_info = match self.block_maker_rx.try_recv() {
                Ok(cmd) => cmd,
                Err(e) => match e {
                    // if there's nothing from the channel, then we can keep trying to build the block
                    crossbeam_channel::TryRecvError::Empty => continue,
                    // if the channel is lost, that means the perpetual builder is destroyed.
                    // No point in continuing since it seems that the node exited.
                    crossbeam_channel::TryRecvError::Disconnected => {
                        log::error!("Block maker control channel lost. Exiting maker task on tip {} on best height {}", self.current_tip_id, self.current_tip_height);
                        break;
                    }
                },
            };

            match new_info {
                BlockMakerControlCommand::StopBecauseNewTip(block_id, _) => {
                    // if there is a new tip, no point in continuing to mine this block
                    if block_id != self.current_tip_id {
                        break;
                    }
                }
                BlockMakerControlCommand::JustStop => break,
            }
        }
        Ok(())
    }
}
