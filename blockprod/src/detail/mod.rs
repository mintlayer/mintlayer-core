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

pub mod block_maker;
pub mod builder;

use std::sync::{atomic::AtomicBool, Arc};

use chainstate::{ChainstateHandle, PropertyQueryError};
use chainstate_types::{BlockIndex, GenBlockIndex, GetAncestorError};
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, timestamp::BlockTimestamp,
            BlockBody, BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, Destination, SignedTransaction,
    },
    primitives::{BlockHeight, Idable},
    time_getter::TimeGetter,
};
use futures::channel::oneshot;
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};
use tokio::sync::mpsc;
use utils::tap_error_log::LogError;

use crate::BlockProductionError;

use self::builder::BlockBuilderControlCommand;

#[derive(Debug, Clone)]
pub enum TransactionsSource {
    Mempool,
    Provided(Vec<SignedTransaction>),
}

#[must_use]
enum BlockSubmitResult {
    Failed,
    Success,
}

#[allow(dead_code)]
pub struct BlockProduction {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    builder_tx: mpsc::UnboundedSender<BlockBuilderControlCommand>,
    // running_miners: BTreeMap<>, // TODO(PR)
    mining_thread_pool: Arc<slave_pool::ThreadPool>,
}

impl BlockProduction {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        builder_tx: mpsc::UnboundedSender<BlockBuilderControlCommand>,
        mining_thread_pool: Arc<slave_pool::ThreadPool>,
    ) -> Result<Self, BlockProductionError> {
        let block_production = Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            builder_tx,
            mining_thread_pool,
        };
        Ok(block_production)
    }

    pub fn time_getter(&self) -> &TimeGetter {
        &self.time_getter
    }

    pub fn builder_tx(&self) -> &mpsc::UnboundedSender<BlockBuilderControlCommand> {
        &self.builder_tx
    }

    pub async fn collect_transactions(
        &self,
    ) -> Result<Box<dyn TransactionAccumulator>, BlockProductionError> {
        let max_block_size = self.chain_config.max_block_size_from_txs();
        let returned_accumulator = self
            .mempool_handle
            .call_async(move |mempool| {
                mempool.collect_txs(Box::new(DefaultTxAccumulator::new(max_block_size)))
            })
            .await?
            .map_err(|_| BlockProductionError::MempoolChannelClosed)?;
        Ok(returned_accumulator)
    }

    async fn pull_consensus_data(
        &self,
        block_timestamp: BlockTimestamp,
    ) -> Result<(ConsensusData, GenBlockIndex), BlockProductionError> {
        let consensus_data = self
            .chainstate_handle
            .call({
                let chain_config = Arc::clone(&self.chain_config);

                move |this| {
                    let best_block_index = this
                        .get_best_block_index()
                        .expect("Best block index retrieval failed in block production");

                    let get_ancestor = |block_index: &BlockIndex, ancestor_height: BlockHeight| {
                        this.get_ancestor(
                            &block_index.clone().into_gen_block_index(),
                            ancestor_height,
                        )
                        .map_err(|_| {
                            PropertyQueryError::GetAncestorError(
                                GetAncestorError::InvalidAncestorHeight {
                                    block_height: block_index.block_height(),
                                    ancestor_height,
                                },
                            )
                        })
                    };

                    let consensus_data = consensus::generate_consensus_data(
                        &chain_config,
                        &best_block_index,
                        block_timestamp,
                        best_block_index.block_height().next_height(),
                        get_ancestor,
                    );
                    consensus_data.map(|cons_data| (cons_data, best_block_index))
                }
            })
            .await?
            .map_err(BlockProductionError::FailedConsensusInitialization)?;

        Ok(consensus_data)
    }

    fn solve_block(
        chain_config: Arc<ChainConfig>,
        mut block_header: BlockHeader,
        current_tip_height: BlockHeight,
        stop_flag: Arc<AtomicBool>,
    ) -> Result<BlockHeader, BlockProductionError> {
        // TODO: use a separate executor for this loop to avoid starving tokio tasks
        consensus::finalize_consensus_data(
            &chain_config,
            &mut block_header,
            current_tip_height,
            stop_flag,
        )?;

        Ok(block_header)
    }

    async fn attempt_submit_new_block(
        &mut self,
        block: Block,
        current_tip_index: &GenBlockIndex,
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
                "Success in submitting block {} at height {}. Exiting Block Maker at tip {} and height {}",
                block_id,
                current_tip_index.block_height().next_height(),
                current_tip_index.block_id(),
                current_tip_index.block_height()
            );
                return Ok(BlockSubmitResult::Success);
            }
        }

        Ok(BlockSubmitResult::Failed)
    }

    pub async fn generate_block(
        &mut self,
        _reward_destination: Destination,
        transactions_source: TransactionsSource,
        submit_block_to_chainstate: bool,
    ) -> Result<Block, BlockProductionError> {
        let stop_flag = Arc::new(false.into());

        loop {
            let timestamp =
                BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

            let (consensus_data, current_tip_index) = self.pull_consensus_data(timestamp).await?;

            // TODO: instead of the following static value, look at
            // self.chain_config for the current block reward, then send
            // it to self.reward_destination
            let block_reward = BlockReward::new(vec![]);

            // TODO: see if we can simplify this
            let transactions = match transactions_source.clone() {
                TransactionsSource::Mempool => {
                    self.collect_transactions().await?.transactions().clone()
                }
                TransactionsSource::Provided(txs) => txs,
            };

            let block_body = BlockBody::new(block_reward, transactions);

            let tx_merkle_root = calculate_tx_merkle_root(&block_body)
                .map_err(BlockCreationError::MerkleTreeError)?;
            let witness_merkle_root = calculate_witness_merkle_root(&block_body)
                .map_err(BlockCreationError::MerkleTreeError)?;

            let block_header = BlockHeader::new(
                current_tip_index.block_id(),
                tx_merkle_root,
                witness_merkle_root,
                timestamp,
                consensus_data,
            );

            // TODO: find a way to use a oneshot channel. It doesn't seem to be supported in crossbeam.
            let (result_sender, mut result_receiver) = oneshot::channel();
            {
                let chain_config = Arc::clone(&self.chain_config);
                let current_tip_height = current_tip_index.block_height();
                let stop_flag = Arc::clone(&stop_flag);
                self.mining_thread_pool.spawn(move || {
                    let block_header = Self::solve_block(
                        chain_config,
                        block_header,
                        current_tip_height,
                        stop_flag,
                    );
                    result_sender
                        .send(block_header)
                        .expect("Failed to send block header back to main thread");
                });
            }

            tokio::select! {
                // TODO(PR): receive a signal from BlockProduction to stop if there's a new block
                solve_receive_result = &mut result_receiver => {
                    let mining_result = match solve_receive_result {
                        Ok(mining_result) => mining_result,
                        Err(_) => {
                            log::error!("Mining thread pool channel lost on tip {} on best height {}", current_tip_index.block_id(), current_tip_index.block_height());
                            continue;
                        }
                    };
                    let block_header = match mining_result {
                        Ok(header) => header,
                        Err(e) => {
                            log::error!("Solving block in thread-pool returned an error on tip {} on best height {}: {e}", current_tip_index.block_id(), current_tip_index.block_height());
                            continue;
                        }
                    };
                    let block = Block::new_from_header(block_header, block_body.clone())?;

                    // If we successfully have found a block, attempt to submit it to chainstate
                    // TODO(PR): The block should either be submitted or returned to the caller; create another function to wrap the one that returns the block and submit it in there
                    if submit_block_to_chainstate {
                        match self.attempt_submit_new_block(block.clone(), &current_tip_index).await? {
                            BlockSubmitResult::Failed => (), // try again in next iteration
                            BlockSubmitResult::Success => return Ok(block),
                        }
                    } else {
                        return Ok(block);
                    }

                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::{
        interface::blockprod_interface::BlockProductionInterface, prepare_thread_pool,
        tests::setup_blockprod_test,
    };

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
            prepare_thread_pool(1),
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
            prepare_thread_pool(1),
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
            prepare_thread_pool(1),
        )
        .expect("Error initializing Block Builder");

        assert!(
            block_production.is_connected(),
            "Block Builder is not connected"
        );
    }
}
