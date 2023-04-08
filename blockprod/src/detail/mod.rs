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

use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicBool, Arc},
};

use chainstate::{ChainstateHandle, PropertyQueryError};
use chainstate_types::{BlockIndex, GenBlockIndex, GetAncestorError};
use common::{
    chain::{
        block::{
            calculate_tx_merkle_root, calculate_witness_merkle_root, timestamp::BlockTimestamp,
            BlockBody, BlockCreationError, BlockHeader, BlockReward, ConsensusData,
        },
        Block, ChainConfig, Destination, GenBlock, SignedTransaction,
    },
    primitives::{BlockHeight, Id},
    time_getter::TimeGetter,
};
use futures::channel::oneshot;
use logging::log;
use mempool::{
    tx_accumulator::{DefaultTxAccumulator, TransactionAccumulator},
    MempoolHandle,
};
use serialization::{Decode, Encode};

use crate::BlockProductionError;

#[derive(Debug, Clone)]
pub enum TransactionsSource {
    Mempool,
    Provided(Vec<SignedTransaction>),
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct JobKey {
    current_tip: Id<GenBlock>,
    // TODO: in proof of stake, we also add some identifier of the current key so that we don't stake twice from the same key.
    //       This is because in PoS, there could be penalties for creating multiple blocks by the same staker.
}

pub struct JobHandle {
    cancel_signal: oneshot::Sender<()>,
}

#[allow(dead_code)]
pub struct BlockProduction {
    chain_config: Arc<ChainConfig>,
    chainstate_handle: ChainstateHandle,
    mempool_handle: MempoolHandle,
    time_getter: TimeGetter,
    all_jobs: BTreeMap<JobKey, JobHandle>,
    mining_thread_pool: Arc<slave_pool::ThreadPool>,
}

impl BlockProduction {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: ChainstateHandle,
        mempool_handle: MempoolHandle,
        time_getter: TimeGetter,
        mining_thread_pool: Arc<slave_pool::ThreadPool>,
    ) -> Result<Self, BlockProductionError> {
        let block_production = Self {
            chain_config,
            chainstate_handle,
            mempool_handle,
            time_getter,
            all_jobs: BTreeMap::new(),
            mining_thread_pool,
        };
        Ok(block_production)
    }

    pub fn time_getter(&self) -> &TimeGetter {
        &self.time_getter
    }

    pub fn stop_all_jobs(&mut self) {
        let mut all_jobs = Vec::new();
        while let Some((key, handle)) = self.all_jobs.pop_first() {
            all_jobs.push((key, handle));
        }

        log::info!("Cancelling {} jobs", all_jobs.len());

        for (key, handle) in all_jobs.drain(..) {
            let _ = handle.cancel_signal.send(());
            log::info!("Stopped mining job for tip {}", key.current_tip);
        }
    }

    pub fn stop_job(&mut self, key: &JobKey) -> bool {
        if let Some(handle) = self.all_jobs.remove(key) {
            let _ = handle.cancel_signal.send(());
            log::info!("Stopped mining job for tip {}", key.current_tip);
            true
        } else {
            false
        }
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

    pub fn make_job_key(tip_at_start: &GenBlockIndex) -> JobKey {
        JobKey {
            current_tip: tip_at_start.block_id(),
        }
    }

    pub async fn generate_block(
        &mut self,
        _reward_destination: Destination,
        transactions_source: TransactionsSource,
    ) -> Result<Block, BlockProductionError> {
        let stop_flag = Arc::new(false.into());

        let (cancel_sender, mut cancel_receiver) = oneshot::channel::<()>();

        let timestamp = BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

        let (_, tip_at_start) = self.pull_consensus_data(timestamp).await?;

        {
            // define the job and insert it into the map of all jobs
            let job_key = Self::make_job_key(&tip_at_start);

            #[allow(clippy::map_entry)]
            if !self.all_jobs.contains_key(&job_key) {
                self.all_jobs.insert(
                    job_key,
                    JobHandle {
                        cancel_signal: cancel_sender,
                    },
                );
            } else {
                return Err(BlockProductionError::JobAlreadyExists(job_key));
            }
        }

        loop {
            let timestamp =
                BlockTimestamp::from_duration_since_epoch(self.time_getter().get_time());

            let (consensus_data, current_tip_index) = self.pull_consensus_data(timestamp).await?;

            if current_tip_index.block_id() != tip_at_start.block_id() {
                log::info!(
                    "Current tip changed from {} with height {} to {} with height {} while mining, cancelling",
                    tip_at_start.block_id(),
                    tip_at_start.block_height(),
                    current_tip_index.block_id(),
                    current_tip_index.block_height(),
                );
                return Err(BlockProductionError::TipChanged(
                    tip_at_start.block_id(),
                    tip_at_start.block_height(),
                    current_tip_index.block_id(),
                    current_tip_index.block_height(),
                ));
            }

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
                _ = &mut cancel_receiver => {
                    // TODO: test cancellations
                    stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(BlockProductionError::Cancelled);
                }
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

                    return Ok(block);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // use tokio::time::{timeout, Duration};

    // use super::*;
    // use crate::{
    //     interface::blockprod_interface::BlockProductionInterface, prepare_thread_pool,
    //     tests::setup_blockprod_test,
    // };

    #[tokio::test]
    async fn stop() {
        // let (_manager, chain_config, chainstate, mempool) = setup_blockprod_test();

        // let (builder_tx, mut builder_rx) = mpsc::unbounded_channel();

        // let block_production = BlockProduction::new(
        //     chain_config,
        //     chainstate,
        //     mempool,
        //     Default::default(),
        //     prepare_thread_pool(1),
        // )
        // .expect("Error initializing Block Builder");

        // block_production.stop().expect("Error stopping Block Builder");

        // let recv = timeout(Duration::from_millis(1000), builder_rx.recv());

        // tokio::select! {
        //     msg = recv => match msg.expect("Block Builder timed out").expect("Error reading from Block Builder") {
        //         BlockBuilderControlCommand::Stop => {},
        //         _ => panic!("Invalid message received from Block Builder"),
        //     }
        // }
    }
}
