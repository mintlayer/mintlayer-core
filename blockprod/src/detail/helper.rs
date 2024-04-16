// Copyright (c) 2021-2024 RBB S.r.l
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

use std::{cmp, sync::Arc};

use chainstate::{ChainstateHandle, GenBlockIndex};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, Block, ChainConfig, RequiredConsensus, SignedTransaction,
        Transaction,
    },
    primitives::Id,
    time_getter::TimeGetter,
};
use consensus::ConsensusCreationError;
use mempool::{tx_accumulator::PackingStrategy, MempoolHandle};
use tokio::sync::{mpsc::UnboundedReceiver, oneshot};
use utils::{atomics::RelaxedAtomicBool, once_destructor::OnceDestructor};

use crate::BlockProductionError;

use super::{job_manager::JobManagerInterface, CustomId};

pub struct Helper {
    job_custom_id: CustomId,
    tip_block_index: GenBlockIndex,
    /// The so-called "median time past" timestamp calculated from the current tip.
    /// Note: when validating a block, the lock-time constraints of its transactions
    /// are validated against the "median time past" of the block's parent, rather than
    /// the timestamp of the block itself.
    /// So when constructing a new block we must make sure that transactions with locks
    /// after this point are not included, otherwise the block will be incorrect.
    tip_median_time_past: BlockTimestamp,
    stop_flag: Arc<RelaxedAtomicBool>,
    starting_timestamp: BlockTimestamp,
    max_timestamp: BlockTimestamp,
    cancel_receiver: UnboundedReceiver<()>,
    job_finished_receiver: Option<oneshot::Receiver<usize>>,
}

impl Helper {
    pub async fn new(
        job_custom_id: CustomId,
        job_manager_handle: &dyn JobManagerInterface,
        chainstate_handle: &ChainstateHandle,
        chain_config: &ChainConfig,
        time_getter: &TimeGetter,
    ) -> Result<(Self, OnceDestructor<impl FnOnce()>), BlockProductionError> {
        let (tip_block_index, tip_median_time_past) = chainstate_handle
            .call(move |cs| {
                let tip_block_index = cs.get_best_block_index().map_err(|err| {
                    BlockProductionError::ChainstateError(
                        consensus::ChainstateError::FailedToObtainBestBlockIndex(err.to_string()),
                    )
                })?;
                let tip_block_id = tip_block_index.block_id();

                let tip_median_time_past =
                    cs.calculate_median_time_past(&tip_block_id).map_err(|err| {
                        BlockProductionError::ChainstateError(
                            consensus::ChainstateError::FailedToCalculateMedianTimePast(
                                tip_block_id,
                                err.to_string(),
                            ),
                        )
                    })?;

                Result::<_, BlockProductionError>::Ok((tip_block_index, tip_median_time_past))
            })
            .await??;

        let stop_flag = Arc::new(RelaxedAtomicBool::new(false));

        let (job_key, last_used_block_timestamp, cancel_receiver) = job_manager_handle
            .add_job(job_custom_id.clone(), tip_block_index.block_id())
            .await?;

        let (job_stopper_function, job_finished_receiver) =
            job_manager_handle.make_job_stopper_function();

        // This destructor ensures that the job manager cleans up its housekeeping for the job.
        // We create it as early as possible - after the job itself has been created but before any
        // failing code is called.
        let job_stopper_destructor = OnceDestructor::new(move || job_stopper_function(job_key));

        let starting_timestamp = {
            let prev_timestamp = cmp::max(
                last_used_block_timestamp.unwrap_or(BlockTimestamp::from_int_seconds(0)),
                tip_block_index.block_timestamp(),
            );

            prev_timestamp
                .add_int_seconds(1)
                .ok_or(ConsensusCreationError::TimestampOverflow(prev_timestamp, 1))?
        };

        let max_timestamp = {
            let cur_timestamp = BlockTimestamp::from_time(time_getter.get_time());

            cur_timestamp
                .add_int_seconds(chain_config.max_future_block_time_offset().as_secs())
                .ok_or(ConsensusCreationError::TimestampOverflow(
                    cur_timestamp,
                    chain_config.max_future_block_time_offset().as_secs(),
                ))?
        };

        if starting_timestamp > max_timestamp {
            return Err(BlockProductionError::TryAgainLater);
        }

        Ok((
            Self {
                job_custom_id,
                tip_block_index,
                tip_median_time_past,
                stop_flag,
                starting_timestamp,
                max_timestamp,
                cancel_receiver,
                job_finished_receiver: Some(job_finished_receiver),
            },
            job_stopper_destructor,
        ))
    }

    pub fn job_custom_id(&self) -> &CustomId {
        &self.job_custom_id
    }

    pub fn tip_block_index(&self) -> &GenBlockIndex {
        &self.tip_block_index
    }

    pub fn starting_timestamp(&self) -> BlockTimestamp {
        self.starting_timestamp
    }

    pub fn max_timestamp(&self) -> BlockTimestamp {
        self.max_timestamp
    }

    pub fn required_consensus_at_next_height(
        &self,
        chain_config: &ChainConfig,
    ) -> RequiredConsensus {
        let next_block_height = self.tip_block_index.block_height().next_height();
        chain_config.consensus_upgrades().consensus_status(next_block_height)
    }

    pub async fn collect_transactions(
        &self,
        mempool_handle: &MempoolHandle,
        chain_config: &ChainConfig,
        transactions: Vec<SignedTransaction>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Vec<SignedTransaction>, BlockProductionError> {
        super::collect_transactions(
            mempool_handle,
            chain_config,
            self.tip_block_index.block_id(),
            self.tip_median_time_past,
            transactions,
            transaction_ids,
            packing_strategy,
        )
        .await
    }

    pub fn spawn_block_solver<Solver, SolverResult>(
        &mut self,
        mining_thread_pool: &slave_pool::ThreadPool,
        block_solver: Solver,
    ) -> SpawnedBlockSolverHandle<SolverResult>
    where
        Solver: FnOnce(
                /*stop_flag:*/ Arc<RelaxedAtomicBool>,
            ) -> Result<SolverResult, BlockProductionError>
            + Send
            + 'static,
        SolverResult: Send + 'static,
    {
        // A synchronous channel that sends only when the mining/staking is done
        let (ended_sender, ended_receiver) = std::sync::mpsc::channel::<()>();

        // Return the result of mining
        let (result_sender, result_receiver) = oneshot::channel();

        mining_thread_pool.spawn({
            let stop_flag = Arc::clone(&self.stop_flag);

            move || {
                let result = block_solver(stop_flag);

                // These can fail if the function exited before the mining thread finished
                let _ = result_sender.send(result);
                let _ = ended_sender.send(());
            }
        });

        SpawnedBlockSolverHandle {
            result_receiver,
            ended_receiver,
        }
    }

    pub async fn wait_for_block_solver_result<SolverResult>(
        &mut self,
        mut handle: SpawnedBlockSolverHandle<SolverResult>,
    ) -> Result<SolverResult, BlockProductionError> {
        tokio::select! {
            _ = self.cancel_receiver.recv() => {
                self.stop_flag.store(true);

                // This can fail if the mining thread has already finished
                let _ended = handle.ended_receiver.recv();

                Err(BlockProductionError::Cancelled)
            }
            solver_result = &mut handle.result_receiver => {
                let solver_result = solver_result.map_err(|_| BlockProductionError::TaskExitedPrematurely)??;
                Ok(solver_result)
            }
        }
    }

    pub fn finish(mut self, block: Block) -> (Block, oneshot::Receiver<usize>) {
        (
            block,
            self.job_finished_receiver
                .take()
                .expect("'Job finished' receiver must not be None"),
        )
    }
}

pub struct SpawnedBlockSolverHandle<SolverResult> {
    result_receiver: oneshot::Receiver<Result<SolverResult, BlockProductionError>>,
    ended_receiver: std::sync::mpsc::Receiver<()>,
}
